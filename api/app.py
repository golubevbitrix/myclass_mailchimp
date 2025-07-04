import base64
import datetime
import hashlib
import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler

import requests
from dotenv import load_dotenv
from flask import Flask, request

load_dotenv()
redis_url = os.getenv("REDIS_URL")
app = Flask(__name__)

MAILCHIMP_API_KEY = os.getenv('MAILCHIMP_API_KEY')
MOY_KLASS_API_KEY = os.getenv('MOY_KLASS_API_KEY')
MOY_KLASS_URL = os.getenv('MOY_KLASS_URL', 'https://api.moyklass.com/v1')

STATUS_ACTIVE = 141033  # "Учится"
STATUS_DECLINED = 141035  # "Отказ"
STATUS_ONLINE = 219123  # "Онлайн"

MAILCHIMP_LIST_NS = '0a2f0f48d2'  # SmartLab NS
MAILCHIMP_LIST_ONLINE = '37a7409e92'  # SmartLab Online

# Групповые теги
GROUP_TAGS = {
    416062: 'Ekskluziv sa Marijom',
    416060: 'Zajedno ka Znanju',
    416057: 'Samostalno Putovanje'
}

# Подписки для тега "11900"
SUBSCRIPTIONS_WITH_11900 = [170376, 180100]
ONLINE_SUBSCRIPTION_IDS = [187447, 180100, 170376, 180098, 148959, 180099,
                           148960]

def get_saved_token():
    r = redis.Redis.from_url(redis_url)
    try:
        data = r.hgetall('token')
        if 'access_token' in data and 'expires_at' in data:
            expires_at = datetime.datetime.fromtimestamp(data['expires_at'])
            if expires_at > datetime.datetime.now():
                return data['access_token']
                print('Saved token has expired or is invalid.')
    except FileNotFoundError:
        print('Token file not found, requesting new token.')
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error reading token file: {str(e)}")
    return None

def save_token(token, expires_at):
    r = redis.Redis.from_url(redis_url)
    r.hset('token', mapping = {'access_token': token, 'expires_at': expires_at})
    print("Token saved successfully.")

def get_token():
    saved_token = get_saved_token()
    if saved_token:
        return saved_token

    url = f'{MOY_KLASS_URL}/company/auth/getToken'
    headers = {'Content-Type': 'application/json'}
    payload = {'apiKey': MOY_KLASS_API_KEY}
    print("Requesting new token")
    response = requests.post(url, json=payload, headers=headers)
    print(
        f"Token request status: {response.status_code}, expiresAt: {response.json().get('expiresAt', 'N/A')}")
    if response.status_code == 200:
        new_token = response.json()
        token = new_token['accessToken']
        expires_at = datetime.datetime.strptime(new_token['expiresAt'],
                                                '%Y-%m-%dT%H:%M:%S%z').timestamp()
        save_token(token, expires_at)
        return token
    else:
        print(
            f"Failed to obtain token from Moy Klass: {response.text}")
    return None

def validate_email(email, name):
    if not email:
        print(
            f"Email is missing for student {name}. Cannot proceed with Mailchimp update.")
        return False
    return True

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.get_json()
    print(f"Received webhook data: {data}")

    if not data:
        print("No JSON data received!")
        return 'Bad request: No JSON data', 200

    user_id = data.get('object', {}).get('userId')
    if not user_id:
        print("User ID not provided in the data.")
        return 'Bad request: No user ID provided', 200

    event_type = data.get('event', 'unknown')
    print(f"Processing event '{event_type}' for user ID: {user_id}")

    token = get_token()
    if not token:
        print("Failed to obtain token from Moy Klass")
        return 'Bad request: Failed to obtain token', 200

    user_info = get_user_info(token, user_id)
    if not user_info:
        print("Failed to obtain student info from Moy Klass")
        return 'Bad request: Failed to obtain student info', 200

    email = user_info.get('email')
    name = user_info.get('name')
    phone = user_info.get('phone')

    if not validate_email(email, name):
        return 'OK: No email, request ignored', 200

    client_state = user_info.get('clientStateId')

    subscription_info = get_user_subscription_info(token, user_id)
    if subscription_info and subscription_info.get('subscriptions'):
        print(
            f"Subscription info for user {user_id}: {json.dumps(subscription_info)}")
    else:
        print(
            f"No subscription info found or empty for user {user_id}")

    tags = []

    if subscription_info and subscription_info.get('subscriptions'):
        for subscription in subscription_info.get('subscriptions', []):
            if subscription.get('subscriptionId') in SUBSCRIPTIONS_WITH_11900:
                print(
                    f"Adding tag '11900' for {email} based on subscription "
                    f"{subscription.get('subscriptionId')}"
                )
                tags.append('11900')
                break

    valid_class_id = None
    if 'joins' in user_info and user_info['joins']:
        for join in user_info['joins']:
            if join.get('classId') in GROUP_TAGS:
                valid_class_id = join.get('classId')
                break

    if client_state == STATUS_ACTIVE:
        print(f"User {user_id} is active; adding tag 'WS'")
        tags.append('WS')
    elif client_state == STATUS_DECLINED:
        print(
            f"User {user_id} is declined; adding tag 'GoodBye Series'")
        tags.append('GoodBye Series')
    elif client_state == STATUS_ONLINE:
        valid_online_subscription = False
        if subscription_info and subscription_info.get('subscriptions'):
            valid_online_subscription = any(
                sub.get(
                    'subscriptionId') in ONLINE_SUBSCRIPTION_IDS and sub.get(
                    'visitedCount', 0) == 0
                for sub in subscription_info.get('subscriptions', [])
            )
        print(
            f"User {user_id} online subscription valid: {valid_online_subscription}")
        if valid_online_subscription:
            print(f"Adding tag 'WSO' for user {user_id}")
            tags.append('WSO')
        elif valid_class_id:
            group_tag = GROUP_TAGS[valid_class_id]
            print(
                f"Adding group tag '{group_tag}' for user {user_id}")
            tags.append(group_tag)
        else:
            print(
                f"Ignoring online user {user_id} with no valid class ID.")
            return 'OK: No valid class ID provided, request ignored', 200

    if tags:
        print(f"Final tags to send for {email}: {tags}")
        response_text = add_or_update_contact_in_mailchimp(email, name, phone,
                                                           MAILCHIMP_LIST_NS,
                                                           tags)
        return response_text
    else:
        print(f"No tags to update for user {user_id}")
        return 'OK: No tags to update', 200

def get_user_info(token, user_id):
    url = f'{MOY_KLASS_URL}/company/users/{user_id}'
    headers = {'x-access-token': token}
    response = requests.get(url, headers=headers)
    print(
        f"Student info request status: {response.status_code}, response: {response.text}")
    if response.status_code == 200:
        return response.json()
    print(f"Failed to get student info: {response.text}")
    return None

def get_user_subscription_info(token, user_id):
    url = f'{MOY_KLASS_URL}/company/userSubscriptions?userId={user_id}'
    headers = {'x-access-token': token}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        subscriptions = response.json()
        if not subscriptions.get('subscriptions'):
            return None
        return subscriptions
    print(f"Failed to get subscription info: {response.text}")
    return None

def get_mailchimp_headers():
    api_key = MAILCHIMP_API_KEY
    encoded_api_key = base64.b64encode(
        f'anystring:{api_key}'.encode('utf-8')).decode('utf-8')
    return {'Authorization': f'Basic {encoded_api_key}'}

def add_or_update_contact_in_mailchimp(email, name, phone, list_id, tags):
    if not validate_email(email, name):
        return 'Bad request: Email is missing, request ignored'
    member_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    headers = get_mailchimp_headers()
    datacenter = MAILCHIMP_API_KEY.split('-')[1]
    member_url = f'https://{datacenter}.api.mailchimp.com/3.0/lists/{list_id}/members/{member_hash}'

    first_name, last_name = split_name(name)

    response = requests.get(member_url, headers=headers)
    if response.status_code == 200:
        print(
            f"Contact for {email} exists. Updating contact and tags.")
        if isinstance(tags, str):
            tags = [tags]

        tag_url = f'{member_url}/tags'
        payload = {'tags': [{'name': tag, 'status': 'active'} for tag in tags]}
        response_tag = requests.post(tag_url, json=payload, headers=headers)
        print(
            f"Mailchimp tag update response for {email}: {response_tag.text}")

        merge_payload = {
            'merge_fields': {'FNAME': first_name, 'LNAME': last_name,
                             'PHONE': phone}}
        response_update = requests.put(member_url, json=merge_payload,
                                       headers=headers)
        log_mailchimp_response(response_update, email)
        return response_update.text
    elif response.status_code == 404:
        print(
            f"Contact for {email} not found. Creating new contact.")

        create_url = f'https://{datacenter}.api.mailchimp.com/3.0/lists/{list_id}/members'
        create_payload = {
            'email_address': email,
            'status': 'subscribed',
            'merge_fields': {'FNAME': first_name, 'LNAME': last_name,
                             'PHONE': phone}
        }
        response_create = requests.post(create_url, json=create_payload,
                                        headers=headers)
        log_mailchimp_response(response_create, email)
        if response_create.status_code != 200:
            print(
                f"Failed to create contact for {email}: {response_create.text}")
            return response_create.text
        time.sleep(1)

        tag_url = f'{member_url}/tags'
        payload = {'tags': [{'name': tag, 'status': 'active'} for tag in tags]}
        response_tag = requests.post(tag_url, json=payload, headers=headers)
        print(
            f"Added tag '{tags}' for email {email}: {response_tag.text}")
        return response_tag.text
    else:
        print(
            f"Error checking member existence for {email}: {response.text}")
        return response.text

def split_name(name):
    parts = name.strip().split()
    if len(parts) == 0:
        return '', ''
    elif len(parts) == 1:
        return parts[0], ''
    else:
        return parts[0], ' '.join(parts[1:])

def log_mailchimp_response(response, email):
    try:
        response_json = response.json()
        member_id = response_json.get('id')
        email_address = response_json.get('email_address')
        tags_count = response_json.get('tags_count')
        print(
            f"Mailchimp response for {email}: id={member_id}, email={email_address}, tags_count={tags_count}")
    except Exception as e:
        print(
            f"Failed to log Mailchimp response for {email}: {str(e)}")

@app.route("/")
def home():
    return "Flask is running!", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
