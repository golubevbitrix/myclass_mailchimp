#!/usr/bin/env python3
import glob
import gzip
import json
import time
import argparse
from pathlib import Path

import requests

LOG_DIR       = '/var/www/myproject'
LOG_PATTERN   = 'app.log*'
WEBHOOK_URL   = 'http://141.8.192.114/webhook'
SLEEP_SECONDS = 0.15  # чтобы не превышать 7 req/s для MoyKlass

def iter_log_files():
    """Перечисляет все файлы логов, включая сжатые .gz."""
    for path in glob.glob(f"{LOG_DIR}/{LOG_PATTERN}"):
        yield Path(path)

def open_log(path: Path):
    """Открывает файл, используя gzip.open для .gz."""
    if path.suffix == '.gz':
        return gzip.open(path, 'rt', encoding='utf-8', errors='ignore')
    return open(path, 'r', encoding='utf-8', errors='ignore')

def extract_json_from_line(line: str):
    """
    Находит в строке первый '{' и последний '}' и пытается распарсить JSON.
    Возвращает dict или None.
    """
    try:
        start = line.index('{')
        end   = line.rfind('}')
        return json.loads(line[start:end+1])
    except Exception:
        return None

def build_email_uid_map():
    """
    Собирает маппинг email → userId из любых строк лога, где после 'response:'
    идёт JSON с полями 'id' и 'email'.
    """
    email_to_uid = {}
    for path in iter_log_files():
        with open_log(path) as f:
            for line in f:
                if 'response:' in line and '{' in line and '"email"' in line:
                    data = extract_json_from_line(line)
                    if not data:
                        continue
                    uid   = data.get('id')
                    email = data.get('email')
                    if uid and email:
                        email_to_uid[email] = uid
    return email_to_uid

def parse_error_emails():
    """
    Собирает set(email) из строк Mailchimp-ошибок (status:404).
    Ищет 'Mailchimp tag response for {email}: ... "status":404 ...'
    """
    errors = set()
    for path in iter_log_files():
        with open_log(path) as f:
            for line in f:
                if 'Mailchimp tag response' in line and '"status":404' in line:
                    try:
                        part  = line.split('Mailchimp tag response for ', 1)[1]
                        email = part.split(':', 1)[0].strip()
                        errors.add(email)
                    except Exception:
                        continue
    return errors

def main(errors_only: bool):
    # 1. Собираем все email → userId из логов
    email_to_uid = build_email_uid_map()

    # 2. Если нужно — фильтруем только по ошибочным email
    if errors_only:
        errors = parse_error_emails()
        uids = { email_to_uid[e] for e in errors if e in email_to_uid }
        print(f"Найдено {len(errors)} ошибочных email, из них {len(uids)} с известным userId")
    else:
        uids = set(email_to_uid.values())
        print(f"Найдено {len(uids)} уникальных userId в логах")

    # 3. Записываем результат
    with open('resend_user_ids.txt', 'w') as out:
        for uid in sorted(uids):
            out.write(f"{uid}\n")

    print("Список userId сохранён в resend_user_ids.txt:")
    print(sorted(uids))

    # 4. Интерективное подтверждение отправки
    confirm = input("Начать повторную отправку? [y/N]: ")
    if confirm.lower() != 'y':
        print("Отправка отменена.")
        return

    # 5. Повторная отправка на /webhook
    for idx, uid in enumerate(sorted(uids), 1):
        payload = {'object': {'userId': uid}}
        try:
            resp = requests.post(WEBHOOK_URL, json=payload, timeout=10)
            status = resp.status_code
        except Exception as e:
            status = f"ERROR: {e}"
        print(f"[{idx}/{len(uids)}] userId={uid} → {status}")
        time.sleep(SLEEP_SECONDS)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Собрать userId из логов и при необходимости повторно вызвать /webhook"
    )
    parser.add_argument(
        '--errors-only',
        action='store_true',
        help="Собирать только те userId, по которым были Mailchimp‑ошибки"
    )
    args = parser.parse_args()
    main(errors_only=args.errors_only)
