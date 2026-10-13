"""CodeMender 테스트용 취약점 샘플 파일 (Python).

포함된 시나리오:
1. [진성 취약점 - CWE-89] f-string 기반 SQL Injection (get_customer_invoice)
2. [오탐 필터링 검증용 - Safe SQL] 파라미터 바인딩(?)이 적용된 안전한 쿼리 (get_audit_logs_safe -> Stage 2 샌드박스에서 오탐으로 제외됨)
3. [진성 취약점 - CWE-78] shell=True 기반 OS Command Injection (ping_payment_gateway)
4. [진성 취약점 - CWE-918] 호스트 검증 없는 SSRF 요청 (fetch_partner_webhook)
5. [진성 취약점 - CWE-502] 안전하지 않은 YAML 역직렬화 (load_routing_policy)
"""

import sqlite3
import subprocess
import requests
import yaml


def get_customer_invoice(db_conn: sqlite3.Connection, invoice_id: str) -> list:
    cursor = db_conn.cursor()
    # [VULNERABLE: CWE-89 SQL Injection]
    cursor.execute(f"SELECT id, customer, amount, status FROM invoices WHERE invoice_id = '{invoice_id}'")
    return cursor.fetchall()


def get_audit_logs_safe(db_conn: sqlite3.Connection, user_id: str) -> list:
    cursor = db_conn.cursor()
    # [SAFE: Parameterized Query - Stage 2 cm verify 샌드박스에서 False Positive로 자동 필터링됨]
    cursor.execute("SELECT action, created_at FROM audit_logs WHERE user_id = ?", (user_id,))
    return cursor.fetchall()


def ping_payment_gateway(gateway_host: str) -> str:
    # [VULNERABLE: CWE-78 OS Command Injection]
    proc = subprocess.run(f"ping -c 1 {gateway_host}", shell=True, capture_output=True, text=True)
    return proc.stdout


def fetch_partner_webhook(webhook_url: str) -> str:
    # [VULNERABLE: CWE-918 Server-Side Request Forgery (SSRF)]
    resp = requests.get(webhook_url, timeout=5)
    return resp.text


def load_routing_policy(raw_yaml_payload: str) -> dict:
    # [VULNERABLE: CWE-502 Insecure Deserialization]
    policy = yaml.load(raw_yaml_payload)
    return policy
