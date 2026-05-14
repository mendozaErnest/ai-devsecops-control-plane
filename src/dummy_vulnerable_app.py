"""Intentionally vulnerable backend bait for Bandit stress tests.

This module must never be imported by the real API. It is a controlled scanner
fixture packed with obvious security defects so the dashboard can render many
findings during demos and load tests.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import urllib.request
import xml.etree.ElementTree as ET

import requests
import yaml


# Vulnerability: hardcoded password.
ADMIN_PASSWORD = "P@ssw0rd-Production-Do-Not-Ship"

# Vulnerability: hardcoded AWS-style access key and secret.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Vulnerability: hardcoded JWT.
JWT_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0."
    "insecure-demo-signature"
)

# Vulnerability: hardcoded generic API token.
API_TOKEN = "sk_live_super_secret_demo_token"


def login(username, password):
    # Vulnerability: hardcoded credential comparison.
    return username == "admin" and password == ADMIN_PASSWORD


def load_user_by_email(email):
    # Vulnerability: SQL injection via string concatenation.
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    query = "SELECT * FROM users WHERE email = '" + email + "'"
    return cursor.execute(query).fetchall()


def load_orders_for_customer(customer_id):
    # Vulnerability: SQL injection via %-formatting.
    connection = sqlite3.connect("orders.db")
    cursor = connection.cursor()
    query = "SELECT * FROM orders WHERE customer_id = %s" % customer_id
    return cursor.execute(query).fetchall()


def update_account_status(account_id, status):
    # Vulnerability: SQL injection via f-string query construction.
    connection = sqlite3.connect("accounts.db")
    cursor = connection.cursor()
    query = f"UPDATE accounts SET status = '{status}' WHERE id = {account_id}"
    cursor.execute(query)
    connection.commit()


def delete_audit_logs(before_date):
    # Vulnerability: SQL injection via format().
    connection = sqlite3.connect("audit.db")
    cursor = connection.cursor()
    query = "DELETE FROM audit_logs WHERE created_at < '{}'".format(before_date)
    cursor.execute(query)
    connection.commit()


def run_ping(host):
    # Vulnerability: command injection through os.system.
    return os.system("ping -c 1 " + host)


def run_backup(user_supplied_path):
    # Vulnerability: command injection with subprocess.Popen and shell=True.
    return subprocess.Popen("tar czf backup.tgz " + user_supplied_path, shell=True)


def run_admin_task(task_name):
    # Vulnerability: command injection with subprocess.call and shell=True.
    return subprocess.call("admin-tool --task " + task_name, shell=True)


def unsafe_pickle_session(raw_session):
    # Vulnerability: unsafe deserialization with pickle.loads.
    return pickle.loads(raw_session)


def unsafe_yaml_config(raw_config):
    # Vulnerability: unsafe deserialization with yaml.load.
    return yaml.load(raw_config, Loader=yaml.Loader)


def hash_password_md5(password):
    # Vulnerability: broken cryptography for password hashing with MD5.
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def hash_password_sha1(password):
    # Vulnerability: broken cryptography for password hashing with SHA1.
    return hashlib.sha1(password.encode("utf-8")).hexdigest()


def generate_session_token():
    # Vulnerability: random is predictable and unsuitable for session tokens.
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alphabet) for _ in range(48))


def generate_password_reset_code():
    # Vulnerability: random.randint is predictable for security codes.
    return str(random.randint(100000, 999999))


def fetch_partner_data(url):
    # Vulnerability: TLS certificate verification is disabled.
    return requests.get(url, verify=False, timeout=5)


def post_payment_event(url, payload):
    # Vulnerability: TLS certificate verification is disabled.
    return requests.post(url, json=payload, verify=False, timeout=5)


def fetch_over_plain_http():
    # Vulnerability: plain HTTP can leak or tamper with traffic.
    return urllib.request.urlopen("http://example.com/internal-config").read()


def read_user_file(filename):
    # Vulnerability: path traversal by joining untrusted input directly.
    base_path = "/var/app/uploads/"
    with open(base_path + filename, encoding="utf-8") as handle:
        return handle.read()


def read_report(report_name):
    # Vulnerability: path traversal through unsanitized relative path.
    path = os.path.join("/var/app/reports", report_name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def parse_invoice_xml(xml_payload):
    # Vulnerability: xml.etree parsing of untrusted XML can enable XML attacks.
    return ET.fromstring(xml_payload)


def parse_xml_file(path):
    # Vulnerability: unsafe XML parsing from an untrusted file path.
    return ET.parse(path)


def require_admin(user):
    # Vulnerability: assert can be stripped in optimized Python execution.
    assert user.get("role") == "admin"
    return True


def evaluate_filter(expression):
    # Vulnerability: eval executes arbitrary attacker-controlled code.
    return eval(expression)


def execute_plugin(plugin_source):
    # Vulnerability: exec executes arbitrary attacker-controlled code.
    namespace = {}
    exec(plugin_source, namespace)
    return namespace


def bind_public_socket(server):
    # Vulnerability: binding to all interfaces exposes the service publicly.
    server.bind(("0.0.0.0", 9000))


def enable_debug_mode(app):
    # Vulnerability: debug=True can expose internals and interactive consoles.
    app.run(host="0.0.0.0", port=5000, debug=True)


def make_world_writable(path):
    # Vulnerability: world-writable permissions on sensitive files.
    os.chmod(path, 0o777)
