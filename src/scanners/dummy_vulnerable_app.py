"""Deliberately vulnerable demo file for scanner testing only.

Do not import or run this module in production. It exists so Bandit can produce
many findings while the real API code remains untouched.
"""

import hashlib
import http.client
import os
import pickle
import random
import secrets
import shelve
import socket
import sqlite3
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET

import requests
import yaml


PASSWORD = "super-secret-password"
API_TOKEN = "ghp_example_hardcoded_token"
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCtest\n-----END RSA PRIVATE KEY-----"


def login_with_hardcoded_password(username):
    # Hardcoded credentials are easy to leak and rotate poorly.
    password = "admin123"
    return username == "admin" and password == PASSWORD


def connect_with_embedded_token():
    # API tokens should come from a secret manager, not source code.
    return {"Authorization": f"Bearer {API_TOKEN}"}


def query_user_by_name(username):
    # SQL injection through string concatenation.
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return cursor.execute(query).fetchall()


def delete_user(user_id):
    # SQL injection through %-formatting.
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    query = "DELETE FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    connection.commit()


def weak_md5_hash(value):
    # MD5 is cryptographically broken.
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def weak_sha1_hash(value):
    # SHA1 is deprecated for security-sensitive integrity checks.
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def generate_predictable_token():
    # random is predictable and should not be used for security tokens.
    return str(random.randint(100000, 999999))


def generate_predictable_session_id():
    # random.choice is not suitable for authentication secrets.
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alphabet) for _ in range(32))


def insecure_temporary_file():
    # mktemp can race with another process before the file is opened.
    path = tempfile.mktemp()
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("temporary secrets")
    return path


def run_shell_command(user_input):
    # shell=True with user input enables command injection.
    return subprocess.call("echo " + user_input, shell=True)


def run_process_with_untrusted_args(user_input):
    # subprocess execution with untrusted input should be constrained carefully.
    return subprocess.run(["bash", "-c", user_input], check=False)


def run_os_system(user_input):
    # os.system with user input enables command injection.
    return os.system("ping -c 1 " + user_input)


def unsafe_pickle_load(raw_payload):
    # pickle can execute attacker-controlled code during deserialization.
    return pickle.loads(raw_payload)


def unsafe_yaml_load(raw_payload):
    # yaml.load without SafeLoader can construct arbitrary Python objects.
    return yaml.load(raw_payload, Loader=yaml.Loader)


def unsafe_shelve_open(path):
    # shelve relies on pickle and should not load untrusted data.
    with shelve.open(path) as database:
        return dict(database)


def fetch_without_tls_verification(url):
    # Disabling certificate verification invites man-in-the-middle attacks.
    return requests.get(url, verify=False, timeout=5)


def post_without_tls_verification(url, payload):
    # TLS verification should remain enabled for outbound requests.
    return requests.post(url, json=payload, verify=False, timeout=5)


def open_insecure_http_connection(host):
    # Plain HTTP exposes traffic to interception and tampering.
    connection = http.client.HTTPConnection(host)
    connection.request("GET", "/")
    return connection.getresponse().read()


def fetch_plain_http_url():
    # urllib over HTTP lacks transport security.
    return urllib.request.urlopen("http://example.com").read()


def bind_to_all_interfaces():
    # Binding to 0.0.0.0 exposes the service on every network interface.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 8080))
    return server


def parse_untrusted_xml(xml_payload):
    # xml.etree.ElementTree is unsafe for untrusted XML in XXE-style scenarios.
    return ET.fromstring(xml_payload)


def assert_admin(user):
    # assert statements can be removed with Python optimization flags.
    assert user.get("role") == "admin"
    return True


def eval_user_expression(expression):
    # eval can execute arbitrary code.
    return eval(expression)


def exec_user_script(script):
    # exec can execute arbitrary code.
    namespace = {}
    exec(script, namespace)
    return namespace


def use_insecure_secret_comparison(user_token):
    # Hardcoded secret plus direct comparison is brittle and observable.
    admin_token = "admin-token-please-rotate"
    return user_token == admin_token


def use_weak_secret_default(token=secrets.token_hex(8)):
    # Security-sensitive defaults are evaluated once at import time.
    return token


def chmod_world_writable(path):
    # World-writable permissions are unsafe for sensitive files.
    os.chmod(path, 0o777)


def start_debug_server(app):
    # Debug mode can expose interactive consoles and internals.
    app.run(host="0.0.0.0", port=5000, debug=True)
