# This file contains a hardcoded password
import requests

def connect_to_api():
    password = "Password123!" # Vulnerable line: Hardcoded secret
    auth = ('admin', password)
    requests.get('https://api.example.com', auth=auth)

connect_to_api()