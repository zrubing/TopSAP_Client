from retrying import retry
import time
import requests
import base64
import json
import logging
import configparser
import warnings
import random  # Import random module
from requests.packages import urllib3
# 关闭警告
urllib3.disable_warnings()
warnings.filterwarnings("ignore")

class AutoLoginTopSap():
    def __init__(self, host, port, username, password, ocr):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.auto_code_url = ocr
        self.logout_url = "https://localhost:7443/api/v1/logout"
        self.login_url = "https://localhost:7443/api/v1/login_by_pwd"
        self.query_statistics_url = "https://localhost:7443/api/v1/query_statistics"
        self.session = requests.session()
        self.json_headers = {
            'Content-Type': 'application/json'
        }
        self.form_headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        }
        self.vpn_version = 'sm2'  # Extracted vpn_version
        self.code_url = self.construct_code_url()
        self.last_recv_bytes = None
        self.last_send_bytes = None
        self.last_check_time = time.time()

        self.already_check = False

    def construct_code_url(self):
        params = {
            'serverAddr': self.host,
            'serverPort': self.port,
            'vpn_version': self.vpn_version,
            'auth_protocol': '0',
            'auth_port': self.port,
            'data_port': self.port,
            'data_protocol': '0',
            'cert_type': '0',
            'proxyType': '',
            'proxyAddr': '',
            'proxyPort': '',
            'proxyUser': '',
            'proxyPwd': '',
            'proxyDomain': '',
            'rnd': random.uniform(0, 1)  # Generate a random float between 0 and 1
        }
        base_url = "https://localhost:7443/api/v1/get_gid"
        return f"{base_url}?{'&'.join([f'{key}={value}' for key, value in params.items()])}"

    def get_code_img(self):
        """
        获取验证码图片
        """
        response = self.session.get(self.code_url, verify=False)
        content_type = response.headers.get('Content-Type')

        if 'application/json' in content_type:
            # Handle error case for JSON response
            error_message = response.json().get('error', 'Unknown error')
            raise Exception(f"Error from get_gid: {error_message}")

        elif 'image/png' in content_type:
            if response.content == b'':
                raise Exception("Received empty image content")

            with open('result.png', 'wb') as f:
                f.write(response.content)
            return response.content
        
        else:
            raise Exception(f"Unexpected Content-Type: {content_type}")

    def get_code_base64(self, content):
        """
        返回base64图片文本
        """
        return "data:image/png;base64," + base64.b64encode(content).decode('utf-8')

    def get_auth_param(self):
        """
        {"method":"get_auth_param", "serverAddr":"","serverPort":"","proxyType":"",
        "proxyAddr":"","proxyUser":"","proxyPwd":"",proxyDmain:"","_flag":1
        }

        """
        pass

    def get_code_text(self):
        """
        获取验证码Code
        """
        result = self.get_code_base64(self.get_code_img())
        data = {
            "base64": result,
            "name": "erp",
            "threshold": 0,
            "count": 0
        }

        code = self.session.post(self.auto_code_url, headers=self.json_headers, data=json.dumps(data), verify=False).text
        return code

    def query_statistics(self):
        """
        统计连接数据
        """
        data = {"method": "query_statistics"}
        try:
            response = self.session.post(self.query_statistics_url, headers=self.json_headers, data=json.dumps(data), verify=False, timeout=2).json()
        except requests.exceptions.Timeout:
            print("请求超时，正在尝试登录...")
            self.login()
            return None

        terr_code = response.get('terr_code') # != 0 

        # Check for send_bytes and recv_bytes conditions
        send_bytes = response.get('send_bytes')
        recv_bytes = response.get('recv_bytes')

        if self.last_recv_bytes is not None and self.last_send_bytes is not None:
            if (time.time() - self.last_check_time) >= 5:  # Check every 10 seconds
                if send_bytes > self.last_send_bytes and recv_bytes == self.last_recv_bytes:
                    print("send_bytes increased while recv_bytes unchanged, logging out...")
                    self.logout()
                    self.login()

                    # 重置状态
                    self.already_check = False

        # 没有做过记录
        if not self.already_check:
            print("record last recv bytes")
            self.last_recv_bytes = recv_bytes
            self.last_send_bytes = send_bytes
            self.last_check_time = time.time()

            self.already_check = True

        return response
    
    def logout(self):
        """
        登出
        """
        data = {"method":"logout"}
        response = self.session.post(self.logout_url, headers=self.json_headers, data=json.dumps(data), verify=False).text
        return response
    
    @retry(stop_max_attempt_number=10)
    def login(self):
        code = self.get_code_text()
        """
        自动登陆
        """
        data = {
            "method": "login_by_pwd",
            "vone": { 
                "addr": self.host, 
                "port": self.port,
                "user": base64.b64encode(self.username.encode('utf-8')).decode('utf-8'),

                "pwd": base64.b64encode(self.password.encode('utf-8')).decode('utf-8')
            },
            "proxy": { 
                "type":"",
                "addr":"",
                "port":"",
                "user":"",
                "pwd":"",
                "domain":""
            },
            "gid" : { 
                "cgid":"" ,
                "gid": code 
            } ,
            "vpn_version" : self.vpn_version,  # Use extracted vpn_version
            "auth_protocol":"0" ,
            "auth_port": self.port ,
            "data_port": self.port ,
            "data_protocol": "0" ,
            "cert_type": "0" ,
            "remember_pwd": "off" 
        }
        response = self.session.post(self.login_url, headers=self.json_headers, data=json.dumps(data), verify=False).json()
        if response.get('err_code') != 0:
            if response.get('err_code') == -18:
                self.logout()
            raise Exception("Login failed")
        print("登录成功")
        return response
    
    def listen(self):
        while True:
            try:
                stat = self.query_statistics()
                print(stat)
                if stat and (stat.get('terr_code') != 0 or stat.get('session_id') == ''):
                    self.login()
            except Exception as e:
                print(e)
                pass
            time.sleep(1)
             

    # def auto_login(self, retry=3):
        
config = configparser.ConfigParser()
config.read('env.ini')

env = config.get('ENV', 'env')

host = config.get(env, 'host')
port = config.get(env, 'port')
username = config.get(env, 'username')
password = config.get(env, 'password')
ocr = config.get(env, 'ocr_url')

print("start")
auto_login = AutoLoginTopSap(host, port, username, password, ocr)
auto_login.listen()
