import json
import base64
import requests
import cv2
import numpy as np
from eth_account import Account
from eth_account.messages import encode_defunct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time
import random
import re
import os


class CoreSkyChecker:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
        })
        self.proxy = None
        self.private_key = None
        self.wallet_address = None
        self.token = None
        self.last_request_time = 0
        
        # ========== 任务配置 ==========
        # 可选择执行的任务类型：
        # "sign_only" - 只执行签到
        # "vote_only" - 只执行投票
        # "both" - 执行签到和投票
        self.TASK_MODE = "both"
        # ============================
    
    def load_private_keys(self):
        """从pk.txt文件中加载私钥"""
        print("🔍 从pk.txt加载私钥...")
        
        private_keys = []
        pk_file = "/Users/mac/Desktop/未命名文件夹/coresky签到脚本/pk.txt"
        
        if not os.path.exists(pk_file):
            print(f"❌ 未找到{pk_file}文件")
            return private_keys
        
        try:
            with open(pk_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines, 1):
                key = line.strip()
                if not key or key.startswith('#'):  # 跳过空行和注释行
                    continue
                    
                # 移除0x前缀（如果存在）
                if key.lower().startswith('0x'):
                    clean_key = key[2:]
                else:
                    clean_key = key
                
                # 验证私钥
                if len(clean_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in clean_key):
                    private_keys.append(clean_key.lower())
                    print(f"✅ 私钥 {len(private_keys)}: {clean_key[:10]}...")
                else:
                    print(f"❌ 第{i}行私钥格式错误")
        
        except Exception as e:
            print(f"❌ 读取私钥文件失败: {e}")
        
        print(f"✅ 总共加载 {len(private_keys)} 个有效私钥")
        return private_keys
    
    def load_proxies(self):
        """从ip.txt文件中加载代理IP，格式：ip:端口:账号:密码:代理协议"""
        print("🔍 从ip.txt加载代理...")
        
        proxies = []
        ip_file = "/Users/mac/Desktop/未命名文件夹/coresky签到脚本/ip.txt"
        
        if not os.path.exists(ip_file):
            print(f"📝 未找到{ip_file}文件，将使用直连")
            return proxies
        
        try:
            with open(ip_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines, 1):
                proxy_line = line.strip()
                if not proxy_line or proxy_line.startswith('#'):  # 跳过空行和注释行
                    continue
                    
                try:
                    # 解析格式: ip:端口:账号:密码:代理协议
                    parts = proxy_line.split(':')
                    if len(parts) >= 5:
                        ip = parts[0]
                        port = parts[1]
                        username = parts[2]
                        password = parts[3]
                        protocol = parts[4]
                        
                        proxy_url = f"{protocol}://{username}:{password}@{ip}:{port}"
                        proxies.append(proxy_url)
                        print(f"✅ 代理 {len(proxies)}: {protocol}://{ip}:{port}")
                    else:
                        print(f"❌ 第{i}行代理格式错误")
                except Exception as e:
                    print(f"❌ 第{i}行代理解析失败: {e}")
        
        except Exception as e:
            print(f"❌ 读取代理文件失败: {e}")
        
        if len(proxies) == 0:
            print("📝 未配置代理，将使用直连")
        else:
            print(f"✅ 总共加载 {len(proxies)} 个代理")
            
        return proxies
    
    def wait_between_requests(self, min_wait=1, max_wait=2):
        """请求间隔控制"""
        current_time = time.time()
        if hasattr(self, 'last_request_time'):
            elapsed = current_time - self.last_request_time
            
            if elapsed < min_wait:
                wait_time = random.uniform(min_wait - elapsed, max_wait - elapsed)
                if wait_time > 0:
                    time.sleep(wait_time)
        
        self.last_request_time = time.time()
    
    def handle_rate_limit_error(self, attempt=1, max_attempts=3):
        """处理频率限制错误"""
        if attempt <= max_attempts:
            wait_time = min(60 * (2 ** (attempt - 1)), 300)
            print(f"⚠️ IP请求频率受限，第{attempt}次重试，等待 {wait_time} 秒...")
            time.sleep(wait_time)
            return True
        else:
            print(f"❌ 达到最大重试次数，跳过此账户")
            return False

    def check_in(self, captcha_data, x, y):
        """验证码验证 - 第一步"""
        try:
            point_json = self.encrypt_point_json(x, y, captcha_data.get('secretKey', ''))
            if not point_json:
                return False
            
            url = "https://www.coresky.com/api/captcha/check"
            
            headers = {
                'Content-Type': 'application/json',
                'Token': self.token,
                'Origin': 'https://www.coresky.com',
                'Referer': 'https://www.coresky.com/tasks-rewards',
                'x-kl-kfa-ajax-request': 'Ajax_Request',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            
            payload = {
                "captchaType": "blockPuzzle",
                "pointJson": point_json,
                "token": captcha_data['token']
            }
            
            response = self.session.post(url, json=payload, headers=headers, timeout=30)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    if data.get('code') == 200:
                        print("✅ 验证码验证成功")
                        return self.final_sign_request(
                            captcha_data['token'], 
                            x, 
                            y, 
                            captcha_data.get('secretKey', '')
                        )
                    else:
                        print(f"❌ 验证码验证失败: {data.get('message', '未知错误')}")
                        return False
                        
                except json.JSONDecodeError as e:
                    print(f"❌ 验证码验证响应解析失败")
                    return False
            else:
                print(f"❌ 验证码验证请求失败: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ 验证码验证异常: {e}")
            return False
    
    def setup_proxy(self, proxy_url):
        """设置代理"""
        if proxy_url:
            self.proxy = {
                'http': proxy_url,
                'https': proxy_url
            }
            self.session.proxies.update(self.proxy)
            time.sleep(random.uniform(2, 5))
        else:
            self.proxy = None
            self.session.proxies.clear()
    
    def test_proxy(self):
        """测试代理连接"""
        try:
            response = self.session.get('https://www.coresky.com', timeout=10)
            if response.status_code == 200:
                return True
        except Exception as e:
            return False
    
    def create_signature(self, private_key):
        """使用EIP-4361协议进行签名"""
        try:
            private_key = private_key.strip()
            
            if private_key.startswith('0x') or private_key.startswith('0X'):
                private_key = private_key[2:]
            
            if len(private_key) != 64:
                raise ValueError(f"私钥长度不正确: {len(private_key)}")
            
            private_key = '0x' + private_key.lower()
            
            account = Account.from_key(private_key)
            wallet_address = account.address
            
            message = f"Welcome to CoreSky!\n\nClick to sign in and accept the CoreSky Terms of Service.\n\nThis request will not trigger a blockchain transaction or cost any gas fees.\n\nYour authentication status will reset after 24 hours.\n\nWallet address:\n\n{wallet_address}"
            
            message_encoded = encode_defunct(text=message)
            signature = account.sign_message(message_encoded)
            
            signature_hex = signature.signature.hex()
            if not signature_hex.startswith('0x'):
                signature_hex = '0x' + signature_hex
            
            return wallet_address, signature_hex
            
        except Exception as e:
            print(f"❌ 签名生成失败: {e}")
            return None, None
    
    def login(self, private_key, max_attempts=3):
        """登录获取token"""
        for attempt in range(1, max_attempts + 1):
            try:
                self.wait_between_requests()
                
                wallet_address, signature = self.create_signature(private_key)
                if not wallet_address or not signature:
                    return False
                    
                self.wallet_address = wallet_address
                
                url = "https://www.coresky.com/api/user/login"
                headers = {
                    'Content-Type': 'application/json',
                    'Origin': 'https://www.coresky.com',
                    'Referer': 'https://www.coresky.com/tasks-rewards',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
                
                payload = {
                    "address": wallet_address,
                    "projectId": "",
                    "refCode": "",
                    "signature": signature
                }
                
                response = self.session.post(url, json=payload, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        
                        if data.get('code') == 500 and 'exceeded limit' in data.get('message', ''):
                            if self.handle_rate_limit_error(attempt, max_attempts):
                                continue
                            else:
                                return False
                        
                        token_pattern = r'ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'
                        token_matches = re.findall(token_pattern, response.text)
                        
                        if token_matches:
                            self.token = token_matches[0]
                            print(f"✅ 登录成功: {wallet_address[:10]}...")
                            return True
                        else:
                            print("❌ 未找到有效token")
                            return False
                            
                    except json.JSONDecodeError:
                        print(f"❌ 响应不是有效的JSON格式")
                        return False
                        
                else:
                    if response.status_code in [429, 500, 502, 503, 504]:
                        if self.handle_rate_limit_error(attempt, max_attempts):
                            continue
                    
                    print(f"❌ 登录失败: {response.status_code}")
                    return False
                    
            except requests.exceptions.RequestException as e:
                print(f"❌ 网络请求异常 (尝试 {attempt}/{max_attempts})")
                if attempt < max_attempts:
                    time.sleep(random.uniform(10, 20))
                    continue
                return False
                
            except Exception as e:
                print(f"❌ 登录异常: {e}")
                return False
        
        return False
    
    def get_captcha(self):
        """获取人机验证"""
        try:
            if not self.token or not self.token.startswith('ey'):
                print(f"❌ Token格式错误")
                return None
            
            url = "https://www.coresky.com/api/captcha/get"
            
            headers = {
                'Content-Type': 'application/json',
                'Token': self.token,
                'Origin': 'https://www.coresky.com',
                'Referer': 'https://www.coresky.com/tasks-rewards',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            
            payload = {"captchaType": "blockPuzzle"}
            
            response = self.session.post(url, json=payload, headers=headers, timeout=30)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    if data.get('code') == 40001:
                        print(f"❌ 授权失败: {data.get('message')}")
                        return None
                    
                    def extract_field_from_response(response_data, field_name):
                        if isinstance(response_data, dict):
                            if field_name in response_data:
                                return response_data[field_name]
                            for key, value in response_data.items():
                                if isinstance(value, dict):
                                    result = extract_field_from_response(value, field_name)
                                    if result:
                                        return result
                                elif isinstance(value, list):
                                    for item in value:
                                        if isinstance(item, dict):
                                            result = extract_field_from_response(item, field_name)
                                            if result:
                                                return result
                        return None
                    
                    original_image = extract_field_from_response(data, 'originalImageBase64')
                    jigsaw_image = extract_field_from_response(data, 'jigsawImageBase64')
                    captcha_token = extract_field_from_response(data, 'token')
                    secret_key = extract_field_from_response(data, 'secretKey') or extract_field_from_response(data, 'secretkey')
                    
                    if not all([original_image, jigsaw_image, captcha_token]):
                        print(f"❌ 关键字段缺失")
                        return None
                    
                    print(f"✅ 获取验证码成功")
                    
                    return {
                        'originalImageBase64': original_image,
                        'jigsawImageBase64': jigsaw_image,
                        'token': captcha_token,
                        'secretKey': secret_key or ''
                    }
                    
                except json.JSONDecodeError as e:
                    print(f"❌ JSON解析失败")
                    return None
            else:
                print(f"❌ 获取验证码失败: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ 获取验证码异常: {e}")
            return None
    
    def solve_captcha(self, captcha_data):
        """解决滑块验证码"""
        try:
            original_img_data = base64.b64decode(captcha_data['originalImageBase64'])
            jigsaw_img_data = base64.b64decode(captcha_data['jigsawImageBase64'])
            
            original_img = cv2.imdecode(np.frombuffer(original_img_data, np.uint8), cv2.IMREAD_COLOR)
            jigsaw_img = cv2.imdecode(np.frombuffer(jigsaw_img_data, np.uint8), cv2.IMREAD_COLOR)
            
            debug_dir = "debug_images"
            if not os.path.exists(debug_dir):
                os.makedirs(debug_dir)
            
            timestamp = int(time.time())
            
            original_gray = cv2.cvtColor(original_img, cv2.COLOR_BGR2GRAY)
            jigsaw_gray = cv2.cvtColor(jigsaw_img, cv2.COLOR_BGR2GRAY)
            
            original_blur = cv2.GaussianBlur(original_gray, (3, 3), 0)
            jigsaw_blur = cv2.GaussianBlur(jigsaw_gray, (3, 3), 0)
            
            original_edges = cv2.Canny(original_blur, 50, 150)
            jigsaw_edges = cv2.Canny(jigsaw_blur, 50, 150)
            
            methods = [
                ('TM_CCOEFF_NORMED', cv2.TM_CCOEFF_NORMED),
                ('TM_CCORR_NORMED', cv2.TM_CCORR_NORMED),
                ('TM_SQDIFF_NORMED', cv2.TM_SQDIFF_NORMED)
            ]
            
            best_match = None
            best_score = 0
            
            for method_name, method in methods:
                result = cv2.matchTemplate(original_gray, jigsaw_gray, method)
                min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(result)
                
                if method == cv2.TM_SQDIFF_NORMED:
                    score = 1 - min_val
                    loc = min_loc
                else:
                    score = max_val
                    loc = max_loc
                
                if score > best_score:
                    best_score = score
                    best_match = loc
                
                result_edges = cv2.matchTemplate(original_edges, jigsaw_edges, method)
                min_val_e, max_val_e, min_loc_e, max_loc_e = cv2.minMaxLoc(result_edges)
                
                if method == cv2.TM_SQDIFF_NORMED:
                    score_e = 1 - min_val_e
                    loc_e = min_loc_e
                else:
                    score_e = max_val_e
                    loc_e = max_loc_e
                
                if score_e > best_score:
                    best_score = score_e
                    best_match = loc_e
            
            x, y = best_match
            y = 5
            
            print(f"🎯 检测位置: x={x}, y={y}, 置信度={best_score:.3f}")
            
            return x, y
            
        except Exception as e:
            print(f"❌ 验证码解析失败: {e}")
            return random.randint(100, 200), 5
    
    def encrypt_point_json(self, x, y, secret_key):
        """使用AES-128-ECB + PKCS7加密生成pointJson"""
        try:
            point_data = {"x": x, "y": y}
            json_str = json.dumps(point_data, separators=(',', ':'))
            
            if not secret_key:
                return None
            
            if len(secret_key) < 16:
                secret_key = secret_key.ljust(16, '0')
            elif len(secret_key) > 16:
                secret_key = secret_key[:16]
            
            cipher = AES.new(secret_key.encode('utf-8'), AES.MODE_ECB)
            padded_data = pad(json_str.encode('utf-8'), AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            point_json = base64.b64encode(encrypted_data).decode('utf-8')
            
            return point_json
            
        except Exception as e:
            print(f"❌ pointJson加密失败: {e}")
            return None
    
    def encrypt_response_token(self, captcha_token, x, y, secret_key):
        """生成responseToken"""
        try:
            point_data = {"x": x, "y": y}
            point_json = json.dumps(point_data, separators=(',', ':'))
            raw_data = captcha_token + "---" + point_json
            
            if not secret_key:
                return None
            
            if len(secret_key) < 16:
                secret_key = secret_key.ljust(16, '0')
            elif len(secret_key) > 16:
                secret_key = secret_key[:16]
            
            cipher = AES.new(secret_key.encode('utf-8'), AES.MODE_ECB)
            padded_data = pad(raw_data.encode('utf-8'), AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            response_token = base64.b64encode(encrypted_data).decode('utf-8')
            
            return response_token
            
        except Exception as e:
            print(f"❌ responseToken生成失败: {e}")
            return None

    def final_sign_request(self, captcha_token, x, y, secret_key):
        """最终签到请求"""
        try:
            response_token = self.encrypt_response_token(captcha_token, x, y, secret_key)
            if not response_token:
                return False
            
            url = "https://www.coresky.com/api/taskwall/meme/sign"
            
            headers = {
                'authority': 'www.coresky.com',
                'content-type': 'application/json',
                'origin': 'https://www.coresky.com',
                'referer': 'https://www.coresky.com/tasks-rewards',
                'Token': self.token,
                'x-kl-kfa-ajax-request': 'Ajax_Request',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            
            payload = {
                "responseToken": response_token
            }
            
            response = self.session.post(url, json=payload, headers=headers, timeout=30)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    if data.get('code') == 200 or data.get('success') == True:
                        print("🎉 签到成功！")
                        return True
                    else:
                        print(f"❌ 签到失败: {data.get('message', '未知错误')}")
                        return False
                        
                except json.JSONDecodeError as e:
                    print(f"❌ 签到响应解析失败")
                    return False
            else:
                print(f"❌ 签到请求失败: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ 签到异常: {e}")
            return False

    def query_points(self):
        """查询账户积分"""
        try:
            url = "https://www.coresky.com/api/user/point"
            
            headers = {
                'authority': 'www.coresky.com',
                'content-type': 'application/json',
                'origin': 'https://www.coresky.com',
                'referer': 'https://www.coresky.com/meme',
                'Token': self.token,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            
            payload = {}
            
            response = self.session.post(url, json=payload, headers=headers, timeout=30)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    points_raw = data.get('debug', 0)
                    
                    try:
                        if isinstance(points_raw, str):
                            points = int(points_raw) if points_raw.isdigit() else 0
                        elif isinstance(points_raw, (int, float)):
                            points = int(points_raw)
                        else:
                            points = 0
                    except (ValueError, TypeError):
                        points = 0
                    
                    print(f"💰 当前积分: {points}")
                    return points
                        
                except json.JSONDecodeError as e:
                    print(f"❌ 积分查询响应解析失败")
                    return None
            else:
                print(f"❌ 积分查询失败: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ 积分查询异常: {e}")
            return None

    def vote_task(self, vote_points):
        """进行投票任务"""
        try:
            if vote_points is None:
                return False
            
            try:
                if isinstance(vote_points, str):
                    vote_points = int(vote_points) if vote_points.isdigit() else 0
                elif isinstance(vote_points, (int, float)):
                    vote_points = int(vote_points)
                else:
                    vote_points = 0
            except (ValueError, TypeError):
                return False
            
            if vote_points <= 0:
                print(f"⚠️ 积分为0，无法投票")
                return False
            
            url = "https://www.coresky.com/api/taskwall/meme/vote"
            
            headers = {
                'authority': 'www.coresky.com',
                'content-type': 'application/json',
                'origin': 'https://www.coresky.com',
                'referer': 'https://www.coresky.com/meme',
                'Token': self.token,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            
            payload = {
                "projectId": 51,
                "voteNum": vote_points
            }
            
            response = self.session.post(url, json=payload, headers=headers, timeout=30)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    if data.get('code') == 200 and data.get('message') == 'success':
                        print(f"🗳️ 投票成功！投票数量: {vote_points}")
                        return True
                    else:
                        print(f"❌ 投票失败: {data.get('message', '未知错误')}")
                        return False
                        
                except json.JSONDecodeError as e:
                    print(f"❌ 投票响应解析失败")
                    return False
            else:
                print(f"❌ 投票请求失败: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ 投票异常: {e}")
            return False
    
    def run_single_account(self, private_key, proxy_url=None):
        """单个账户任务流程"""
        print(f"\n{'='*50}")
        print(f"开始处理账户...")
        
        self.setup_proxy(proxy_url)
        
        if proxy_url:
            if not self.test_proxy():
                print("⚠️ 代理连接失败，使用直连")
                self.setup_proxy(None)
        
        if not self.login(private_key):
            return False
        
        sign_success = False
        vote_success = False
        
        if self.TASK_MODE in ["sign_only", "both"]:
            print("🎯 开始签到任务...")
            
            captcha_data = self.get_captcha()
            if not captcha_data:
                print("❌ 获取验证码失败")
                if self.TASK_MODE == "sign_only":
                    return False
            else:
                x, y = self.solve_captcha(captcha_data)
                
                sign_success = self.check_in(captcha_data, x, y)
                
                if sign_success:
                    print("✅ 签到任务完成！")
                else:
                    print("❌ 签到任务失败")
                    if self.TASK_MODE == "sign_only":
                        return False
        
        if self.TASK_MODE in ["vote_only", "both"]:
            print("🎯 开始投票任务...")
            
            if sign_success:
                time.sleep(random.uniform(2, 5))
            
            points = self.query_points()
            
            if points is not None:
                try:
                    if isinstance(points, str):
                        points = int(points) if points.isdigit() else 0
                    elif isinstance(points, (int, float)):
                        points = int(points)
                    else:
                        points = 0
                except (ValueError, TypeError):
                    points = 0
                
                if points > 0:
                    time.sleep(random.uniform(2, 5))
                    
                    vote_success = self.vote_task(points)
                    
                    if vote_success:
                        print("✅ 投票任务完成！")
                    else:
                        print("❌ 投票任务失败")
                        if self.TASK_MODE == "vote_only":
                            return False
                else:
                    print("⚠️ 积分为0，无法进行投票")
                    if self.TASK_MODE == "vote_only":
                        return False
            else:
                print("❌ 查询积分失败")
                if self.TASK_MODE == "vote_only":
                    return False
        
        # 根据任务模式判断整体成功状态
        if self.TASK_MODE == "sign_only":
            return sign_success
        elif self.TASK_MODE == "vote_only":
            return vote_success
        elif self.TASK_MODE == "both":
            if sign_success and vote_success:
                print("🎉 所有任务完成成功！")
                return True
            elif sign_success or vote_success:
                print("⚠️ 部分任务完成")
                return True
            else:
                print("❌ 所有任务都失败了")
                return False
        
        return False
    
    def run_all_accounts(self):
        """运行所有账户"""
        private_keys = self.load_private_keys()
        proxies = self.load_proxies()
        
        if not private_keys:
            print("❌ 没有找到私钥")
            return
        
        print(f"📊 加载了 {len(private_keys)} 个私钥")
        print(f"📊 加载了 {len(proxies)} 个代理")
        print(f"🎯 任务模式: {self.TASK_MODE}")
        
        success_count = 0
        
        print(f"⏰ 程序启动，等待后开始...")
        time.sleep(random.uniform(5, 10))
        
        for i, private_key in enumerate(private_keys):
            try:
                print(f"\n{'='*60}")
                print(f"📋 处理账户 {i+1}/{len(private_keys)}")
                
                proxy_url = proxies[i] if i < len(proxies) else None
                if proxy_url:
                    proxy_info = proxy_url.split('@')[1] if '@' in proxy_url else proxy_url
                    print(f"🔗 使用代理: {proxy_info.split(':')[0]}:****")
                
                if self.run_single_account(private_key, proxy_url):
                    success_count += 1
                
                if i < len(private_keys) - 1:
                    wait_time = random.uniform(30, 60)
                    print(f"⏰ 等待 {wait_time:.1f} 秒后处理下一个账户...")
                    time.sleep(wait_time)
                
            except Exception as e:
                print(f"❌ 处理账户 {i+1} 时发生异常: {e}")
                continue
        
        print(f"\n{'='*60}")
        print(f"🎉 任务执行完成! 成功: {success_count}/{len(private_keys)}")


def main():
    print("🚀 CoreSky自动任务脚本启动...")
    
    # 检查必要的依赖
    missing_deps = []
    try:
        import cv2
    except ImportError:
        missing_deps.append("opencv-python")
    
    try:
        import numpy as np
    except ImportError:
        missing_deps.append("numpy")
    
    try:
        from eth_account import Account
    except ImportError:
        missing_deps.append("eth-account")
    
    try:
        from Crypto.Cipher import AES
    except ImportError:
        missing_deps.append("pycryptodome")
    
    if missing_deps:
        print(f"❌ 缺少必要的依赖库: {', '.join(missing_deps)}")
        print(f"请运行: pip install {' '.join(missing_deps)}")
        return
    
    print("✅ 所有依赖库检查通过")
    
    # 检查配置文件
    pk_file_path = "/Users/mac/Desktop/未命名文件夹/coresky签到脚本/pk.txt"
    ip_file_path = "/Users/mac/Desktop/未命名文件夹/coresky签到脚本/ip.txt"
    
    if not os.path.exists(pk_file_path):
        print(f"❌ 未找到{pk_file_path}文件")
        print("请在指定目录下创建pk.txt文件，每行一个私钥")
        return
    
    if not os.path.exists(ip_file_path):
        print("📝 未找到ip.txt文件，将使用直连")
        print("如需使用代理，请在指定目录创建ip.txt文件，格式：ip:端口:账号:密码:协议")
    
    checker = CoreSkyChecker()
    
    # 显示任务模式配置
    mode_descriptions = {
        "sign_only": "只执行签到任务",
        "vote_only": "只执行投票任务", 
        "both": "执行签到和投票任务"
    }
    
    current_mode = checker.TASK_MODE
    print(f"🎯 当前任务模式: {current_mode}")
    print(f"📝 模式说明: {mode_descriptions.get(current_mode, '未知模式')}")
    
    if current_mode not in ["sign_only", "vote_only", "both"]:
        print("❌ 任务模式配置错误！")
        print("请在代码中设置 TASK_MODE 为以下值之一:")
        print("  - 'sign_only': 只执行签到")
        print("  - 'vote_only': 只执行投票")
        print("  - 'both': 执行签到和投票")
        return
    
    checker.run_all_accounts()


if __name__ == "__main__":
    main()
