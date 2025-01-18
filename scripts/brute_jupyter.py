#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import socket
import logging
import queue
import requests
from threading import Thread, Lock
from optparse import OptionParser
import re
import json
import base64

"""
Jupyter Notebook 未授权访问检测工具

使用方法:
    单个目标:
        python brute_jupyter.py -t 192.168.1.1
    批量检测:
        python brute_jupyter.py -a ip.txt
    指定端口:
        python brute_jupyter.py -t 192.168.1.1 -p 8888
    显示详细信息:
        python brute_jupyter.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认8888)
    -v  显示详细信息

支持检测的端口:
    - 8888: Jupyter Notebook默认端口
"""

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 全局变量
result = []
result_lock = Lock()
task_queue = queue.Queue()

# 默认Token列表
DEFAULT_TOKENS = [
    '',
    'jupyter',
    'admin',
    'password',
    '123456'
]

def save_result(text):
    """
    安全地保存结果
    
    Args:
        text: 要保存的文本
    """
    with result_lock:
        result.append(text)

def save_to_file(filename, text):
    """
    安全地写入文件
    
    Args:
        filename: 文件名
        text: 要写入的文本
    """
    try:
        with open(filename, 'a+', encoding='utf-8') as f:
            f.write(f"{text}\n")
    except Exception as e:
        logger.error(f"[!] 写入文件失败 {filename}: {str(e)}")

def check_token(ip, port, token):
    """
    检查Token是否有效
    
    Args:
        ip: 目标IP
        port: 目标端口
        token: 要检查的Token
    Returns:
        tuple: (是否成功, Token, 认证头)
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36'
    }
    
    try:
        url = f"http://{ip}:{port}/api/kernels"
        if token:
            headers['Authorization'] = f'token {token}'
        
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        
        if response.status_code == 200:
            return True, token, headers
    except:
        pass
    
    return False, None, None

def brute(ip, port):
    """
    检测Jupyter Notebook未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        # 检测点1: 访问根路径检查服务
        url = f"http://{ip}:{port}/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200 and ('jupyter' in response.text.lower() or 'ipython' in response.text.lower()):
                _t = f"[+] {ip}:{port} - 发现Jupyter Notebook服务"
                save_result(_t)
                logger.info(_t)
                
                # 检测点2: 检查是否需要Token
                if 'token=' in response.text:
                    _t = f"[*] {ip}:{port} - 需要Token认证"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 检测点3: 检查默认Token
                    for token in DEFAULT_TOKENS:
                        success, valid_token, auth_headers = check_token(ip, port, token)
                        if success:
                            _t = f"[+] {ip}:{port} - 发现有效Token: {valid_token if valid_token else '空'}"
                            save_result(_t)
                            logger.info(_t)
                            
                            # 检测点4: 获取内核信息
                            url = f"http://{ip}:{port}/api/kernels"
                            try:
                                response = requests.get(url, headers=auth_headers, timeout=5, verify=False)
                                if response.status_code == 200:
                                    kernels = response.json()
                                    _t = f"[*] {ip}:{port} - 发现 {len(kernels)} 个活动内核"
                                    save_result(_t)
                                    logger.info(_t)
                                    
                                    # 显示前5个内核信息
                                    for kernel in kernels[:5]:
                                        _t = f"[*] {ip}:{port} - 内核ID: {kernel.get('id')}, 名称: {kernel.get('name')}"
                                        save_result(_t)
                                        logger.info(_t)
                            except:
                                pass
                            
                            # 检测点5: 获取会话信息
                            url = f"http://{ip}:{port}/api/sessions"
                            try:
                                response = requests.get(url, headers=auth_headers, timeout=5, verify=False)
                                if response.status_code == 200:
                                    sessions = response.json()
                                    _t = f"[*] {ip}:{port} - 发现 {len(sessions)} 个活动会话"
                                    save_result(_t)
                                    logger.info(_t)
                                    
                                    # 显示前5个会话信息
                                    for session in sessions[:5]:
                                        _t = f"[*] {ip}:{port} - 会话路径: {session.get('path')}, 类型: {session.get('type')}"
                                        save_result(_t)
                                        logger.info(_t)
                            except:
                                pass
                            
                            # 检测点6: 检查代码执行权限
                            url = f"http://{ip}:{port}/api/kernels"
                            data = {
                                "name": "python3"
                            }
                            try:
                                response = requests.post(url, headers=auth_headers, json=data, timeout=5, verify=False)
                                if response.status_code == 201:
                                    _t = f"[!] {ip}:{port} - 具有代码执行权限"
                                    save_result(_t)
                                    logger.info(_t)
                                    
                                    # 清理测试内核
                                    kernel_id = response.json().get('id')
                                    if kernel_id:
                                        url = f"http://{ip}:{port}/api/kernels/{kernel_id}"
                                        requests.delete(url, headers=auth_headers, timeout=5, verify=False)
                            except:
                                pass
                            
                            break
                else:
                    _t = f"[!] {ip}:{port} - 未启用Token认证"
                    save_result(_t)
                    logger.info(_t)
                
                return True
        except requests.exceptions.RequestException as e:
            logger.debug(f"[-] {ip}:{port} - 连接失败: {str(e)}")
    except Exception as e:
        logger.debug(f"[-] {ip}:{port} - {str(e)}")
    return False

def run(func, threadnum, ips, port, filename=None):
    """
    多线程运行检测函数
    
    Args:
        func: 要运行的函数
        threadnum: 线程数
        ips: IP列表
        port: 端口
        filename: 文件名(可选)
    """
    running_threads = []
    
    for ip in ips:
        while len(running_threads) >= threadnum:
            running_threads = [t for t in running_threads if t.is_alive()]
        
        if filename:
            t = Thread(target=func, args=(ip, port, filename))
        else:
            t = Thread(target=func, args=(ip, port))
        
        running_threads.append(t)
        t.start()
    
    for t in running_threads:
        t.join()

def scan(ip, port, filename):
    """
    扫描端口是否开放
    
    Args:
        ip: 目标IP
        port: 目标端口
        filename: 保存结果的文件名
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        res = s.connect_ex((ip, int(port)))
        if res == 0:
            with open(filename, 'a+') as f:
                f.write(f"{ip}\n")
    except:
        pass
    finally:
        s.close()

def main():
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target", help="目标IP")
    parser.add_option("-a", "--address", dest="address", help="IP列表文件")
    parser.add_option("-p", "--port", dest="port", default="8888", help="端口(默认8888)")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="显示详细信息")
    
    (options, args) = parser.parse_args()
    
    if options.verbose:
        logger.setLevel(logging.DEBUG)
    
    if not options.target and not options.address:
        parser.print_help()
        sys.exit(1)
    
    if options.target:
        brute(options.target, options.port)
    
    if options.address:
        try:
            with open(options.address) as f:
                ips = [ip.strip() for ip in f.readlines()]
            run(brute, 10, ips, options.port)
        except Exception as e:
            logger.error(f"[!] 读取文件失败 {options.address}: {str(e)}")
            sys.exit(1)
    
    if result:
        save_to_file("jupyter_unauthorized.txt", "\n".join(result))

if __name__ == "__main__":
    main() 