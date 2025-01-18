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
Docker Registry 未授权访问检测工具

使用方法:
    单个目标:
        python brute_docker_registry.py -t 192.168.1.1
    批量检测:
        python brute_docker_registry.py -a ip.txt
    指定端口:
        python brute_docker_registry.py -t 192.168.1.1 -p 5000
    显示详细信息:
        python brute_docker_registry.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认5000)
    -v  显示详细信息

支持检测的端口:
    - 5000: Docker Registry默认端口
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

# 默认凭据列表
DEFAULT_CREDENTIALS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '123456'),
    ('docker', 'docker'),
    ('admin', '')
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

def check_default_credentials(ip, port):
    """
    检查默认凭据
    
    Args:
        ip: 目标IP
        port: 目标端口
    Returns:
        tuple: (是否成功, 用户名, 密码, 认证头)
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36'
    }
    
    for username, password in DEFAULT_CREDENTIALS:
        try:
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers['Authorization'] = f'Basic {auth}'
            
            url = f"http://{ip}:{port}/v2/"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                return True, username, password, headers
        except:
            continue
    
    return False, None, None, None

def brute(ip, port):
    """
    检测Docker Registry未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        # 检测点1: 访问API版本信息
        url = f"http://{ip}:{port}/v2/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                _t = f"[+] {ip}:{port} - 发现Docker Registry服务"
                save_result(_t)
                logger.info(_t)
                
                # 检测点2: 获取API版本信息
                version = response.headers.get('Docker-Distribution-Api-Version')
                if version:
                    _t = f"[*] {ip}:{port} - API版本: {version}"
                    save_result(_t)
                    logger.info(_t)
                
                # 检测点3: 获取仓库列表
                url = f"http://{ip}:{port}/v2/_catalog"
                try:
                    response = requests.get(url, headers=headers, timeout=5, verify=False)
                    if response.status_code == 200:
                        data = response.json()
                        repositories = data.get('repositories', [])
                        _t = f"[*] {ip}:{port} - 发现 {len(repositories)} 个仓库"
                        save_result(_t)
                        logger.info(_t)
                        
                        # 显示前5个仓库
                        for repo in repositories[:5]:
                            _t = f"[*] {ip}:{port} - 仓库: {repo}"
                            save_result(_t)
                            logger.info(_t)
                            
                            # 检测点4: 获取标签列表
                            url = f"http://{ip}:{port}/v2/{repo}/tags/list"
                            try:
                                response = requests.get(url, headers=headers, timeout=5, verify=False)
                                if response.status_code == 200:
                                    data = response.json()
                                    tags = data.get('tags', [])
                                    _t = f"[*] {ip}:{port} - 仓库 {repo} 有 {len(tags)} 个标签"
                                    save_result(_t)
                                    logger.info(_t)
                                    
                                    # 显示前5个标签
                                    for tag in tags[:5]:
                                        _t = f"[*] {ip}:{port} - 标签: {tag}"
                                        save_result(_t)
                                        logger.info(_t)
                                        
                                        # 检测点5: 获取镜像清单
                                        url = f"http://{ip}:{port}/v2/{repo}/manifests/{tag}"
                                        headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'
                                        try:
                                            response = requests.get(url, headers=headers, timeout=5, verify=False)
                                            if response.status_code == 200:
                                                data = response.json()
                                                _t = f"[*] {ip}:{port} - 镜像 {repo}:{tag} 大小: {data.get('config', {}).get('size', 0)} 字节"
                                                save_result(_t)
                                                logger.info(_t)
                                        except:
                                            pass
                            except:
                                pass
                except:
                    pass
                
                # 检测点6: 检查上传权限
                test_repo = "test"
                test_tag = "latest"
                url = f"http://{ip}:{port}/v2/{test_repo}/manifests/{test_tag}"
                headers['Content-Type'] = 'application/vnd.docker.distribution.manifest.v2+json'
                data = {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "config": {
                        "mediaType": "application/vnd.docker.container.image.v1+json",
                        "size": 1,
                        "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    },
                    "layers": []
                }
                try:
                    response = requests.put(url, headers=headers, json=data, timeout=5, verify=False)
                    if response.status_code in [201, 202]:
                        _t = f"[!] {ip}:{port} - 具有镜像上传权限"
                        save_result(_t)
                        logger.info(_t)
                        
                        # 清理测试镜像
                        url = f"http://{ip}:{port}/v2/{test_repo}/manifests/{response.headers.get('Docker-Content-Digest', '')}"
                        requests.delete(url, headers=headers, timeout=5, verify=False)
                except:
                    pass
                
                return True
            elif response.status_code == 401:
                _t = f"[*] {ip}:{port} - 需要认证"
                save_result(_t)
                logger.info(_t)
                
                # 检查默认凭据
                success, username, password, auth_headers = check_default_credentials(ip, port)
                if success:
                    _t = f"[+] {ip}:{port} - 存在默认凭据: {username}/{password}"
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
    parser.add_option("-p", "--port", dest="port", default="5000", help="端口(默认5000)")
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
        save_to_file("docker_registry_unauthorized.txt", "\n".join(result))

if __name__ == "__main__":
    main() 