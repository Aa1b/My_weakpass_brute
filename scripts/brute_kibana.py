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

"""
Kibana 未授权访问检测工具

使用方法:
    单个目标:
        python brute_kibana.py -t 192.168.1.1
    批量检测:
        python brute_kibana.py -a ip.txt
    指定端口:
        python brute_kibana.py -t 192.168.1.1 -p 5601
    显示详细信息:
        python brute_kibana.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认5601)
    -v  显示详细信息

支持检测的端口:
    - 5601: Kibana默认端口
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

def brute(ip, port):
    """
    检测Kibana未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'kbn-version': '7.0.0'  # 添加一个默认的Kibana版本头
        }
        
        # 检测点1: 访问Kibana主页
        url = f"http://{ip}:{port}/"
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        
        if response.status_code == 200:
            _t = f"[+] {ip}:{port} - 存在Kibana未授权访问"
            save_result(_t)
            logger.info(_t)
            
            # 检测点2: 获取Kibana状态信息
            url = f"http://{ip}:{port}/api/status"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    version = data.get('version', {}).get('number', 'Unknown')
                    _t = f"[*] {ip}:{port} - Kibana版本: {version}"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 更新正确的版本号到请求头
                    headers['kbn-version'] = version
                except:
                    pass
            
            # 检测点3: 获取索引模式列表
            url = f"http://{ip}:{port}/api/saved_objects/_find?type=index-pattern&per_page=100"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    total = data.get('total', 0)
                    _t = f"[*] {ip}:{port} - 发现 {total} 个索引模式"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 列出前5个索引模式
                    for item in data.get('saved_objects', [])[:5]:
                        index_pattern = item.get('attributes', {}).get('title', '')
                        if index_pattern:
                            _t = f"[*] {ip}:{port} - 索引模式: {index_pattern}"
                            save_result(_t)
                            logger.info(_t)
                except:
                    pass
            
            # 检测点4: 获取仪表板列表
            url = f"http://{ip}:{port}/api/saved_objects/_find?type=dashboard&per_page=100"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    total = data.get('total', 0)
                    _t = f"[*] {ip}:{port} - 发现 {total} 个仪表板"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 列出前5个仪表板
                    for item in data.get('saved_objects', [])[:5]:
                        dashboard = item.get('attributes', {}).get('title', '')
                        if dashboard:
                            _t = f"[*] {ip}:{port} - 仪表板: {dashboard}"
                            save_result(_t)
                            logger.info(_t)
                except:
                    pass
            
            # 检测点5: 获取可视化列表
            url = f"http://{ip}:{port}/api/saved_objects/_find?type=visualization&per_page=100"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    total = data.get('total', 0)
                    _t = f"[*] {ip}:{port} - 发现 {total} 个可视化"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 列出前5个可视化
                    for item in data.get('saved_objects', [])[:5]:
                        viz = item.get('attributes', {}).get('title', '')
                        if viz:
                            _t = f"[*] {ip}:{port} - 可视化: {viz}"
                            save_result(_t)
                            logger.info(_t)
                except:
                    pass
            
            # 检测点6: 检查Dev Tools访问权限
            url = f"http://{ip}:{port}/api/console/proxy?path=_cat/indices&method=GET"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                _t = f"[+] {ip}:{port} - Dev Tools可访问"
                save_result(_t)
                logger.info(_t)
                
                # 尝试获取索引列表
                try:
                    indices = response.text.strip().split('\n')
                    _t = f"[*] {ip}:{port} - 发现 {len(indices)} 个索引"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 列出前5个索引
                    for index in indices[:5]:
                        _t = f"[*] {ip}:{port} - 索引: {index}"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
            
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
    parser.add_option("-p", "--port", dest="port", default="5601", help="端口(默认5601)")
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
        save_to_file("kibana_unauthorized.txt", "\n".join(result))

if __name__ == "__main__":
    main() 