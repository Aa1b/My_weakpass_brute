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
Spark 未授权访问检测工具

使用方法:
    单个目标:
        python brute_spark.py -t 192.168.1.1
    批量检测:
        python brute_spark.py -a ip.txt
    指定端口:
        python brute_spark.py -t 192.168.1.1 -p 8080
    显示详细信息:
        python brute_spark.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认8080)
    -v  显示详细信息

支持检测的端口:
    - 8080: Spark Master Web UI默认端口
    - 8081: Spark Worker Web UI默认端口
    - 4040: Spark Application Web UI默认端口
    - 7077: Spark Master默认端口
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

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

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
    检测Spark未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
            "Accept": "application/json"
        }
        
        # 检测点1: 访问Master状态页面
        url = f"http://{ip}:{port}/json/"
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        
        if response.status_code == 200:
            _t = f"[+] {ip}:{port} - 存在Spark未授权访问"
            save_result(_t)
            logger.info(_t)
            
            try:
                data = response.json()
                if 'url' in data:
                    url = data.get('url', '未知')
                    version = data.get('version', '未知')
                    _t = f"[*] {ip}:{port} - Spark Master URL: {url}, 版本: {version}"
                    save_result(_t)
                    logger.info(_t)
                
                # 获取Worker信息
                if 'workers' in data:
                    workers = data['workers']
                    _t = f"[*] {ip}:{port} - 发现 {len(workers)} 个Worker节点"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 列出前5个Worker
                    for worker in workers[:5]:
                        worker_id = worker.get('id', '未知')
                        state = worker.get('state', '未知')
                        cores = worker.get('cores', 0)
                        memory = worker.get('memory', 0)
                        _t = f"[*] {ip}:{port} - Worker: {worker_id}, 状态: {state}, CPU核心: {cores}, 内存: {memory}MB"
                        save_result(_t)
                        logger.info(_t)
            except:
                pass
            
            # 检测点2: 访问应用程序列表
            url = f"http://{ip}:{port}/api/v1/applications"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                try:
                    apps = response.json()
                    if apps:
                        _t = f"[*] {ip}:{port} - 发现 {len(apps)} 个应用程序"
                        save_result(_t)
                        logger.info(_t)
                        
                        # 列出前5个应用
                        for app in apps[:5]:
                            app_id = app.get('id', '未知')
                            name = app.get('name', '未知')
                            state = app.get('state', '未知')
                            _t = f"[*] {ip}:{port} - 应用: {name}({app_id}), 状态: {state}"
                            save_result(_t)
                            logger.info(_t)
                except:
                    pass
            
            # 检测点3: 访问环境变量
            url = f"http://{ip}:{port}/environment"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                _t = f"[+] {ip}:{port} - 环境变量信息可访问"
                save_result(_t)
                logger.info(_t)
                
                try:
                    data = response.json()
                    if 'sparkProperties' in data:
                        props = data['sparkProperties']
                        _t = f"[*] {ip}:{port} - 发现 {len(props)} 个Spark配置项"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
            
            # 检测点4: 访问日志
            url = f"http://{ip}:{port}/logPage"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                _t = f"[+] {ip}:{port} - 日志信息可访问"
                save_result(_t)
                logger.info(_t)
            
            # 检测点5: 检查REST API提交应用功能
            url = f"http://{ip}:{port}/v1/submissions/create"
            response = requests.post(url, headers=headers, timeout=5, verify=False)
            if response.status_code != 404:
                _t = f"[+] {ip}:{port} - REST API提交应用接口可访问"
                save_result(_t)
                logger.info(_t)
            
            # 检测点6: 检查JMX信息
            url = f"http://{ip}:{port}/jmx"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                _t = f"[+] {ip}:{port} - JMX接口可访问"
                save_result(_t)
                logger.info(_t)
                
                try:
                    data = response.json()
                    if 'beans' in data:
                        for bean in data['beans']:
                            if 'name' in bean and 'java.lang:type=Memory' in bean['name']:
                                heap = bean.get('HeapMemoryUsage', {})
                                used = heap.get('used', 0) / 1024 / 1024
                                max = heap.get('max', 0) / 1024 / 1024
                                _t = f"[*] {ip}:{port} - 堆内存使用: {used:.2f}MB / {max:.2f}MB"
                                save_result(_t)
                                logger.info(_t)
                                break
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
    parser.add_option("-p", "--port", dest="port", default="8080", help="端口(默认8080)")
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
        save_to_file("spark_unauthorized.txt", "\n".join(result))

if __name__ == "__main__":
    main() 