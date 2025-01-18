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
Hadoop YARN 未授权访问检测工具

使用方法:
    单个目标:
        python brute_yarn.py -t 192.168.1.1
    批量检测:
        python brute_yarn.py -a ip.txt
    指定端口:
        python brute_yarn.py -t 192.168.1.1 -p 8088
    显示详细信息:
        python brute_yarn.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认8088)
    -v  显示详细信息

支持检测的端口:
    - 8088: YARN ResourceManager Web UI默认端口
    - 8050: YARN ResourceManager默认端口
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
    检测Hadoop YARN未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
            "Accept": "application/json"
        }
        
        # 检测点1: 访问集群信息
        url = f"http://{ip}:{port}/ws/v1/cluster/info"
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        
        if response.status_code == 200:
            _t = f"[+] {ip}:{port} - 存在Hadoop YARN未授权访问"
            save_result(_t)
            logger.info(_t)
            
            try:
                data = response.json()
                if 'clusterInfo' in data:
                    info = data['clusterInfo']
                    version = info.get('hadoopVersion', '未知')
                    state = info.get('state', '未知')
                    _t = f"[*] {ip}:{port} - Hadoop版本: {version}, 集群状态: {state}"
                    save_result(_t)
                    logger.info(_t)
            except:
                pass
            
            # 检测点2: 获取集群指标
            url = f"http://{ip}:{port}/ws/v1/cluster/metrics"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'clusterMetrics' in data:
                        metrics = data['clusterMetrics']
                        nodes = metrics.get('activeNodes', 0)
                        apps = metrics.get('appsSubmitted', 0)
                        containers = metrics.get('containersAllocated', 0)
                        _t = f"[*] {ip}:{port} - 活动节点: {nodes}, 已提交应用: {apps}, 已分配容器: {containers}"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
            
            # 检测点3: 获取节点列表
            url = f"http://{ip}:{port}/ws/v1/cluster/nodes"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'nodes' in data and 'node' in data['nodes']:
                        nodes = data['nodes']['node']
                        _t = f"[*] {ip}:{port} - 发现 {len(nodes)} 个节点"
                        save_result(_t)
                        logger.info(_t)
                        
                        # 列出前5个节点
                        for node in nodes[:5]:
                            state = node.get('state', '未知')
                            rack = node.get('rack', '未知')
                            _t = f"[*] {ip}:{port} - 节点: {node.get('id', '未知')}, 状态: {state}, 机架: {rack}"
                            save_result(_t)
                            logger.info(_t)
                except:
                    pass
            
            # 检测点4: 获取应用列表
            url = f"http://{ip}:{port}/ws/v1/cluster/apps"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'apps' in data and data['apps']:
                        apps = data['apps']['app']
                        _t = f"[*] {ip}:{port} - 发现 {len(apps)} 个应用"
                        save_result(_t)
                        logger.info(_t)
                        
                        # 列出前5个应用
                        for app in apps[:5]:
                            name = app.get('name', '未知')
                            state = app.get('state', '未知')
                            user = app.get('user', '未知')
                            _t = f"[*] {ip}:{port} - 应用: {name}, 状态: {state}, 用户: {user}"
                            save_result(_t)
                            logger.info(_t)
                except:
                    pass
            
            # 检测点5: 获取调度器信息
            url = f"http://{ip}:{port}/ws/v1/cluster/scheduler"
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'scheduler' in data:
                        scheduler = data['scheduler']
                        type = scheduler.get('schedulerInfo', {}).get('type', '未知')
                        _t = f"[*] {ip}:{port} - 调度器类型: {type}"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
            
            # 检测点6: 获取系统指标
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
    parser.add_option("-p", "--port", dest="port", default="8088", help="端口(默认8088)")
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
        save_to_file("yarn_unauthorized.txt", "\n".join(result))

if __name__ == "__main__":
    main() 