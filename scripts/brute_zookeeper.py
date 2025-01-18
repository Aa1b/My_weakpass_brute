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
import telnetlib

"""
Zookeeper 未授权访问检测工具

使用方法:
    单个目标:
        python brute_zookeeper.py -t 192.168.1.1
    批量检测:
        python brute_zookeeper.py -a ip.txt
    指定端口:
        python brute_zookeeper.py -t 192.168.1.1 -p 2181
    显示详细信息:
        python brute_zookeeper.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认2181)
    -v  显示详细信息

支持检测的端口:
    - 2181: Zookeeper默认端口
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

# 四字命令列表
COMMANDS = [
    'conf',  # 打印服务配置信息
    'cons',  # 列出所有连接到服务器的客户端
    'stat',  # 查看服务器状态
    'ruok',  # 测试服务是否处于正确状态
    'dump',  # 列出未经处理的会话和临时节点
    'envi',  # 打印环境变量
    'wchs',  # 列出服务器watches信息
    'wchc',  # 列出服务器watches详细信息
    'wchp',  # 列出服务器watches路径
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

def send_command(ip, port, cmd, timeout=5):
    """
    发送四字命令到Zookeeper服务器
    
    Args:
        ip: 目标IP
        port: 目标端口
        cmd: 四字命令
        timeout: 超时时间(秒)
    Returns:
        str: 命令执行结果
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, int(port)))
        sock.send(cmd.encode())
        data = sock.recv(2048)
        sock.close()
        return data.decode('utf-8', errors='ignore')
    except:
        return None

def brute(ip, port):
    """
    检测Zookeeper未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        # 检测点1: 使用ruok命令检查服务状态
        response = send_command(ip, port, 'ruok')
        if response == 'imok':
            _t = f"[+] {ip}:{port} - 存在Zookeeper未授权访问"
            save_result(_t)
            logger.info(_t)
            
            # 检测点2: 获取服务器状态信息
            response = send_command(ip, port, 'stat')
            if response:
                try:
                    # 提取版本信息
                    version = re.search(r'Zookeeper version: ([^\n]+)', response)
                    if version:
                        _t = f"[*] {ip}:{port} - Zookeeper版本: {version.group(1)}"
                        save_result(_t)
                        logger.info(_t)
                    
                    # 提取客户端连接数
                    connections = re.search(r'Connections: (\d+)', response)
                    if connections:
                        _t = f"[*] {ip}:{port} - 当前连接数: {connections.group(1)}"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
            
            # 检测点3: 获取配置信息
            response = send_command(ip, port, 'conf')
            if response:
                try:
                    # 提取关键配置
                    client_port = re.search(r'clientPort=(\d+)', response)
                    data_dir = re.search(r'dataDir=([^\n]+)', response)
                    if client_port:
                        _t = f"[*] {ip}:{port} - 客户端端口: {client_port.group(1)}"
                        save_result(_t)
                        logger.info(_t)
                    if data_dir:
                        _t = f"[*] {ip}:{port} - 数据目录: {data_dir.group(1)}"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
            
            # 检测点4: 获取客户端连接信息
            response = send_command(ip, port, 'cons')
            if response:
                try:
                    # 计算客户端连接数
                    clients = [line for line in response.split('\n') if line.strip()]
                    _t = f"[*] {ip}:{port} - 发现 {len(clients)} 个客户端连接"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 列出前5个客户端信息
                    for client in clients[:5]:
                        _t = f"[*] {ip}:{port} - 客户端: {client}"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
            
            # 检测点5: 获取环境信息
            response = send_command(ip, port, 'envi')
            if response:
                try:
                    # 提取Java环境信息
                    java_version = re.search(r'java.version=([^\n]+)', response)
                    if java_version:
                        _t = f"[*] {ip}:{port} - Java版本: {java_version.group(1)}"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
            
            # 检测点6: 获取watches信息
            response = send_command(ip, port, 'wchs')
            if response:
                try:
                    # 提取watches数量
                    watches = re.search(r'(\d+) connections watching (\d+) paths', response)
                    if watches:
                        _t = f"[*] {ip}:{port} - {watches.group(1)} 个连接正在监视 {watches.group(2)} 个路径"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
            
            return True
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
    parser.add_option("-p", "--port", dest="port", default="2181", help="端口(默认2181)")
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
        save_to_file("zookeeper_unauthorized.txt", "\n".join(result))

if __name__ == "__main__":
    main()




