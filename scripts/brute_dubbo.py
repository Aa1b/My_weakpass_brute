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
Dubbo 未授权访问检测工具

使用方法:
    单个目标:
        python brute_dubbo.py -t 192.168.1.1
    批量检测:
        python brute_dubbo.py -a ip.txt
    指定端口:
        python brute_dubbo.py -t 192.168.1.1 -p 20880
    显示详细信息:
        python brute_dubbo.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认20880)
    -v  显示详细信息

支持检测的端口:
    - 20880: Dubbo默认端口
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

def send_telnet_command(tn, command):
    """
    发送telnet命令并获取响应
    
    Args:
        tn: telnet连接对象
        command: 要发送的命令
    Returns:
        str: 命令响应
    """
    try:
        tn.write(command.encode() + b'\n')
        return tn.read_until(b'dubbo>', timeout=5).decode('utf-8', errors='ignore')
    except:
        return ''

def brute(ip, port):
    """
    检测Dubbo未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        # 检测点1: 尝试建立telnet连接
        tn = telnetlib.Telnet(ip, int(port), timeout=5)
        
        # 等待Dubbo提示符
        welcome = tn.read_until(b'dubbo>', timeout=5).decode('utf-8', errors='ignore')
        if 'dubbo>' in welcome:
            _t = f"[+] {ip}:{port} - 存在Dubbo未授权访问"
            save_result(_t)
            logger.info(_t)
            
            # 检测点2: 获取服务列表
            response = send_telnet_command(tn, 'ls')
            if response:
                services = [line.strip() for line in response.split('\n') if line.strip() and 'dubbo>' not in line]
                if services:
                    _t = f"[*] {ip}:{port} - 发现 {len(services)} 个服务"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 列出前5个服务
                    for service in services[:5]:
                        _t = f"[*] {ip}:{port} - 服务: {service}"
                        save_result(_t)
                        logger.info(_t)
            
            # 检测点3: 获取服务状态
            response = send_telnet_command(tn, 'status')
            if response and 'OK' in response:
                _t = f"[*] {ip}:{port} - 服务状态正常"
                save_result(_t)
                logger.info(_t)
            
            # 检测点4: 获取系统信息
            response = send_telnet_command(tn, 'sysinfo')
            if response:
                # 提取JVM信息
                if 'java.version' in response:
                    java_version = re.search(r'java.version: ([^\r\n]+)', response)
                    if java_version:
                        _t = f"[*] {ip}:{port} - Java版本: {java_version.group(1)}"
                        save_result(_t)
                        logger.info(_t)
            
            # 检测点5: 获取配置信息
            response = send_telnet_command(tn, 'dump')
            if response:
                _t = f"[*] {ip}:{port} - 可获取配置信息"
                save_result(_t)
                logger.info(_t)
            
            # 关闭连接
            try:
                tn.close()
            except:
                pass
            
            return True
    except socket.timeout:
        logger.debug(f"[-] {ip}:{port} - 连接超时")
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
    parser.add_option("-p", "--port", dest="port", default="20880", help="端口(默认20880)")
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
        save_to_file("dubbo_unauthorized.txt", "\n".join(result))

if __name__ == "__main__":
    main()