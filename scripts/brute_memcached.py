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
import subprocess
import time

"""
Memcached 未授权访问检测工具

使用方法:
    单个目标:
        python brute_memcached.py -t 192.168.1.1
    批量检测:
        python brute_memcached.py -a ip.txt
    指定端口:
        python brute_memcached.py -t 192.168.1.1 -p 11211
    显示详细信息:
        python brute_memcached.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认11211)
    -v  显示详细信息

支持检测的端口:
    - 11211: Memcached默认端口
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

def execute_command(cmd, timeout=5):
    """
    执行命令并获取输出
    
    Args:
        cmd: 要执行的命令
        timeout: 超时时间(秒)
    Returns:
        tuple: (stdout, stderr)
    """
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore')
    except subprocess.TimeoutExpired:
        process.kill()
        return None, "Command timed out"
    except Exception as e:
        return None, str(e)

def brute(ip, port):
    """
    检测Memcached未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        # 检测点1: 使用nc命令检查stats信息
        cmd = f"echo 'stats' | nc -vn {ip} {port} -w 3"
        stdout, stderr = execute_command(cmd)
        
        if stdout and ('STAT pid' in stdout or 'STAT version' in stdout):
            _t = f"[+] {ip}:{port} - 存在Memcached未授权访问"
            save_result(_t)
            logger.info(_t)
            
            # 检测点2: 获取版本信息
            try:
                version = re.search(r'STAT version ([^\r\n]+)', stdout)
                if version:
                    _t = f"[*] {ip}:{port} - Memcached版本: {version.group(1)}"
                    save_result(_t)
                    logger.info(_t)
            except:
                pass
            
            # 检测点3: 获取连接信息
            try:
                curr_connections = re.search(r'STAT curr_connections (\d+)', stdout)
                if curr_connections:
                    _t = f"[*] {ip}:{port} - 当前连接数: {curr_connections.group(1)}"
                    save_result(_t)
                    logger.info(_t)
            except:
                pass
            
            # 检测点4: 获取内存使用信息
            try:
                bytes_used = re.search(r'STAT bytes (\d+)', stdout)
                limit_maxbytes = re.search(r'STAT limit_maxbytes (\d+)', stdout)
                if bytes_used and limit_maxbytes:
                    used = int(bytes_used.group(1))
                    total = int(limit_maxbytes.group(1))
                    used_mb = used / (1024 * 1024)
                    total_mb = total / (1024 * 1024)
                    _t = f"[*] {ip}:{port} - 内存使用: {used_mb:.2f}MB / {total_mb:.2f}MB"
                    save_result(_t)
                    logger.info(_t)
            except:
                pass
            
            # 检测点5: 获取命中率信息
            try:
                get_hits = re.search(r'STAT get_hits (\d+)', stdout)
                get_misses = re.search(r'STAT get_misses (\d+)', stdout)
                if get_hits and get_misses:
                    hits = int(get_hits.group(1))
                    misses = int(get_misses.group(1))
                    total = hits + misses
                    if total > 0:
                        hit_rate = (hits / total) * 100
                        _t = f"[*] {ip}:{port} - 缓存命中率: {hit_rate:.2f}%"
                        save_result(_t)
                        logger.info(_t)
            except:
                pass
            
            # 检测点6: 获取存储项信息
            try:
                curr_items = re.search(r'STAT curr_items (\d+)', stdout)
                if curr_items:
                    _t = f"[*] {ip}:{port} - 当前存储项数: {curr_items.group(1)}"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 尝试获取前5个key
                    cmd = f"echo 'stats items' | nc -vn {ip} {port} -w 3"
                    stdout, stderr = execute_command(cmd)
                    if stdout and 'STAT items' in stdout:
                        # 提取所有slab ID
                        slab_ids = re.findall(r'STAT items:(\d+):', stdout)
                        if slab_ids:
                            for slab_id in slab_ids[:5]:  # 只检查前5个slab
                                cmd = f"echo 'stats cachedump {slab_id} 5' | nc -vn {ip} {port} -w 3"
                                stdout, stderr = execute_command(cmd)
                                if stdout and 'ITEM' in stdout:
                                    items = re.findall(r'ITEM ([^\s]+) \[(\d+) b', stdout)
                                    for item, size in items:
                                        _t = f"[*] {ip}:{port} - 键: {item}, 大小: {size}字节"
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
    parser.add_option("-p", "--port", dest="port", default="11211", help="端口(默认11211)")
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
        save_to_file("memcached_unauthorized.txt", "\n".join(result))

if __name__ == "__main__":
    main() 