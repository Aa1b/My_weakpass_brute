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

"""
Cassandra 未授权访问检测工具

使用方法:
    单个目标:
        python brute_cassandra.py -t 192.168.1.1
    批量检测:
        python brute_cassandra.py -a ip.txt
    指定端口:
        python brute_cassandra.py -t 192.168.1.1 -p 9042
    显示详细信息:
        python brute_cassandra.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认9042)
    -v  显示详细信息

支持检测的端口:
    - 9042: Cassandra默认端口
    - 9160: Cassandra Thrift端口
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
    检测Cassandra未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        # 检测点1: 使用nodetool获取节点状态
        cmd = f"nodetool -h {ip} -p {port} status"
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8'
        )
        stdout, stderr = process.communicate(timeout=5)
        
        if process.returncode == 0 and "Datacenter" in stdout:
            _t = f"[+] {ip}:{port} - 存在Cassandra未授权访问"
            save_result(_t)
            logger.info(_t)
            
            # 解析节点信息
            nodes = len(re.findall(r'UN\s+', stdout))  # UN表示Up/Normal状态的节点
            if nodes > 0:
                _t = f"[*] {ip}:{port} - 发现 {nodes} 个活动节点"
                save_result(_t)
                logger.info(_t)
            
            # 检测点2: 获取集群信息
            cmd = f"nodetool -h {ip} -p {port} info"
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding='utf-8'
            )
            stdout, stderr = process.communicate(timeout=5)
            
            if process.returncode == 0:
                # 提取版本信息
                version = re.search(r'Cassandra version: ([^\n]+)', stdout)
                if version:
                    _t = f"[*] {ip}:{port} - Cassandra版本: {version.group(1)}"
                    save_result(_t)
                    logger.info(_t)
            
            # 检测点3: 获取keyspace列表
            cmd = f"echo 'DESCRIBE KEYSPACES;' | cqlsh {ip} {port}"
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding='utf-8'
            )
            stdout, stderr = process.communicate(timeout=5)
            
            if process.returncode == 0:
                keyspaces = [ks.strip() for ks in stdout.split() if ks.strip()]
                if keyspaces:
                    _t = f"[*] {ip}:{port} - 发现 {len(keyspaces)} 个keyspace"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 列出前5个keyspace
                    for ks in keyspaces[:5]:
                        _t = f"[*] {ip}:{port} - Keyspace: {ks}"
                        save_result(_t)
                        logger.info(_t)
            
            # 检测点4: 获取表信息
            for ks in keyspaces[:5]:  # 只检查前5个keyspace
                cmd = f"echo 'DESCRIBE TABLES;' | cqlsh {ip} {port} -k {ks}"
                process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    encoding='utf-8'
                )
                stdout, stderr = process.communicate(timeout=5)
                
                if process.returncode == 0:
                    tables = [t.strip() for t in stdout.split() if t.strip()]
                    if tables:
                        _t = f"[*] {ip}:{port} - Keyspace {ks} 包含 {len(tables)} 个表"
                        save_result(_t)
                        logger.info(_t)
            
            # 检测点5: 检查系统表访问权限
            cmd = f"echo 'SELECT * FROM system.local;' | cqlsh {ip} {port}"
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding='utf-8'
            )
            stdout, stderr = process.communicate(timeout=5)
            
            if process.returncode == 0:
                _t = f"[+] {ip}:{port} - 可访问系统表"
                save_result(_t)
                logger.info(_t)
            
            # 检测点6: 检查数据写入权限
            cmd = f"echo 'CREATE KEYSPACE IF NOT EXISTS test WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': 1}};' | cqlsh {ip} {port}"
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding='utf-8'
            )
            stdout, stderr = process.communicate(timeout=5)
            
            if process.returncode == 0:
                _t = f"[+] {ip}:{port} - 具有数据写入权限"
                save_result(_t)
                logger.info(_t)
                
                # 清理测试数据
                cmd = f"echo 'DROP KEYSPACE test;' | cqlsh {ip} {port}"
                subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            return True
    except subprocess.TimeoutExpired:
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
    parser.add_option("-p", "--port", dest="port", default="9042", help="端口(默认9042)")
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
        save_to_file("cassandra_unauthorized.txt", "\n".join(result))

if __name__ == "__main__":
    main() 