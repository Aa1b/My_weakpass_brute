#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import socket
import logging
from threading import Thread
from optparse import OptionParser

"""
[服务名] 未授权访问/弱口令检测工具

使用方法:
    单个目标:
        python script.py -t 192.168.1.1
    批量检测:
        python script.py -a ip.txt
    指定端口:
        python script.py -t 192.168.1.1 -p [PORT]
    显示详细信息:
        python script.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认[PORT])
    -v  显示详细信息
"""

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def brute(ip, port):
    """
    检测服务未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        # 具体的检测逻辑
        pass
    except Exception as e:
        logger.debug(f"[-] {ip}:{port} - {str(e)}")

def run(func, threadnum, ips, port, filename=None):
    """
    运行多线程任务
    
    Args:
        func: 要执行的函数
        threadnum: 线程数
        ips: IP列表
        port: 端口
        filename: 输出文件名
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
        filename: 输出文件名
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        try:
            res = s.connect_ex((ip, int(port)))
            if res == 0:
                with open(filename, 'a+') as f:
                    f.write(f"{ip}\n")
                logger.debug(f"[*] {ip}:{port} - 端口开放")
        except Exception as e:
            logger.debug(f"[-] {ip}:{port} - {str(e)}")

def main():
    """主函数"""
    usage = "Usage: python %prog [options] args"
    parser = OptionParser(usage, version="%prog 1.0")
    parser.add_option("-t", dest="host", help="target host")
    parser.add_option("-p", dest="port", default="[PORT]", help="target port (default: [PORT])")
    parser.add_option("-a", dest="hosts", help="target hosts file")
    parser.add_option("-v", dest="verbose", action="store_true", help="verbose output")
    options, args = parser.parse_args()

    if options.verbose:
        logger.setLevel(logging.DEBUG)

    port = options.port
    global result
    result = []
    threadnum = 50

    try:
        if options.host:
            logger.info(f"[*] 开始检测单个目标: {options.host}")
            brute(options.host, port)
        elif options.hosts:
            logger.info("[*] 开始批量检测")
            # 1. 读取目标文件
            with open(options.hosts, 'r') as f:
                tmp_list = [line.strip() for line in f if line.strip()]
            
            if not tmp_list:
                logger.error("[!] 目标文件为空")
                return

            logger.info(f"[*] 读取到 {len(tmp_list)} 个目标")

            # 2. 端口扫描
            file_name = f"{port}_[service].txt"
            logger.info("[*] 开始端口扫描")
            run(scan, threadnum, tmp_list, port, file_name)
            
            # 3. 漏洞检测
            try:
                with open(file_name, 'r') as f:
                    last_list = [line.strip() for line in f if line.strip()]
                
                if last_list:
                    logger.info(f"[*] 发现 {len(last_list)} 个开放端口")
                    logger.info("[*] 开始漏洞检测")
                    run(brute, threadnum, last_list, port)
            except Exception as e:
                logger.error(f"[!] 读取扫描结果失败: {str(e)}")
        else:
            parser.print_help()
            return

        # 输出结果统计
        if result:
            logger.info(f"[*] 检测完成，发现 {len(result)} 个未授权访问")
            print("\n漏洞详情:")
            for m in result:
                print(m)
        else:
            logger.info("[*] 检测完成，未发现未授权访问")

    except KeyboardInterrupt:
        logger.warning("\n[!] 扫描已终止")
    except Exception as e:
        logger.error(f"\n[!] Error: {str(e)}")

if __name__ == '__main__':
    main()