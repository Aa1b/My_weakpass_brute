#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import socket
import logging
import queue
from threading import Thread, Lock
from optparse import OptionParser

"""
VNC 未授权访问检测工具

使用方法:
    单个目标:
        python brute_vnc.py -t 192.168.1.1
    批量检测:
        python brute_vnc.py -a ip.txt
    指定端口:
        python brute_vnc.py -t 192.168.1.1 -p 5900
    显示详细信息:
        python brute_vnc.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认5900)
    -v  显示详细信息

支持检测的端口:
    - 5900: VNC默认端口
    - 5901-5903: 常用VNC端口
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
    检测VNC未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        # 创建TCP连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, int(port)))
        
        # 接收VNC服务器版本信息
        banner = sock.recv(1024)
        if banner.startswith(b'RFB '):
            version = banner.decode('utf-8').strip()
            _t = f"[+] {ip}:{port} - 存在VNC服务 ({version})"
            save_result(_t)
            logger.info(_t)
            
            # 发送客户端版本
            sock.send(b'RFB 003.008\n')
            
            # 接收安全类型
            security_types = sock.recv(1024)
            if security_types:
                # 检查是否支持无密码认证 (security type 1)
                if b'\x01' in security_types:
                    _t = f"[+] {ip}:{port} - 支持无密码认证"
                    save_result(_t)
                    logger.info(_t)
                    return True
                else:
                    logger.debug(f"[-] {ip}:{port} - 需要密码认证")
    except socket.timeout:
        logger.debug(f"[-] {ip}:{port} - 连接超时")
    except Exception as e:
        logger.debug(f"[-] {ip}:{port} - {str(e)}")
    finally:
        try:
            sock.close()
        except:
            pass
    return False

def worker():
    """
    工作线程函数
    """
    while True:
        try:
            task = task_queue.get_nowait()
            if task is None:
                break
                
            func, args = task
            func(*args)
        except queue.Empty:
            break
        except Exception as e:
            logger.debug(f"[-] 线程执行错误: {str(e)}")
        finally:
            task_queue.task_done()

def run_threads(tasks, threadnum):
    """
    运行多线程任务
    
    Args:
        tasks: 任务列表，每个任务是(func, args)的元组
        threadnum: 线程数
    """
    # 将任务加入队列
    for task in tasks:
        task_queue.put(task)
    
    # 创建工作线程
    threads = []
    for _ in range(min(threadnum, len(tasks))):
        t = Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    
    # 等待所有任务完成
    task_queue.join()
    
    # 停止工作线程
    for _ in range(len(threads)):
        task_queue.put(None)
    for t in threads:
        t.join()

def scan(ip, port, filename):
    """
    扫描端口是否开放
    
    Args:
        ip: 目标IP
        port: 目标端口
        filename: 输出文件名
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        res = s.connect_ex((ip, int(port)))
        if res == 0:
            save_to_file(filename, ip)
            logger.debug(f"[*] {ip}:{port} - 端口开放")
    except Exception as e:
        logger.debug(f"[-] {ip}:{port} - {str(e)}")
    finally:
        try:
            s.close()
        except:
            pass

def read_targets(filename):
    """
    读取目标文件
    
    Args:
        filename: 文件名
    Returns:
        list: 目标列表
    """
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"[!] 读取文件失败 {filename}: {str(e)}")
        return []

def main():
    """主函数"""
    usage = "Usage: python %prog [options] args"
    parser = OptionParser(usage, version="%prog 1.0")
    parser.add_option("-t", dest="host", help="target host")
    parser.add_option("-p", dest="port", default="5900", help="target port (default: 5900)")
    parser.add_option("-a", dest="hosts", help="target hosts file")
    parser.add_option("-v", dest="verbose", action="store_true", help="verbose output")
    options, args = parser.parse_args()

    if options.verbose:
        logger.setLevel(logging.DEBUG)

    port = options.port
    threadnum = 50

    try:
        if options.host:
            logger.info(f"[*] 开始检测单个目标: {options.host}")
            brute(options.host, port)
        elif options.hosts:
            logger.info("[*] 开始批量检测")
            # 1. 读取目标文件
            tmp_list = read_targets(options.hosts)
            if not tmp_list:
                return

            logger.info(f"[*] 读取到 {len(tmp_list)} 个目标")

            # 2. 端口扫描
            file_name = f"{port}_vnc.txt"
            logger.info("[*] 开始端口扫描")
            scan_tasks = [(scan, (ip, port, file_name)) for ip in tmp_list]
            run_threads(scan_tasks, threadnum)
            
            # 3. 未授权访问检测
            last_list = read_targets(file_name)
            if last_list:
                logger.info(f"[*] 发现 {len(last_list)} 个开放端口")
                logger.info("[*] 开始未授权访问检测")
                brute_tasks = [(brute, (ip, port)) for ip in last_list]
                run_threads(brute_tasks, threadnum)
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