#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import pymssql
import socket
import logging
import queue
from threading import Thread, Lock
from optparse import OptionParser

"""
MSSQL 弱口令检测工具

使用方法:
    单个目标:
        python brute_mssql.py -t 192.168.1.1 -u users.txt -P pass.txt
    批量检测:
        python brute_mssql.py -a ip.txt -u users.txt -P pass.txt
    指定端口:
        python brute_mssql.py -t 192.168.1.1 -p 1433 -u users.txt -P pass.txt
    显示详细信息:
        python brute_mssql.py -a ip.txt -u users.txt -P pass.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认1433)
    -u  指定用户名字典
    -P  指定密码字典
    -v  显示详细信息
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

def brute(ip, port, users, passwds):
    """
    检测MSSQL弱口令
    
    Args:
        ip: 目标IP
        port: 目标端口
        users: 用户名列表
        passwds: 密码列表
    """
    for u in users:
        for p in passwds:
            u = u.strip()
            p = p.strip()
            if not u or not p:  # 跳过空用户名或密码
                continue
                
            conn = None
            try:
                conn = pymssql.connect(
                    host=ip,
                    user=u,
                    password=p,
                    port=int(port),
                    database='master',
                    timeout=5,
                    charset="utf8"
                )
                if conn:
                    _t = f"[+] {ip}:{port} - 存在弱口令 {u}:{p}"
                    save_result(_t)
                    logger.info(_t)
                    return
            except pymssql.OperationalError as e:
                logger.debug(f"[-] {ip}:{port} - {u}:{p} - 认证失败")
            except Exception as e:
                logger.debug(f"[-] {ip}:{port} - {u}:{p} - {str(e)}")
            finally:
                if conn:
                    try:
                        conn.close()
                    except:
                        pass

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
    parser.add_option("-p", dest="port", default="1433", help="target port (default: 1433)")
    parser.add_option("-u", dest="user", help="user dictionary file")
    parser.add_option("-P", dest="passwd", help="password dictionary file")
    parser.add_option("-a", dest="hosts", help="target hosts file")
    parser.add_option("-v", dest="verbose", action="store_true", help="verbose output")
    options, args = parser.parse_args()

    if options.verbose:
        logger.setLevel(logging.DEBUG)

    # 检查必要参数
    if not options.user:
        logger.error("[!] 请使用 -u 参数指定用户名字典")
        return
    if not options.passwd:
        logger.error("[!] 请使用 -P 参数指定密码字典")
        return

    # 读取字典文件
    users = read_targets(options.user)
    if not users:
        return
    passwds = read_targets(options.passwd)
    if not passwds:
        return

    logger.info(f"[*] 加载用户名字典: {len(users)} 个")
    logger.info(f"[*] 加载密码字典: {len(passwds)} 个")

    port = options.port
    threadnum = 50

    try:
        if options.host:
            logger.info(f"[*] 开始检测单个目标: {options.host}")
            brute(options.host, port, users, passwds)
        elif options.hosts:
            logger.info("[*] 开始批量检测")
            # 1. 读取目标文件
            tmp_list = read_targets(options.hosts)
            if not tmp_list:
                return

            logger.info(f"[*] 读取到 {len(tmp_list)} 个目标")

            # 2. 端口扫描
            file_name = f"{port}_mssql.txt"
            logger.info("[*] 开始端口扫描")
            scan_tasks = [(scan, (ip, port, file_name)) for ip in tmp_list]
            run_threads(scan_tasks, threadnum)
            
            # 3. 弱口令检测
            last_list = read_targets(file_name)
            if last_list:
                logger.info(f"[*] 发现 {len(last_list)} 个开放端口")
                logger.info("[*] 开始弱口令检测")
                brute_tasks = [(brute, (ip, port, users, passwds)) for ip in last_list]
                run_threads(brute_tasks, threadnum)
        else:
            parser.print_help()
            return

        # 输出结果统计
        if result:
            logger.info(f"[*] 检测完成，发现 {len(result)} 个弱口令")
            print("\n漏洞详情:")
            for m in result:
                print(m)
        else:
            logger.info("[*] 检测完成，未发现弱口令")

    except KeyboardInterrupt:
        logger.warning("\n[!] 扫描已终止")
    except Exception as e:
        logger.error(f"\n[!] Error: {str(e)}")

if __name__ == '__main__':
    main()

		

