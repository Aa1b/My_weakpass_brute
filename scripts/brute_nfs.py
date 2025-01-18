#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import socket
import logging
import queue
import subprocess
from threading import Thread, Lock
from optparse import OptionParser

"""
NFS 未授权访问检测工具

使用方法:
    单个目标:
        python brute_nfs.py -t 192.168.1.1
    批量检测:
        python brute_nfs.py -a ip.txt
    指定端口:
        python brute_nfs.py -t 192.168.1.1 -p 2049
    显示详细信息:
        python brute_nfs.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认2049)
    -v  显示详细信息

支持检测的端口:
    - 2049: NFS默认端口
    - 20048: NFS mountd默认端口
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
    检测NFS未授权访问
    
    Args:
        ip: 目标IP
        port: 目标端口
    """
    try:
        # 使用showmount命令检查NFS共享
        cmd = f"showmount -e {ip}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            _t = f"[+] {ip}:{port} - 存在NFS未授权访问"
            save_result(_t)
            logger.info(_t)
            
            # 解析共享目录列表
            shares = []
            for line in stdout.decode().split('\n'):
                if line.startswith('Export list for'):
                    continue
                if line.strip():
                    share = line.split()[0]
                    shares.append(share)
            
            if shares:
                _t = f"[+] {ip}:{port} - 发现 {len(shares)} 个共享目录"
                save_result(_t)
                logger.info(_t)
                
                # 显示每个共享目录
                for share in shares:
                    _t = f"[+] {ip}:{port} - 共享目录: {share}"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 尝试检查目录权限
                    try:
                        # 创建临时挂载点
                        mount_point = "/tmp/nfs_test"
                        subprocess.run(f"mkdir -p {mount_point}", shell=True, check=True)
                        
                        # 尝试挂载
                        cmd = f"mount -t nfs {ip}:{share} {mount_point}"
                        process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        
                        if process.returncode == 0:
                            _t = f"[+] {ip}:{port} - 目录 {share} 可以被挂载"
                            save_result(_t)
                            logger.info(_t)
                            
                            # 检查读写权限
                            cmd = f"touch {mount_point}/test_write_permission"
                            process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            if process.returncode == 0:
                                _t = f"[+] {ip}:{port} - 目录 {share} 具有写入权限"
                                save_result(_t)
                                logger.info(_t)
                                # 清理测试文件
                                subprocess.run(f"rm {mount_point}/test_write_permission", shell=True)
                            
                            # 卸载目录
                            subprocess.run(f"umount {mount_point}", shell=True)
                    except:
                        pass
                    finally:
                        # 清理临时挂载点
                        subprocess.run(f"rm -rf {mount_point}", shell=True)
            
            return True
            
    except subprocess.SubprocessError as e:
        logger.debug(f"[-] {ip}:{port} - 命令执行失败: {str(e)}")
    except Exception as e:
        logger.debug(f"[-] {ip}:{port} - {str(e)}")
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
    parser.add_option("-p", dest="port", default="2049", help="target port (default: 2049)")
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
            file_name = f"{port}_nfs.txt"
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