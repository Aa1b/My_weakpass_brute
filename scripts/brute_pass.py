#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import threading
import queue
import logging
from threading import Lock

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 定义默认端口
default_port = 80

# 存储检测结果
result = []
result_lock = Lock()

def save_result(text):
    """安全地保存结果到全局result列表"""
    with result_lock:
        result.append(text)

class BruteThread(threading.Thread):
    def __init__(self, target, port, task_queue, success_word="", failure_word=""):
        threading.Thread.__init__(self)
        self.target = target
        self.port = port
        self.task_queue = task_queue
        self.success_word = success_word
        self.failure_word = failure_word
        self.daemon = True
    
    def run(self):
        while True:
            try:
                username, password = self.task_queue.get_nowait()
                self.check_password(username, password)
            except queue.Empty:
                break
            except Exception as e:
                logger.debug(f"检测出错: {str(e)}")
            finally:
                self.task_queue.task_done()
    
    def check_password(self, username, password):
        """检测单个用户名密码组合"""
        try:
            url = f"http://{self.target}:{self.port}"
            data = {
                "username": username,
                "password": password
            }
            
            response = requests.post(url, data=data, timeout=5)
            
            # 根据响应判断是否成功
            if self.success_word and self.success_word in response.text:
                _t = f"[+] {self.target}:{self.port} - 发现弱口令 - {username}:{password}"
                save_result(_t)
                logger.info(_t)
            elif self.failure_word and self.failure_word not in response.text:
                _t = f"[+] {self.target}:{self.port} - 可能存在弱口令 - {username}:{password}"
                save_result(_t)
                logger.info(_t)
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"[-] {self.target}:{self.port} - 连接失败: {str(e)}")
        except Exception as e:
            logger.debug(f"[-] {self.target}:{self.port} - 检测出错: {str(e)}")

def brute(target, port, usernames=None, passwords=None, thread_num=10, success_word="", failure_word=""):
    """
    主检测函数
    
    Args:
        target: 目标IP
        port: 目标端口
        usernames: 用户名列表
        passwords: 密码列表
        thread_num: 线程数
        success_word: 登录成功的特征字符串
        failure_word: 登录失败的特征字符串
    """
    global result
    result = []  # 清空上次的检测结果
    
    # 使用默认用户名密码列表
    if not usernames:
        usernames = ["admin"]
    if not passwords:
        passwords = ["admin", "password", "123456"]
    
    # 创建任务队列
    task_queue = queue.Queue()
    
    # 生成所有用户名密码组合
    for username in usernames:
        for password in passwords:
            task_queue.put((username, password))
    
    # 创建线程池
    threads = []
    for _ in range(min(thread_num, task_queue.qsize())):
        t = BruteThread(target, port, task_queue, success_word, failure_word)
        threads.append(t)
        t.start()
    
    # 等待所有线程完成
    for t in threads:
        t.join()
    
    # 如果没有发现弱口令，添加结果
    if not result:
        _t = f"[-] {target}:{port} - 未发现弱口令"
        save_result(_t)
        logger.info(_t)

if __name__ == '__main__':
    # 命令行调用示例
    target = "127.0.0.1"
    port = "80"
    usernames = ["admin"]
    passwords = ["admin", "123456"]
    brute(target, port, usernames, passwords)