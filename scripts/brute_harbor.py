#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
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

def check_harbor(ip, port):
    """检测Harbor未授权访问"""
    try:
        # 检查API访问
        url = f"http://{ip}:{port}/api/v2.0/projects"
        response = requests.get(url, timeout=5, verify=False)
        
        if response.status_code == 200:
            _t = f"[+] {ip}:{port} - 存在Harbor未授权访问"
            save_result(_t)
            logger.info(_t)
            
            # 获取项目列表
            try:
                projects = response.json()
                if projects:
                    _t = f"[*] {ip}:{port} - 发现 {len(projects)} 个项目"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 显示前5个项目的信息
                    for project in projects[:5]:
                        _t = f"[*] {ip}:{port} - 项目名称: {project.get('name', 'unknown')}, ID: {project.get('project_id', 'unknown')}"
                        save_result(_t)
                        logger.info(_t)
            except:
                pass
            
            # 获取系统信息
            try:
                sys_info_url = f"http://{ip}:{port}/api/v2.0/systeminfo"
                sys_response = requests.get(sys_info_url, timeout=5, verify=False)
                if sys_response.status_code == 200:
                    sys_info = sys_response.json()
                    _t = f"[*] {ip}:{port} - Harbor版本: {sys_info.get('harbor_version', 'unknown')}"
                    save_result(_t)
                    logger.info(_t)
            except:
                pass
            
            return True
            
    except requests.exceptions.RequestException as e:
        logger.debug(f"[-] {ip}:{port} - 连接失败: {str(e)}")
    except Exception as e:
        logger.debug(f"[-] {ip}:{port} - 检测出错: {str(e)}")
    
    return False

def brute(ip, port=None):
    """主检测函数"""
    global result
    result = []  # 清空上次的检测结果
    
    # 使用传入的端口或默认端口
    port = port or default_port
    
    try:
        if check_harbor(ip, port):
            return
        
        _t = f"[-] {ip}:{port} - 未发现Harbor未授权访问"
        save_result(_t)
        logger.info(_t)
        
    except KeyboardInterrupt:
        save_result("[*] 用户中断检测")
    except Exception as e:
        save_result(f"[*] 检测过程出错: {str(e)}")

if __name__ == '__main__':
    import sys
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} target [port]")
        sys.exit(1)
    
    target = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else None
    
    brute(target, port)
    
    for line in result:
        print(line) 