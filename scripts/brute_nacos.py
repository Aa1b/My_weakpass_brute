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
default_port = 8848

# 存储检测结果
result = []
result_lock = Lock()

def save_result(text):
    """安全地保存结果到全局result列表"""
    with result_lock:
        result.append(text)

def check_nacos(ip, port):
    """检测Nacos未授权访问"""
    try:
        # 检查Nacos API
        endpoints = [
            '/nacos/v1/auth/users',  # 用户列表
            '/nacos/v1/cs/configs',  # 配置列表
            '/nacos/v1/ns/service/list',  # 服务列表
            '/nacos/v1/ns/instance/list',  # 实例列表
            '/nacos/v1/ns/namespace'  # 命名空间列表
        ]
        
        vulnerable = False
        
        # 首先检查版本信息
        version_url = f"http://{ip}:{port}/nacos/v1/console/server/state"
        try:
            response = requests.get(version_url, timeout=5, verify=False)
            if response.status_code == 200:
                _t = f"[+] {ip}:{port} - 存在Nacos未授权访问"
                save_result(_t)
                logger.info(_t)
                vulnerable = True
                
                # 获取Nacos版本和状态信息
                try:
                    state_data = response.json()
                    if 'version' in state_data:
                        _t = f"[*] {ip}:{port} - Nacos版本: {state_data['version']}"
                        save_result(_t)
                        logger.info(_t)
                    if 'standalone' in state_data:
                        _t = f"[*] {ip}:{port} - 部署模式: {'单机' if state_data['standalone'] else '集群'}"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
        except:
            pass
        
        # 检查其他端点
        for endpoint in endpoints:
            url = f"http://{ip}:{port}{endpoint}"
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    vulnerable = True
                    try:
                        data = response.json()
                        if endpoint == '/nacos/v1/auth/users':
                            if isinstance(data, list):
                                _t = f"[*] {ip}:{port} - 发现 {len(data)} 个用户"
                                save_result(_t)
                                logger.info(_t)
                        elif endpoint == '/nacos/v1/cs/configs':
                            if isinstance(data, dict) and 'pageItems' in data:
                                _t = f"[*] {ip}:{port} - 发现 {len(data['pageItems'])} 个配置项"
                                save_result(_t)
                                logger.info(_t)
                        elif endpoint == '/nacos/v1/ns/service/list':
                            if isinstance(data, dict) and 'count' in data:
                                _t = f"[*] {ip}:{port} - 发现 {data['count']} 个服务"
                                save_result(_t)
                                logger.info(_t)
                    except:
                        pass
            except:
                continue
        
        return vulnerable
            
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
        if check_nacos(ip, port):
            return
        
        _t = f"[-] {ip}:{port} - 未发现Nacos未授权访问"
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