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
default_port = 8001

# 存储检测结果
result = []
result_lock = Lock()

def save_result(text):
    """安全地保存结果到全局result列表"""
    with result_lock:
        result.append(text)

def check_kong(ip, port):
    """检测Kong API Gateway未授权访问"""
    try:
        # 检查Kong Admin API
        endpoints = [
            '/status',  # 状态信息
            '/services',  # 服务列表
            '/routes',  # 路由列表
            '/consumers',  # 消费者列表
            '/plugins',  # 插件列表
            '/upstreams',  # 上游服务列表
            '/certificates',  # 证书列表
            '/snis'  # SNI列表
        ]
        
        vulnerable = False
        
        # 首先检查状态端点
        status_url = f"http://{ip}:{port}/status"
        try:
            response = requests.get(status_url, timeout=5, verify=False)
            if response.status_code == 200:
                _t = f"[+] {ip}:{port} - 存在Kong API Gateway未授权访问"
                save_result(_t)
                logger.info(_t)
                vulnerable = True
                
                # 获取Kong版本和状态信息
                try:
                    status_data = response.json()
                    if 'server' in status_data:
                        _t = f"[*] {ip}:{port} - Kong版本: {status_data['server']['version']}"
                        save_result(_t)
                        logger.info(_t)
                        
                        # 显示数据库状态
                        if 'database' in status_data:
                            _t = f"[*] {ip}:{port} - 数据库状态: {status_data['database']['reachable']}"
                            save_result(_t)
                            logger.info(_t)
                except:
                    pass
        except:
            pass
        
        # 检查其他端点
        for endpoint in endpoints:
            if endpoint == '/status':  # 已经检查过了
                continue
                
            url = f"http://{ip}:{port}{endpoint}"
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    vulnerable = True
                    try:
                        data = response.json()
                        if isinstance(data, dict) and 'data' in data:
                            items = data['data']
                            if items:
                                _t = f"[*] {ip}:{port} - {endpoint[1:].title()}: 发现 {len(items)} 个配置项"
                                save_result(_t)
                                logger.info(_t)
                                
                                # 显示前3个配置项的基本信息
                                for item in items[:3]:
                                    if 'name' in item:
                                        _t = f"[*] {ip}:{port} - {endpoint[1:].title()}配置: {item['name']}"
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
        if check_kong(ip, port):
            return
        
        _t = f"[-] {ip}:{port} - 未发现Kong API Gateway未授权访问"
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