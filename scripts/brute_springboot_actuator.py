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
default_port = 8080

# 存储检测结果
result = []
result_lock = Lock()

# SpringBoot Actuator端点列表
ACTUATOR_ENDPOINTS = [
    'env',
    'health',
    'info',
    'metrics',
    'mappings',
    'dump',
    'trace',
    'logfile',
    'shutdown',
    'beans',
    'configprops',
    'autoconfig',
    'heapdump',
    'threaddump',
    'jolokia'
]

def save_result(text):
    """安全地保存结果到全局result列表"""
    with result_lock:
        result.append(text)

def check_actuator(ip, port):
    """检测SpringBoot Actuator未授权访问"""
    try:
        # 检查常见的Actuator路径
        base_paths = [
            '',  # 直接访问根路径
            '/actuator',  # Spring Boot 2.x
            '/admin'  # 某些自定义路径
        ]
        
        vulnerable = False
        
        for base_path in base_paths:
            # 先检查actuator主入口
            url = f"http://{ip}:{port}{base_path}/actuator"
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    _t = f"[+] {ip}:{port} - 发现SpringBoot Actuator入口: {url}"
                    save_result(_t)
                    logger.info(_t)
                    vulnerable = True
                    
                    # 尝试解析可用端点
                    try:
                        endpoints = response.json().get('_links', {})
                        if endpoints:
                            _t = f"[*] {ip}:{port} - 发现以下可用端点:"
                            save_result(_t)
                            logger.info(_t)
                            for endpoint in endpoints:
                                _t = f"[*] {ip}:{port} - {endpoint}"
                                save_result(_t)
                                logger.info(_t)
                    except:
                        pass
            except:
                pass
            
            # 检查各个端点
            for endpoint in ACTUATOR_ENDPOINTS:
                # 检查不同的URL模式
                urls = [
                    f"http://{ip}:{port}{base_path}/{endpoint}",  # 直接访问
                    f"http://{ip}:{port}{base_path}/actuator/{endpoint}",  # Spring Boot 2.x
                    f"http://{ip}:{port}{base_path}/admin/{endpoint}"  # 自定义路径
                ]
                
                for url in urls:
                    try:
                        response = requests.get(url, timeout=5, verify=False)
                        if response.status_code == 200:
                            _t = f"[+] {ip}:{port} - 发现未授权访问端点: {url}"
                            save_result(_t)
                            logger.info(_t)
                            vulnerable = True
                            
                            # 对特定端点获取更多信息
                            if endpoint == 'env':
                                try:
                                    env_data = response.json()
                                    _t = f"[*] {ip}:{port} - 环境信息: {str(env_data)[:200]}..."  # 只显示前200个字符
                                    save_result(_t)
                                    logger.info(_t)
                                except:
                                    pass
                            elif endpoint == 'info':
                                try:
                                    info_data = response.json()
                                    _t = f"[*] {ip}:{port} - 应用信息: {str(info_data)}"
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
        if check_actuator(ip, port):
            return
        
        _t = f"[-] {ip}:{port} - 未发现SpringBoot Actuator未授权访问"
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