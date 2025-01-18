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
default_port = 8500

# 存储检测结果
result = []
result_lock = Lock()

def save_result(text):
    """安全地保存结果到全局result列表"""
    with result_lock:
        result.append(text)

def check_consul(ip, port):
    """检测Consul未授权访问"""
    try:
        # 检查Consul API
        endpoints = [
            '/v1/agent/members',  # 集群成员
            '/v1/agent/services',  # 服务列表
            '/v1/agent/checks',  # 健康检查
            '/v1/kv',  # Key/Value存储
            '/v1/catalog/services',  # 目录服务
            '/v1/catalog/nodes',  # 节点列表
            '/v1/acl/tokens'  # ACL令牌
        ]
        
        vulnerable = False
        
        # 首先检查版本信息
        version_url = f"http://{ip}:{port}/v1/agent/self"
        try:
            response = requests.get(version_url, timeout=5, verify=False)
            if response.status_code == 200:
                _t = f"[+] {ip}:{port} - 存在Consul未授权访问"
                save_result(_t)
                logger.info(_t)
                vulnerable = True
                
                # 获取Consul版本和配置信息
                try:
                    self_data = response.json()
                    if 'Config' in self_data:
                        config = self_data['Config']
                        if 'Version' in config:
                            _t = f"[*] {ip}:{port} - Consul版本: {config['Version']}"
                            save_result(_t)
                            logger.info(_t)
                        if 'Datacenter' in config:
                            _t = f"[*] {ip}:{port} - 数据中心: {config['Datacenter']}"
                            save_result(_t)
                            logger.info(_t)
                        if 'NodeName' in config:
                            _t = f"[*] {ip}:{port} - 节点名称: {config['NodeName']}"
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
                        if endpoint == '/v1/agent/members':
                            if isinstance(data, list):
                                _t = f"[*] {ip}:{port} - 发现 {len(data)} 个集群成员"
                                save_result(_t)
                                logger.info(_t)
                                # 显示前3个成员信息
                                for member in data[:3]:
                                    _t = f"[*] {ip}:{port} - 成员: {member.get('Name', 'unknown')} ({member.get('Addr', 'unknown')})"
                                    save_result(_t)
                                    logger.info(_t)
                        elif endpoint == '/v1/agent/services':
                            if isinstance(data, dict):
                                _t = f"[*] {ip}:{port} - 发现 {len(data)} 个服务"
                                save_result(_t)
                                logger.info(_t)
                        elif endpoint == '/v1/kv':
                            if isinstance(data, list):
                                _t = f"[*] {ip}:{port} - 发现 {len(data)} 个KV键值对"
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
        if check_consul(ip, port):
            return
        
        _t = f"[-] {ip}:{port} - 未发现Consul未授权访问"
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