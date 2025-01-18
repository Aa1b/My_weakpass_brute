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
default_port = 2379

# 存储检测结果
result = []
result_lock = Lock()

def save_result(text):
    """安全地保存结果到全局result列表"""
    with result_lock:
        result.append(text)

def check_etcd(ip, port):
    """检测Etcd未授权访问"""
    try:
        # 检查Etcd API
        endpoints = [
            '/version',  # 版本信息
            '/v2/keys',  # Key/Value存储
            '/v2/members',  # 集群成员
            '/v2/stats/self',  # 节点统计
            '/v2/stats/store',  # 存储统计
            '/v2/stats/leader',  # 领导者统计
            '/health'  # 健康状态
        ]
        
        vulnerable = False
        
        # 首先检查版本信息
        version_url = f"http://{ip}:{port}/version"
        try:
            response = requests.get(version_url, timeout=5, verify=False)
            if response.status_code == 200:
                _t = f"[+] {ip}:{port} - 存在Etcd未授权访问"
                save_result(_t)
                logger.info(_t)
                vulnerable = True
                
                # 获取Etcd版本信息
                try:
                    version_data = response.json()
                    if 'etcdserver' in version_data:
                        _t = f"[*] {ip}:{port} - Etcd版本: {version_data['etcdserver']}"
                        save_result(_t)
                        logger.info(_t)
                    if 'etcdcluster' in version_data:
                        _t = f"[*] {ip}:{port} - 集群版本: {version_data['etcdcluster']}"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
        except:
            pass
        
        # 检查其他端点
        for endpoint in endpoints:
            if endpoint == '/version':  # 已经检查过了
                continue
                
            url = f"http://{ip}:{port}{endpoint}"
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    vulnerable = True
                    try:
                        data = response.json()
                        if endpoint == '/v2/keys':
                            if 'node' in data and 'nodes' in data['node']:
                                nodes = data['node']['nodes']
                                _t = f"[*] {ip}:{port} - 发现 {len(nodes)} 个键值对"
                                save_result(_t)
                                logger.info(_t)
                                # 显示前3个键值对
                                for node in nodes[:3]:
                                    if 'key' in node:
                                        _t = f"[*] {ip}:{port} - 键: {node['key']}"
                                        save_result(_t)
                                        logger.info(_t)
                        elif endpoint == '/v2/members':
                            if 'members' in data:
                                members = data['members']
                                _t = f"[*] {ip}:{port} - 发现 {len(members)} 个集群成员"
                                save_result(_t)
                                logger.info(_t)
                                # 显示成员信息
                                for member in members:
                                    if 'name' in member:
                                        _t = f"[*] {ip}:{port} - 成员: {member['name']}"
                                        save_result(_t)
                                        logger.info(_t)
                        elif endpoint == '/v2/stats/store':
                            if 'getsSuccess' in data:
                                _t = f"[*] {ip}:{port} - 成功读取次数: {data['getsSuccess']}"
                                save_result(_t)
                                logger.info(_t)
                            if 'watchers' in data:
                                _t = f"[*] {ip}:{port} - 当前观察者数量: {data['watchers']}"
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
        if check_etcd(ip, port):
            return
        
        _t = f"[-] {ip}:{port} - 未发现Etcd未授权访问"
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