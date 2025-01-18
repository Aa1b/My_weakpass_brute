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
default_port = 9090

# 存储检测结果
result = []
result_lock = Lock()

def save_result(text):
    """安全地保存结果到全局result列表"""
    with result_lock:
        result.append(text)

def check_prometheus(ip, port):
    """检测Prometheus未授权访问"""
    try:
        # 检查Prometheus API
        endpoints = [
            '/-/healthy',  # 健康检查
            '/api/v1/status/config',  # 配置状态
            '/api/v1/status/flags',  # 运行时标志
            '/api/v1/status/runtimeinfo',  # 运行时信息
            '/api/v1/status/buildinfo',  # 构建信息
            '/api/v1/targets',  # 监控目标
            '/api/v1/rules',  # 告警规则
            '/api/v1/alerts',  # 当前告警
            '/api/v1/query?query=up',  # 基本查询
            '/graph'  # Web界面
        ]
        
        vulnerable = False
        
        # 首先检查构建信息
        build_url = f"http://{ip}:{port}/api/v1/status/buildinfo"
        try:
            response = requests.get(build_url, timeout=5, verify=False)
            if response.status_code == 200:
                _t = f"[+] {ip}:{port} - 存在Prometheus未授权访问"
                save_result(_t)
                logger.info(_t)
                vulnerable = True
                
                # 获取Prometheus版本信息
                try:
                    build_data = response.json()
                    if 'data' in build_data:
                        data = build_data['data']
                        if 'version' in data:
                            _t = f"[*] {ip}:{port} - Prometheus版本: {data['version']}"
                            save_result(_t)
                            logger.info(_t)
                        if 'goVersion' in data:
                            _t = f"[*] {ip}:{port} - Go版本: {data['goVersion']}"
                            save_result(_t)
                            logger.info(_t)
                except:
                    pass
        except:
            pass
        
        # 检查其他端点
        for endpoint in endpoints:
            if endpoint == '/api/v1/status/buildinfo':  # 已经检查过了
                continue
                
            url = f"http://{ip}:{port}{endpoint}"
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    vulnerable = True
                    try:
                        if endpoint == '/api/v1/targets':
                            data = response.json()
                            if 'data' in data and 'activeTargets' in data['data']:
                                targets = data['data']['activeTargets']
                                _t = f"[*] {ip}:{port} - 发现 {len(targets)} 个监控目标"
                                save_result(_t)
                                logger.info(_t)
                                # 显示前3个目标信息
                                for target in targets[:3]:
                                    if 'labels' in target and '__address__' in target['labels']:
                                        _t = f"[*] {ip}:{port} - 监控目标: {target['labels']['__address__']} ({target.get('health', 'unknown')})"
                                        save_result(_t)
                                        logger.info(_t)
                        elif endpoint == '/api/v1/rules':
                            data = response.json()
                            if 'data' in data and 'groups' in data['data']:
                                rules = []
                                for group in data['data']['groups']:
                                    if 'rules' in group:
                                        rules.extend(group['rules'])
                                _t = f"[*] {ip}:{port} - 发现 {len(rules)} 条规则"
                                save_result(_t)
                                logger.info(_t)
                        elif endpoint == '/api/v1/alerts':
                            data = response.json()
                            if 'data' in data and 'alerts' in data['data']:
                                alerts = data['data']['alerts']
                                _t = f"[*] {ip}:{port} - 发现 {len(alerts)} 个活跃告警"
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
        if check_prometheus(ip, port):
            return
        
        _t = f"[-] {ip}:{port} - 未发现Prometheus未授权访问"
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