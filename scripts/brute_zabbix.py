#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json
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
default_port = 10051

# 存储检测结果
result = []
result_lock = Lock()

def save_result(text):
    """安全地保存结果到全局result列表"""
    with result_lock:
        result.append(text)

def check_zabbix(ip, port):
    """检测Zabbix未授权访问"""
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, int(port)))
        
        # Zabbix请求数据
        request = {
            "request": "sender data",
            "data": []
        }
        
        # 发送请求
        sock.send(json.dumps(request).encode())
        
        # 接收响应
        response = sock.recv(1024).decode()
        
        # 检查响应
        if "failed: 0" in response or "success" in response.lower():
            _t = f"[+] {ip}:{port} - 存在Zabbix未授权访问"
            save_result(_t)
            logger.info(_t)
            
            # 尝试获取更多信息
            try:
                request = {
                    "request": "agent.version",
                }
                sock.send(json.dumps(request).encode())
                version_response = sock.recv(1024).decode()
                if version_response:
                    _t = f"[*] {ip}:{port} - Zabbix版本信息: {version_response}"
                    save_result(_t)
                    logger.info(_t)
            except:
                pass
            
            return True
            
    except socket.timeout:
        logger.debug(f"[-] {ip}:{port} - 连接超时")
    except ConnectionRefusedError:
        logger.debug(f"[-] {ip}:{port} - 连接被拒绝")
    except Exception as e:
        logger.debug(f"[-] {ip}:{port} - 检测出错: {str(e)}")
    finally:
        try:
            sock.close()
        except:
            pass
    
    return False

def brute(ip, port=None):
    """主检测函数"""
    global result
    result = []  # 清空上次的检测结果
    
    # 使用传入的端口或默认端口
    port = port or default_port
    
    try:
        if check_zabbix(ip, port):
            return
        
        _t = f"[-] {ip}:{port} - 未发现Zabbix未授权访问"
        save_result(_t)
        logger.info(_t)
        
    except KeyboardInterrupt:
        save_result("[*] 用户中断检测")
    except Exception as e:
        save_result(f"[*] 检测过程出错: {str(e)}")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} target [port]")
        sys.exit(1)
    
    target = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else None
    
    brute(target, port)
    
    for line in result:
        print(line) 