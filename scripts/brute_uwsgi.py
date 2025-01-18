#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import logging
from threading import Lock
import struct

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 定义默认端口
default_port = 8000

# 存储检测结果
result = []
result_lock = Lock()

def save_result(text):
    """安全地保存结果到全局result列表"""
    with result_lock:
        result.append(text)

def build_uwsgi_packet():
    """构建uWSGI数据包"""
    # uWSGI Packet Header
    packet = b'\x00'  # modifier1
    packet += struct.pack('<H', 0)  # datasize (placeholder)
    packet += b'\x00'  # modifier2
    
    # UWSGI vars
    vars_dict = {
        'REQUEST_METHOD': 'GET',
        'REQUEST_URI': '/',
        'PATH_INFO': '/',
        'QUERY_STRING': '',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'SERVER_NAME': 'localhost',
        'SERVER_PORT': '80',
        'REMOTE_ADDR': '127.0.0.1',
        'REMOTE_PORT': '12345',
        'UWSGI_FILE': 'test.py',
        'SCRIPT_NAME': ''
    }
    
    # Pack vars
    vars_payload = b''
    for key, val in vars_dict.items():
        key_bytes = key.encode('utf-8')
        val_bytes = val.encode('utf-8')
        vars_payload += struct.pack('<H', len(key_bytes))
        vars_payload += key_bytes
        vars_payload += struct.pack('<H', len(val_bytes))
        vars_payload += val_bytes
    
    # Update packet size
    packet = packet[:1] + struct.pack('<H', len(vars_payload)) + packet[3:]
    packet += vars_payload
    
    return packet

def check_uwsgi(ip, port):
    """检测uWSGI未授权访问"""
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, int(port)))
        
        # 发送uWSGI请求
        packet = build_uwsgi_packet()
        sock.send(packet)
        
        # 接收响应
        response = sock.recv(1024)
        
        # 检查响应
        if response and len(response) > 0:
            if b'uWSGI' in response or b'Python' in response or b'HTTP/' in response:
                _t = f"[+] {ip}:{port} - 存在uWSGI未授权访问"
                save_result(_t)
                logger.info(_t)
                
                # 尝试获取更多信息
                try:
                    if b'uWSGI Version:' in response:
                        version = response.split(b'uWSGI Version:')[1].split(b'\n')[0].strip().decode()
                        _t = f"[*] {ip}:{port} - uWSGI版本: {version}"
                        save_result(_t)
                        logger.info(_t)
                except:
                    pass
                
                try:
                    if b'Python Version:' in response:
                        py_version = response.split(b'Python Version:')[1].split(b'\n')[0].strip().decode()
                        _t = f"[*] {ip}:{port} - Python版本: {py_version}"
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
        if check_uwsgi(ip, port):
            return
        
        _t = f"[-] {ip}:{port} - 未发现uWSGI未授权访问"
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