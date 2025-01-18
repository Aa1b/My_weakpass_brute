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
default_port = 9000

# 存储检测结果
result = []
result_lock = Lock()

def save_result(text):
    """安全地保存结果到全局result列表"""
    with result_lock:
        result.append(text)

def pack_fastcgi_params(params):
    """打包FastCGI参数"""
    encoded = b''
    for key, value in params.items():
        key_len = len(key)
        value_len = len(value)
        
        if key_len < 128:
            encoded += bytes([key_len])
        else:
            encoded += struct.pack('>I', key_len | 0x80000000)
        
        if value_len < 128:
            encoded += bytes([value_len])
        else:
            encoded += struct.pack('>I', value_len | 0x80000000)
            
        encoded += key.encode() + value.encode()
    return encoded

def build_fastcgi_request():
    """构建FastCGI请求"""
    params = {
        'SCRIPT_FILENAME': '/tmp/test.php',
        'SCRIPT_NAME': '/tmp/test.php',
        'REQUEST_METHOD': 'GET',
        'QUERY_STRING': '',
        'REQUEST_URI': '/tmp/test.php',
        'DOCUMENT_ROOT': '/tmp',
        'SERVER_SOFTWARE': 'php/fcgiclient',
        'REMOTE_ADDR': '127.0.0.1',
        'REMOTE_PORT': '9985',
        'SERVER_ADDR': '127.0.0.1',
        'SERVER_PORT': '80',
        'SERVER_NAME': 'localhost',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'CONTENT_TYPE': '',
        'CONTENT_LENGTH': '0'
    }
    
    # FastCGI记录头
    FCGI_VERSION = 1
    FCGI_BEGIN_REQUEST = 1
    FCGI_PARAMS = 4
    FCGI_STDIN = 5
    FCGI_RESPONDER = 1
    
    # 开始请求记录
    request = struct.pack('>BBHHBx',
        FCGI_VERSION,
        FCGI_BEGIN_REQUEST,
        1,  # request ID
        8,  # content length
        0,  # padding length
    )
    request += struct.pack('>HBx',
        FCGI_RESPONDER,  # role
        0,  # flags
    )
    
    # 参数记录
    params_data = pack_fastcgi_params(params)
    request += struct.pack('>BBHHBx',
        FCGI_VERSION,
        FCGI_PARAMS,
        1,  # request ID
        len(params_data),  # content length
        0,  # padding length
    )
    request += params_data
    
    # 空参数记录表示参数结束
    request += struct.pack('>BBHHBx',
        FCGI_VERSION,
        FCGI_PARAMS,
        1,  # request ID
        0,  # content length
        0,  # padding length
    )
    
    # 空STDIN记录表示请求结束
    request += struct.pack('>BBHHBx',
        FCGI_VERSION,
        FCGI_STDIN,
        1,  # request ID
        0,  # content length
        0,  # padding length
    )
    
    return request

def check_phpfpm(ip, port):
    """检测PHP-FPM未授权访问"""
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, int(port)))
        
        # 发送FastCGI请求
        request = build_fastcgi_request()
        sock.send(request)
        
        # 接收响应
        response = sock.recv(1024)
        
        # 检查响应
        if response and len(response) > 0:
            if b'X-Powered-By: PHP' in response or b'Primary script unknown' in response:
                _t = f"[+] {ip}:{port} - 存在PHP-FPM未授权访问"
                save_result(_t)
                logger.info(_t)
                
                # 尝试获取PHP版本信息
                if b'X-Powered-By: PHP' in response:
                    php_version = response.split(b'X-Powered-By: PHP/')[1].split(b'\r\n')[0].decode()
                    _t = f"[*] {ip}:{port} - PHP版本: {php_version}"
                    save_result(_t)
                    logger.info(_t)
                
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
        if check_phpfpm(ip, port):
            return
        
        _t = f"[-] {ip}:{port} - 未发现PHP-FPM未授权访问"
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