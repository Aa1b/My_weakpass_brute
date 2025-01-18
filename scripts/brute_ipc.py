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
default_port = 445

# 存储检测结果
result = []
result_lock = Lock()

def save_result(text):
    """安全地保存结果到全局result列表"""
    with result_lock:
        result.append(text)

def build_smb_negotiate_packet():
    """构建SMB协议协商数据包"""
    # NetBIOS Session Service
    netbios = bytearray([
        0x00,               # 消息类型
        0x00, 0x00, 0x54   # 长度（84字节）
    ])
    
    # SMB Header
    smb_header = bytearray([
        0xFF, 0x53, 0x4D, 0x42,  # SMB协议标识 ("\xffSMB")
        0x72,                     # SMB命令: Negotiate Protocol (0x72)
        0x00, 0x00, 0x00, 0x00,  # NT状态: SUCCESS
        0x18,                     # 标志
        0x53, 0xC8,              # 标志2
        0x00, 0x00,              # 进程ID高位
        0x00, 0x00, 0x00, 0x00,  # 签名
        0x00, 0x00,              # 保留
        0x00, 0x00,              # 树ID
        0x00, 0x00,              # 进程ID
        0x00, 0x00,              # 用户ID
        0x00, 0x00               # 多路复用ID
    ])
    
    # SMB参数
    smb_parameters = bytearray([
        0x00,               # 字数
        0x0C, 0x00         # 字节计数 (12)
    ])
    
    # SMB数据
    smb_data = bytearray([
        0x02,               # 方言计数
        0x4E, 0x54, 0x20,  # "NT "
        0x4C, 0x4D, 0x20,  # "LM "
        0x30, 0x2E, 0x31,  # "0.1"
        0x32, 0x00         # "\0"
    ])
    
    return netbios + smb_header + smb_parameters + smb_data

def check_ipc(ip, port):
    """检测Windows IPC共享未授权访问"""
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, int(port)))
        
        # 发送SMB协商请求
        packet = build_smb_negotiate_packet()
        sock.send(packet)
        
        # 接收响应
        response = sock.recv(1024)
        
        # 检查响应
        if response and len(response) > 0:
            # 检查SMB协议标识
            if response[4:8] == b'\xffSMB':
                # 检查NT状态码
                nt_status = struct.unpack('>L', response[9:13])[0]
                if nt_status == 0:  # STATUS_SUCCESS
                    _t = f"[+] {ip}:{port} - 存在Windows IPC共享未授权访问"
                    save_result(_t)
                    logger.info(_t)
                    
                    # 尝试获取更多信息
                    try:
                        # 从响应中提取Windows版本信息
                        if len(response) > 72:
                            major_version = response[72]
                            minor_version = response[73]
                            _t = f"[*] {ip}:{port} - Windows版本: {major_version}.{minor_version}"
                            save_result(_t)
                            logger.info(_t)
                    except:
                        pass
                    
                    return True
                else:
                    # 记录NT状态码
                    _t = f"[-] {ip}:{port} - SMB响应状态码: 0x{nt_status:08x}"
                    logger.debug(_t)
            
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
        if check_ipc(ip, port):
            return
        
        _t = f"[-] {ip}:{port} - 未发现Windows IPC共享未授权访问"
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