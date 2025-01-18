#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import socket
from threading import Thread, Lock
from optparse import OptionParser
import logging

"""
Docker API 未授权访问检测工具

使用方法:
    单个目标:
        python brute_docker.py -t 192.168.1.1
    批量检测:
        python brute_docker.py -a ip.txt
    指定端口:
        python brute_docker.py -t 192.168.1.1 -p 2376
    显示详细信息:
        python brute_docker.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认2375)
    -v  显示详细信息
"""

# 定义默认端口
default_port = 2375

# 配置日志
logging.basicConfig(
	level=logging.INFO,
	format='%(asctime)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 存储检测结果
result = []
result_lock = Lock()

def save_result(text):
	"""安全地保存结果到全局result列表"""
	with result_lock:
		result.append(text)

def brute(ip, port):
	"""
	检测Docker未授权访问
	
	Args:
		ip: 目标IP
		port: 目标端口
	"""
	try:
		# 检测点1: 获取Docker信息
		url = f"http://{ip}:{port}/info"
		response = requests.get(url, timeout=5)
		if response.status_code == 200:
			_t = f"[+] {ip}:{port} - 存在Docker未授权访问"
			save_result(_t)
			logger.info(_t)
			
			data = response.json()
			if "ServerVersion" in data:
				_t = f"[*] {ip}:{port} - Docker版本: {data['ServerVersion']}"
				save_result(_t)
				logger.info(_t)
			
			# 检测点2: 列出容器
			url = f"http://{ip}:{port}/containers/json?all=1"
			response = requests.get(url, timeout=5)
			if response.status_code == 200:
				containers = response.json()
				_t = f"[*] {ip}:{port} - 发现 {len(containers)} 个容器"
				save_result(_t)
				logger.info(_t)
				
				# 显示容器详细信息
				for container in containers[:5]:  # 只显示前5个
					_t = f"[*] {ip}:{port} - 容器ID: {container.get('Id', '')[:12]}, 镜像: {container.get('Image', '')}, 状态: {container.get('State', '')}"
					save_result(_t)
					logger.info(_t)
			
			# 检测点3: 列出镜像
			url = f"http://{ip}:{port}/images/json"
			response = requests.get(url, timeout=5)
			if response.status_code == 200:
				images = response.json()
				_t = f"[*] {ip}:{port} - 发现 {len(images)} 个镜像"
				save_result(_t)
				logger.info(_t)
			
			return True
	except requests.exceptions.RequestException as e:
		logger.debug(f"[-] {ip}:{port} - 连接失败: {str(e)}")
	except Exception as e:
		logger.debug(f"[-] {ip}:{port} - {str(e)}")
	return False

if __name__ == '__main__':
	usage = "Usage: python %prog [options] args"
	parser = OptionParser(usage, version="%prog 1.0")
	parser.add_option("-t", dest="host", help="target host")
	parser.add_option("-p", dest="port", default="2375", help="target port (default: 2375)")
	parser.add_option("-a", dest="hosts", help="target hosts file")
	parser.add_option("-v", dest="verbose", action="store_true", help="verbose output")
	options, args = parser.parse_args()

	if options.verbose:
		logging.getLogger().setLevel(logging.DEBUG)

	port = options.port

	try:
		if options.host:
			brute(options.host, port)
		elif options.hosts:
			with open(options.hosts, 'r') as f:
				targets = [line.strip() for line in f if line.strip()]
			for target in targets:
				brute(target, port)
		else:
			parser.print_help()

		# 输出结果
		if result:
			print("\n检测结果:")
			for line in result:
				print(line)

	except KeyboardInterrupt:
		print("\n[!] 扫描已终止")
	except Exception as e:
		print(f"\n[!] Error: {str(e)}")


		

