#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import socket
import logging
import queue
import requests
from threading import Thread, Lock
from optparse import OptionParser
import re
import json

"""
Elasticsearch 未授权访问检测工具

使用方法:
    单个目标:
        python brute_elasticsearch.py -t 192.168.1.1
    批量检测:
        python brute_elasticsearch.py -a ip.txt
    指定端口:
        python brute_elasticsearch.py -t 192.168.1.1 -p 9200
    显示详细信息:
        python brute_elasticsearch.py -a ip.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认9200)
    -v  显示详细信息

支持检测的端口:
    - 9200: Elasticsearch HTTP默认端口
    - 9300: Elasticsearch 传输默认端口
"""

# 配置日志
logging.basicConfig(
	level=logging.INFO,
	format='%(asctime)s - %(levelname)s - %(message)s',
	datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 全局变量
result = []
result_lock = Lock()
task_queue = queue.Queue()

def save_result(text):
	"""
	安全地保存结果
	
	Args:
		text: 要保存的文本
	"""
	with result_lock:
		result.append(text)

def save_to_file(filename, text):
	"""
	安全地写入文件
	
	Args:
		filename: 文件名
		text: 要写入的文本
	"""
	try:
		with open(filename, 'a+', encoding='utf-8') as f:
			f.write(f"{text}\n")
	except Exception as e:
		logger.error(f"[!] 写入文件失败 {filename}: {str(e)}")

def brute(ip, port):
	"""
	检测Elasticsearch未授权访问
	
	Args:
		ip: 目标IP
		port: 目标端口
	"""
	try:
		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
			'Content-Type': 'application/json'
		}
		
		# 检测点1: 访问根路径获取基本信息
		url = f"http://{ip}:{port}/"
		response = requests.get(url, headers=headers, timeout=5, verify=False)
		
		if response.status_code == 200:
			_t = f"[+] {ip}:{port} - 存在Elasticsearch未授权访问"
			save_result(_t)
			logger.info(_t)
			
			try:
				data = response.json()
				version = data.get('version', {}).get('number', 'Unknown')
				cluster_name = data.get('cluster_name', 'Unknown')
				_t = f"[*] {ip}:{port} - Elasticsearch版本: {version}, 集群名称: {cluster_name}"
				save_result(_t)
				logger.info(_t)
			except:
				pass
			
			# 检测点2: 获取集群健康状态
			url = f"http://{ip}:{port}/_cluster/health"
			response = requests.get(url, headers=headers, timeout=5, verify=False)
			
			if response.status_code == 200:
				try:
					data = response.json()
					status = data.get('status', 'Unknown')
					nodes = data.get('number_of_nodes', 0)
					indices = data.get('number_of_indices', 0)
					_t = f"[*] {ip}:{port} - 集群状态: {status}, 节点数: {nodes}, 索引数: {indices}"
					save_result(_t)
					logger.info(_t)
				except:
					pass
			
			# 检测点3: 获取节点信息
			url = f"http://{ip}:{port}/_nodes/stats"
			response = requests.get(url, headers=headers, timeout=5, verify=False)
			
			if response.status_code == 200:
				try:
					data = response.json()
					nodes = data.get('nodes', {})
					_t = f"[*] {ip}:{port} - 发现 {len(nodes)} 个节点"
					save_result(_t)
					logger.info(_t)
					
					# 列出前5个节点的信息
					for node_id, node_info in list(nodes.items())[:5]:
						name = node_info.get('name', 'Unknown')
						transport_address = node_info.get('transport_address', 'Unknown')
						_t = f"[*] {ip}:{port} - 节点: {name}, 地址: {transport_address}"
						save_result(_t)
						logger.info(_t)
				except:
					pass
			
			# 检测点4: 获取索引信息
			url = f"http://{ip}:{port}/_cat/indices?format=json"
			response = requests.get(url, headers=headers, timeout=5, verify=False)
			
			if response.status_code == 200:
				try:
					indices = response.json()
					_t = f"[*] {ip}:{port} - 发现 {len(indices)} 个索引"
					save_result(_t)
					logger.info(_t)
					
					# 列出前5个索引的信息
					for index in indices[:5]:
						index_name = index.get('index', 'Unknown')
						docs = index.get('docs.count', 0)
						size = index.get('store.size', 'Unknown')
						_t = f"[*] {ip}:{port} - 索引: {index_name}, 文档数: {docs}, 大小: {size}"
						save_result(_t)
						logger.info(_t)
				except:
					pass
			
			# 检测点5: 检查快照信息
			url = f"http://{ip}:{port}/_snapshot/_all"
			response = requests.get(url, headers=headers, timeout=5, verify=False)
			
			if response.status_code == 200:
				try:
					repositories = response.json()
					_t = f"[*] {ip}:{port} - 发现 {len(repositories)} 个快照仓库"
					save_result(_t)
					logger.info(_t)
					
					# 列出快照仓库信息
					for repo_name, repo_info in repositories.items():
						repo_type = repo_info.get('type', 'Unknown')
						_t = f"[*] {ip}:{port} - 仓库: {repo_name}, 类型: {repo_type}"
						save_result(_t)
						logger.info(_t)
				except:
					pass
			
			# 检测点6: 检查写入权限
			test_index = 'test_index_delete_me'
			url = f"http://{ip}:{port}/{test_index}"
			try:
				# 创建测试索引
				response = requests.put(url, headers=headers, timeout=5, verify=False)
				if response.status_code in [200, 201]:
					_t = f"[+] {ip}:{port} - 具有索引创建权限"
					save_result(_t)
					logger.info(_t)
					
					# 尝试写入测试文档
					doc_url = f"{url}/_doc/1"
					data = {"test": "test_data"}
					response = requests.post(doc_url, headers=headers, json=data, timeout=5, verify=False)
					
					if response.status_code in [200, 201]:
						_t = f"[+] {ip}:{port} - 具有文档写入权限"
						save_result(_t)
						logger.info(_t)
					
					# 清理测试数据
					requests.delete(url, headers=headers, timeout=5, verify=False)
			except:
				pass
			
			return True
	except requests.exceptions.RequestException as e:
		logger.debug(f"[-] {ip}:{port} - 连接失败: {str(e)}")
	except Exception as e:
		logger.debug(f"[-] {ip}:{port} - {str(e)}")
	return False

def run(func, threadnum, ips, port, filename=None):
	"""
	多线程运行检测函数
	
	Args:
		func: 要运行的函数
		threadnum: 线程数
		ips: IP列表
		port: 端口
		filename: 文件名(可选)
	"""
	running_threads = []
	
	for ip in ips:
		while len(running_threads) >= threadnum:
			running_threads = [t for t in running_threads if t.is_alive()]
		
		if filename:
			t = Thread(target=func, args=(ip, port, filename))
		else:
			t = Thread(target=func, args=(ip, port))
		
		running_threads.append(t)
		t.start()
	
	for t in running_threads:
		t.join()

def scan(ip, port, filename):
	"""
	扫描端口是否开放
	
	Args:
		ip: 目标IP
		port: 目标端口
		filename: 保存结果的文件名
	"""
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(2)
	try:
		res = s.connect_ex((ip, int(port)))
		if res == 0:
			with open(filename, 'a+') as f:
				f.write(f"{ip}\n")
	except:
		pass
	finally:
		s.close()

def main():
	parser = OptionParser()
	parser.add_option("-t", "--target", dest="target", help="目标IP")
	parser.add_option("-a", "--address", dest="address", help="IP列表文件")
	parser.add_option("-p", "--port", dest="port", default="9200", help="端口(默认9200)")
	parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="显示详细信息")
	
	(options, args) = parser.parse_args()
	
	if options.verbose:
		logger.setLevel(logging.DEBUG)
	
	if not options.target and not options.address:
		parser.print_help()
		sys.exit(1)
	
	if options.target:
		brute(options.target, options.port)
	
	if options.address:
		try:
			with open(options.address) as f:
				ips = [ip.strip() for ip in f.readlines()]
			run(brute, 10, ips, options.port)
		except Exception as e:
			logger.error(f"[!] 读取文件失败 {options.address}: {str(e)}")
			sys.exit(1)
	
	if result:
		save_to_file("elasticsearch_unauthorized.txt", "\n".join(result))

if __name__ == "__main__":
	main()




