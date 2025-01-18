#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2019-05-29 20:13:27
# @Author  : crhua 

import sys
import socket
import telnetlib
import re
import time
from threading import Thread
from optparse import OptionParser
import logging

"""
Telnet 弱口令检测工具

使用方法:
    单个目标:
        python brute_telnet.py -t 192.168.1.1 -u users.txt -P pass.txt
    批量检测:
        python brute_telnet.py -a ip.txt -u users.txt -P pass.txt
    指定端口:
        python brute_telnet.py -t 192.168.1.1 -p 23 -u users.txt -P pass.txt
    显示详细信息:
        python brute_telnet.py -a ip.txt -u users.txt -P pass.txt -v

参数说明:
    -t  指定单个目标IP
    -a  指定IP列表文件
    -p  指定端口(默认23)
    -u  指定用户名字典
    -P  指定密码字典
    -v  显示详细信息
"""

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def brute(ip, port, users, passwds):
	for u in users:
		for p in passwds:
			u = u.strip()
			p = p.strip()
			try:
				tn = telnetlib.Telnet(ip, port, timeout=5)
				os = tn.read_some()
				
				user_match = "(?i)(login|user|username)"
				passwd_match = "(?i)(password)"
				login_match = "#|\$|>"
				
				if re.search(user_match, os.decode(errors='ignore')):
					try:
						tn.write(u.encode() + b"\r\n")
						tn.read_until(passwd_match.encode(), timeout=2)
						tn.write(p.encode() + b"\r\n")
						login_info = tn.read_until(login_match.encode(), timeout=3)
						if re.search(login_match, login_info.decode(errors='ignore')):
							_t = f"[+] {ip}:{port} Telnet弱口令: {u}/{p}"
							result.append(_t)
							return
					except:
						pass
					finally:
						try:
							tn.close()
						except:
							pass
			except:
				pass

def run(func, threadnum, ips, port, filename=None, users=None, passwds=None):
	running_threads = []
	
	for ip in ips:
		while len(running_threads) >= threadnum:
			running_threads = [t for t in running_threads if t.is_alive()]
		
		if filename:
			t = Thread(target=func, args=(ip, port, filename))
		else:
			t = Thread(target=func, args=(ip, port, users, passwds))
		
		running_threads.append(t)
		t.start()
	
	for t in running_threads:
		t.join()

def scan(ip, port, filename):
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
	usage = "Usage: python %prog [options] args"
	parser = OptionParser(usage, version="%prog 1.0")
	parser.add_option("-t", dest="host", help="target host")
	parser.add_option("-p", dest="port", default="23", help="target port (default: 23)")
	parser.add_option("-u", dest="user", help="username dictionary file")
	parser.add_option("-P", dest="passwd", help="password dictionary file")
	parser.add_option("-a", dest="hosts", help="target hosts file")
	parser.add_option("-v", dest="verbose", action="store_true", help="verbose output")
	options, args = parser.parse_args()

	if options.verbose:
		logging.getLogger().setLevel(logging.DEBUG)

	if not options.user or not options.passwd:
		print("请指定用户名字典(-u)和密码字典(-P)")
		return

	# 读取用户名和密码字典
	try:
		with open(options.user, 'r') as f:
			users = [line.strip() for line in f if line.strip()]
		with open(options.passwd, 'r') as f:
			passwds = [line.strip() for line in f if line.strip()]
	except:
		print("读取字典文件失败")
		return

	port = options.port
	global result
	result = []
	threadnum = 50

	try:
		if options.host:
			brute(options.host, port, users, passwds)
		elif options.hosts:
			# 1. 读取目标文件
			with open(options.hosts, 'r') as f:
				tmp_list = [line.strip() for line in f if line.strip()]
			
			if not tmp_list:
				return

			# 2. 端口扫描
			file_name = f"{port}_telnet.txt"
			run(scan, threadnum, tmp_list, port, file_name)
			
			# 3. 漏洞检测
			try:
				with open(file_name, 'r') as f:
					last_list = [line.strip() for line in f if line.strip()]
				
				if last_list:
					run(brute, threadnum, last_list, port, None, users, passwds)
			except:
				pass
		else:
			parser.print_help()
			return

		# 只输出存在漏洞的结果
		if result:
			for m in result:
				print(m)

	except KeyboardInterrupt:
		print("\n[!] 扫描已终止")
	except Exception as e:
		print(f"\n[!] Error: {str(e)}")

if __name__ == '__main__':
	main()


		

