#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import queue
import glob
import os
import importlib.util
import logging
from datetime import datetime

class VulnScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("自用小工具")
        self.root.geometry("800x600")
        
        # 确保必要的目录存在
        self.setup_directories()
        
        # 创建日志记录器
        self.setup_logger()
        
        # 初始化变量
        self.scanning = False
        self.result_queue = queue.Queue()
        self.scripts = {
            'unauthorized': [],
            'weakpass': []
        }
        self.usernames = []
        self.passwords = []
        
        # 发现检测脚本
        self.discover_scan_scripts()
        
        # 创建选项卡
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)
        
        # 未授权访问检测选项卡
        self.unauth_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.unauth_frame, text='未授权访问检测')
        self.setup_unauth_tab()
        
        # 弱口令检测选项卡
        self.weakpass_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.weakpass_frame, text='弱口令检测')
        self.setup_weakpass_tab()
        
        # 定期更新结果
        self.root.after(100, self.update_results)
    
    def setup_directories(self):
        """确保必要的目录和文件存在"""
        # 创建logs目录
        self.logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
        os.makedirs(self.logs_dir, exist_ok=True)
        
        # 创建scripts目录
        self.scripts_dir = os.path.join(os.path.dirname(__file__), 'scripts')
        os.makedirs(self.scripts_dir, exist_ok=True)
        
        # 如果scripts目录为空，创建示例脚本
        if not os.listdir(self.scripts_dir):
            self.create_example_script()
    
    def create_example_script(self):
        """创建示例脚本文件"""
        example_script = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def brute(target, timeout=5):
    """未授权访问检测函数"""
    # 在这里实现检测逻辑
    result.append(f"[*] 正在检测 {target}")
    result.append(f"[+] 发现未授权访问: {target}/example")

# 存储检测结果
result = []
'''
        
        with open(os.path.join(self.scripts_dir, 'brute_example.py'), 'w', encoding='utf-8') as f:
            f.write(example_script)
    
    def setup_logger(self):
        """配置日志记录器"""
        self.logger = logging.getLogger('VulnScanner')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # 文件处理器
        log_file = os.path.join(self.logs_dir, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def discover_scan_scripts(self):
        """发现所有检测脚本"""
        self.scripts = {
            'unauthorized': [],
            'weakpass': []
        }
        
        # 查找所有以brute_开头的Python文件
        script_files = glob.glob(os.path.join(self.scripts_dir, 'brute_*.py'))
        
        if not script_files:
            self.logger.warning("未找到任何检测脚本")
            return
            
        for script_file in script_files:
            try:
                # 获取脚本名称
                script_name = os.path.basename(script_file)[6:-3]  # 移除'brute_'前缀和'.py'后缀
                
                # 导入脚本模块
                spec = importlib.util.spec_from_file_location(script_name, script_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # 检查是否包含必要的函数
                if hasattr(module, 'brute'):
                    # 根据脚本类型分类
                    if hasattr(module, 'check_password'):
                        self.scripts['weakpass'].append({
                            'name': script_name,
                            'module': module,
                            'file': script_file
                        })
                    else:
                        self.scripts['unauthorized'].append({
                            'name': script_name,
                            'module': module,
                            'file': script_file
                        })
            except Exception as e:
                self.logger.error(f"加载脚本 {script_file} 失败: {str(e)}")
    
    def setup_unauth_tab(self):
        """设置未授权访问检测选项卡"""
        # 目标输入框
        target_frame = ttk.LabelFrame(self.unauth_frame, text="目标")
        target_frame.pack(fill='x', padx=5, pady=5)
        
        self.target_entry = ttk.Entry(target_frame)
        self.target_entry.pack(side='left', fill='x', expand=True, padx=5, pady=5)
        
        ttk.Button(target_frame, text="导入", command=self.import_targets).pack(side='right', padx=5, pady=5)
        
        # 服务选择框
        service_frame = ttk.LabelFrame(self.unauth_frame, text="检测服务")
        service_frame.pack(fill='x', padx=5, pady=5)
        
        self.service_listbox = tk.Listbox(service_frame, selectmode='multiple', height=10)
        self.service_listbox.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(service_frame, orient="vertical", command=self.service_listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self.service_listbox.config(yscrollcommand=scrollbar.set)
        
        # 添加服务到列表
        for script in self.scripts['unauthorized']:
            self.service_listbox.insert('end', script['name'])
        
        # 全选按钮
        self.unauth_select_all_btn = ttk.Button(service_frame, text="全选", command=self.toggle_unauth_selection)
        self.unauth_select_all_btn.pack(side='bottom', padx=5, pady=5)
        
        # 配置选项
        config_frame = ttk.LabelFrame(self.unauth_frame, text="配置")
        config_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(config_frame, text="线程数:").grid(row=0, column=0, padx=5, pady=5)
        self.thread_spinbox = ttk.Spinbox(config_frame, from_=1, to=100, width=10)
        self.thread_spinbox.set(10)
        self.thread_spinbox.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(config_frame, text="超时(秒):").grid(row=0, column=2, padx=5, pady=5)
        self.timeout_spinbox = ttk.Spinbox(config_frame, from_=1, to=60, width=10)
        self.timeout_spinbox.set(5)
        self.timeout_spinbox.grid(row=0, column=3, padx=5, pady=5)
        
        # 控制按钮
        control_frame = ttk.Frame(self.unauth_frame)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        self.start_button = ttk.Button(control_frame, text="开始检测", command=self.start_unauth_scan)
        self.start_button.pack(side='left', padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="停止", command=self.stop_scan, state='disabled')
        self.stop_button.pack(side='left', padx=5)
        
        ttk.Button(control_frame, text="导出结果", command=self.export_results).pack(side='right', padx=5)
        
        # 结果显示
        result_frame = ttk.LabelFrame(self.unauth_frame, text="检测结果")
        result_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD)
        self.result_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def setup_weakpass_tab(self):
        """设置弱口令检测选项卡"""
        # 目标输入框
        target_frame = ttk.LabelFrame(self.weakpass_frame, text="目标")
        target_frame.pack(fill='x', padx=5, pady=5)
        
        self.weakpass_target_entry = ttk.Entry(target_frame)
        self.weakpass_target_entry.pack(side='left', fill='x', expand=True, padx=5, pady=5)
        
        ttk.Button(target_frame, text="导入", command=self.import_targets).pack(side='right', padx=5, pady=5)
        
        # HTTP请求配置
        http_frame = ttk.LabelFrame(self.weakpass_frame, text="HTTP请求配置")
        http_frame.pack(fill='x', padx=5, pady=5)
        
        # 请求方法选择
        ttk.Label(http_frame, text="请求方法:").grid(row=0, column=0, padx=5, pady=5)
        self.http_method = tk.StringVar(value="POST")
        ttk.Radiobutton(http_frame, text="POST", variable=self.http_method, value="POST").grid(row=0, column=1, padx=5, pady=5)
        ttk.Radiobutton(http_frame, text="GET", variable=self.http_method, value="GET").grid(row=0, column=2, padx=5, pady=5)
        
        # 请求参数
        ttk.Label(http_frame, text="请求参数:").grid(row=1, column=0, padx=5, pady=5)
        self.http_params = ttk.Entry(http_frame)
        self.http_params.grid(row=1, column=1, columnspan=3, sticky='ew', padx=5, pady=5)
        ttk.Label(http_frame, text="例: {'username':'^LOGIN^','password':'^PASSWORD^'}").grid(row=1, column=4, padx=5, pady=5)
        
        # 成功/失败判断
        ttk.Label(http_frame, text="成功标识:").grid(row=2, column=0, padx=5, pady=5)
        self.success_text = ttk.Entry(http_frame)
        self.success_text.grid(row=2, column=1, columnspan=2, sticky='ew', padx=5, pady=5)
        
        ttk.Label(http_frame, text="失败标识:").grid(row=2, column=3, padx=5, pady=5)
        self.failure_text = ttk.Entry(http_frame)
        self.failure_text.grid(row=2, column=4, columnspan=2, sticky='ew', padx=5, pady=5)
        
        # 字典导入
        dict_frame = ttk.LabelFrame(self.weakpass_frame, text="字典")
        dict_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(dict_frame, text="用户名:").grid(row=0, column=0, padx=5, pady=5)
        self.username_count = tk.StringVar(value="0个")
        ttk.Label(dict_frame, textvariable=self.username_count).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(dict_frame, text="导入", command=lambda: self.import_dict('username')).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(dict_frame, text="密码:").grid(row=1, column=0, padx=5, pady=5)
        self.password_count = tk.StringVar(value="0个")
        ttk.Label(dict_frame, textvariable=self.password_count).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(dict_frame, text="导入", command=lambda: self.import_dict('password')).grid(row=1, column=2, padx=5, pady=5)
        
        # 配置选项
        config_frame = ttk.LabelFrame(self.weakpass_frame, text="配置")
        config_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(config_frame, text="线程数:").grid(row=0, column=0, padx=5, pady=5)
        self.weakpass_thread_spinbox = ttk.Spinbox(config_frame, from_=1, to=100, width=10)
        self.weakpass_thread_spinbox.set(10)
        self.weakpass_thread_spinbox.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(config_frame, text="超时(秒):").grid(row=0, column=2, padx=5, pady=5)
        self.weakpass_timeout_spinbox = ttk.Spinbox(config_frame, from_=1, to=60, width=10)
        self.weakpass_timeout_spinbox.set(5)
        self.weakpass_timeout_spinbox.grid(row=0, column=3, padx=5, pady=5)
        
        # 控制按钮
        control_frame = ttk.Frame(self.weakpass_frame)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        self.weakpass_start_button = ttk.Button(control_frame, text="开始检测", command=self.start_weakpass_scan)
        self.weakpass_start_button.pack(side='left', padx=5)
        
        self.weakpass_stop_button = ttk.Button(control_frame, text="停止", command=self.stop_scan, state='disabled')
        self.weakpass_stop_button.pack(side='left', padx=5)
        
        ttk.Button(control_frame, text="导出结果", command=self.export_results).pack(side='right', padx=5)
        
        # 结果显示
        result_frame = ttk.LabelFrame(self.weakpass_frame, text="检测结果")
        result_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.weakpass_result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD)
        self.weakpass_result_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def import_targets(self):
        """导入目标"""
        file_path = filedialog.askopenfilename(filetypes=[("文本文件", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    targets = f.read().strip()
                if self.notebook.select() == str(self.unauth_frame):
                    self.target_entry.delete(0, 'end')
                    self.target_entry.insert(0, targets)
                else:
                    self.weakpass_target_entry.delete(0, 'end')
                    self.weakpass_target_entry.insert(0, targets)
                messagebox.showinfo("成功", "目标导入成功")
            except Exception as e:
                messagebox.showerror("错误", f"导入失败: {str(e)}")
    
    def import_dict(self, dict_type):
        """导入字典"""
        file_path = filedialog.askopenfilename(filetypes=[("文本文件", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    items = [line.strip() for line in f if line.strip()]
                if dict_type == 'username':
                    self.usernames = items
                    self.username_count.set(f"{len(items)}个")
                else:
                    self.passwords = items
                    self.password_count.set(f"{len(items)}个")
                messagebox.showinfo("成功", f"{dict_type}字典导入成功")
            except Exception as e:
                messagebox.showerror("错误", f"导入失败: {str(e)}")
    
    def start_unauth_scan(self):
        """开始未授权访问检测"""
        if self.scanning:
            return
        
        # 获取目标
        targets = self.target_entry.get().strip().split('\n')
        if not targets:
            messagebox.showerror("错误", "请输入目标")
            return
        
        # 获取选中的服务
        selected_indices = self.service_listbox.curselection()
        if not selected_indices:
            messagebox.showerror("错误", "请选择要检测的服务")
            return
        
        selected_scripts = [self.scripts['unauthorized'][i] for i in selected_indices]
        
        # 获取配置
        try:
            thread_count = int(self.thread_spinbox.get())
            timeout = int(self.timeout_spinbox.get())
        except ValueError:
            messagebox.showerror("错误", "线程数和超时时间必须是整数")
            return
        
        # 开始检测
        self.start_scan(targets, selected_scripts, thread_count, timeout)
    
    def start_weakpass_scan(self):
        """开始弱口令检测"""
        if self.scanning:
            return
        
        # 获取目标
        targets = self.weakpass_target_entry.get().strip().split('\n')
        if not targets:
            messagebox.showerror("错误", "请输入目标")
            return
        
        # 检查字典
        if not self.usernames or not self.passwords:
            messagebox.showerror("错误", "请导入用户名和密码字典")
            return
        
        # 检查HTTP配置
        http_params = self.http_params.get().strip()
        if not http_params:
            messagebox.showerror("错误", "请输入HTTP请求参数")
            return
        
        success_text = self.success_text.get().strip()
        failure_text = self.failure_text.get().strip()
        if not success_text and not failure_text:
            messagebox.showerror("错误", "请至少输入一个成功或失败标识")
            return
        
        # 获取配置
        try:
            thread_count = int(self.weakpass_thread_spinbox.get())
            timeout = int(self.weakpass_timeout_spinbox.get())
        except ValueError:
            messagebox.showerror("错误", "线程数和超时时间必须是整数")
            return
        
        # 开始检测
        self.scanning = True
        self.result_queue = queue.Queue()
        
        # 更新按钮状态
        self.weakpass_start_button.config(state='disabled')
        self.weakpass_stop_button.config(state='normal')
        self.weakpass_result_text.delete(1.0, 'end')
        
        # 创建工作线程
        self.scan_thread = threading.Thread(
            target=self.scan_worker,
            args=(targets, self.scripts['weakpass'], thread_count, timeout, True)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def start_scan(self, targets, scripts, thread_count, timeout, is_weakpass=False):
        """开始检测"""
        self.scanning = True
        self.result_queue = queue.Queue()
        
        # 更新按钮状态
        if is_weakpass:
            self.weakpass_start_button.config(state='disabled')
            self.weakpass_stop_button.config(state='normal')
            self.weakpass_result_text.delete(1.0, 'end')
        else:
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.result_text.delete(1.0, 'end')
        
        # 创建工作线程
        self.scan_thread = threading.Thread(
            target=self.scan_worker,
            args=(targets, scripts, thread_count, timeout, is_weakpass)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def scan_worker(self, targets, scripts, thread_count, timeout, is_weakpass):
        """检测工作线程"""
        try:
            for target in targets:
                target = target.strip()
                if not target:
                    continue
                
                self.result_queue.put(f"\n[*] 正在检测目标: {target}")
                
                for script in scripts:
                    if not self.scanning:
                        return
                    
                    try:
                        if is_weakpass:
                            # 弱口令检测
                            method = self.http_method.get().lower()
                            params = self.http_params.get().strip()
                            success_text = self.success_text.get().strip()
                            failure_text = self.failure_text.get().strip()
                            
                            # 设置脚本参数
                            script['module'].method_name = method
                            script['module'].method = params
                            script['module'].success_word = success_text
                            script['module'].failure_word = failure_text
                            script['module'].timeout = timeout
                            
                            # 执行检测
                            script['module'].brute(
                                target,
                                usernames=self.usernames,
                                passwords=self.passwords,
                                timeout=timeout
                            )
                        else:
                            # 未授权访问检测
                            script['module'].brute(target, timeout=timeout)
                        
                        # 获取检测结果
                        if hasattr(script['module'], 'result'):
                            for line in script['module'].result:
                                self.result_queue.put(line)
                            # 清空结果，避免重复显示
                            script['module'].result = []
                    except Exception as e:
                        self.result_queue.put(f"[-] {target} - {script['name']}检测失败: {str(e)}")
        finally:
            self.scanning = False
            if is_weakpass:
                self.root.after(0, lambda: self.weakpass_start_button.config(state='normal'))
                self.root.after(0, lambda: self.weakpass_stop_button.config(state='disabled'))
            else:
                self.root.after(0, lambda: self.start_button.config(state='normal'))
                self.root.after(0, lambda: self.stop_button.config(state='disabled'))
    
    def stop_scan(self):
        """停止检测"""
        self.scanning = False
    
    def update_results(self):
        """更新结果显示"""
        while True:
            try:
                result = self.result_queue.get_nowait()
                if self.notebook.select() == str(self.unauth_frame):
                    self.result_text.insert('end', result + '\n')
                    self.result_text.see('end')
                else:
                    self.weakpass_result_text.insert('end', result + '\n')
                    self.weakpass_result_text.see('end')
                self.logger.info(result)
            except queue.Empty:
                break
        
        self.root.after(100, self.update_results)
    
    def export_results(self):
        """导出检测结果"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt")],
            initialfile=f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    if self.notebook.select() == str(self.unauth_frame):
                        f.write(self.result_text.get(1.0, 'end'))
                    else:
                        f.write(self.weakpass_result_text.get(1.0, 'end'))
                messagebox.showinfo("成功", "结果导出成功")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {str(e)}")
    
    def toggle_unauth_selection(self):
        """切换未授权检测服务的全选/全不选状态"""
        if self.service_listbox.size() == len(self.service_listbox.curselection()):
            # 如果已经全选，则全不选
            self.service_listbox.selection_clear(0, 'end')
            self.unauth_select_all_btn.config(text="全选")
        else:
            # 如果未全选，则全选
            self.service_listbox.selection_set(0, 'end')
            self.unauth_select_all_btn.config(text="全不选")
    
    def toggle_weakpass_selection(self):
        """切换弱口令检测服务的全选/全不选状态"""
        if self.weakpass_service_listbox.size() == len(self.weakpass_service_listbox.curselection()):
            # 如果已经全选，则全不选
            self.weakpass_service_listbox.selection_clear(0, 'end')
            self.weakpass_select_all_btn.config(text="全选")
        else:
            # 如果未全选，则全选
            self.weakpass_service_listbox.selection_set(0, 'end')
            self.weakpass_select_all_btn.config(text="全不选")

if __name__ == '__main__':
    root = tk.Tk()
    app = VulnScannerGUI(root)
    root.mainloop() 