# 弱口令&未授权访问检测工具

一个基于Python的安全检测工具，提供图形界面，支持弱口令爆破和未授权访问检测。

## 功能特点

### 弱口令检测
- 支持HTTP协议的用户名密码爆破
- 支持GET/POST请求方法
- 支持自定义请求参数
- 支持自定义成功/失败标识

### 未授权访问检测
- 支持自定义检测脚本
- 可扩展的插件系统

### 通用功能
- 图形化界面，操作简单
- 支持多线程检测
- 支持导入目标列表
- 支持导入用户名和密码字典
- 支持检测结果导出
- 支持日志记录

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用说明

1. 运行程序：
```bash
python gui.py
```

2. 弱口令检测：
   - 输入目标URL
   - 选择HTTP请求方法（GET/POST）
   - 配置请求参数，使用 ^LOGIN^ 和 ^PASSWORD^ 作为用户名和密码的占位符
   - 设置成功/失败标识文本
   - 导入用户名和密码字典
   - 设置线程数和超时时间
   - 点击"开始检测"

3. 未授权访问检测：
   - 输入目标URL
   - 选择要检测的服务
   - 设置线程数和超时时间
   - 点击"开始检测"

## 目录结构
```
My_weakpass_brute/
├── gui.py            # 主程序
├── scripts/          # 检测脚本目录
│   ├── brute_pass.py # 弱口令检测脚本
│   └── brute_*.py    # 其他检测脚本
├── logs/            # 日志目录
├── requirements.txt  # 依赖文件
└── README.md        # 说明文档
```

## 请求参数示例

POST请求参数示例：
```python
{'username': '^LOGIN^', 'password': '^PASSWORD^'}
```

GET请求参数示例：
```python
{'user': '^LOGIN^', 'pwd': '^PASSWORD^'}
```

## 自定义检测脚本

1. 在scripts目录下创建以"brute_"开头的Python文件
2. 实现必要的函数：
   - 弱口令检测脚本：实现 `brute(target, usernames, passwords, timeout=5)` 函数
   - 未授权检测脚本：实现 `brute(target, timeout=5)` 函数
3. 使用全局变量 `result` 列表存储检测结果

## 注意事项

1. 请合法使用本工具，仅用于授权的安全测试
2. 建议先使用小字典测试，确认配置正确后再使用大字典
3. 线程数建议根据目标服务器性能和网络情况适当调整
4. 超时时间建议根据网络情况适当调整

## 许可证

MIT License 