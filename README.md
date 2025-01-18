# 未授权访问检测工具

这是一个用于检测各种服务未授权访问漏洞的图形化工具。支持多种常见服务的检测，包括Redis、MongoDB、Elasticsearch等。

## 功能特点

- 图形化界面，操作简单直观
- 支持多种常见服务的未授权访问检测
- 可自定义检测端口
- 多线程扫描，提高检测效率
- 实时显示检测结果
- 可随时停止检测任务

## 支持的服务

- Redis (默认端口: 6379)
- MongoDB (默认端口: 27017)
- Elasticsearch (默认端口: 9200)
- Memcached (默认端口: 11211)
- Docker (默认端口: 2375)
- Jenkins (默认端口: 8080)
- Kubernetes (默认端口: 8080)
- Zookeeper (默认端口: 2181)
- RabbitMQ (默认端口: 5672)
- CouchDB (默认端口: 5984)
- Druid (默认端口: 8888)
- ActiveMQ (默认端口: 8161)
- Spark (默认端口: 8080)
- Tomcat (默认端口: 8080)
- WebLogic (默认端口: 7001)
- JBoss (默认端口: 8080)
- Jupyter (默认端口: 8888)
- Docker Registry (默认端口: 5000)
- Flink (默认端口: 8081)
- Neo4j (默认端口: 7474)
- Cassandra (默认端口: 9042)
- HBase (默认端口: 16010)
- Kibana (默认端口: 5601)
- Solr (默认端口: 8983)

## 安装

1. 克隆仓库：
```bash
git clone https://github.com/yourusername/unauthorized-scanner.git
cd unauthorized-scanner
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

## 使用方法

1. 运行程序：
```bash
python gui.py
```

2. 在图形界面中：
   - 从左侧列表选择要检测的服务（可多选）
   - 输入目标IP地址
   - 可选：自定义端口号（留空则使用默认端口）
   - 设置线程数（默认为10）
   - 点击"开始检测"按钮开始检测
   - 可随时点击"停止检测"按钮终止检测

3. 检测结果会实时显示在界面的输出区域

## 注意事项

- 请确保有合法授权后再进行检测
- 建议在测试环境中使用
- 不要在未经授权的目标上使用本工具
- 使用多线程时注意合理设置线程数，避免对目标系统造成过大压力

## 贡献

欢迎提交Issue和Pull Request来帮助改进这个工具。

## 许可证

MIT License 