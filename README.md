# 网络流量异常检测系统

这是一个基于机器学习的网络流量异常检测系统，能够分析网络数据包并识别潜在的异常流量。支持多种数据源，包括 Arkime 和本地 PCAP 文件。

## 功能特点

- 多数据源支持
  - Arkime Elasticsearch 数据源
  - 本地 PCAP 文件分析
  - 实时网络流量捕获
- TCP 流量特征提取
- 基于时间窗口的流量分析
- 使用隔离森林(Isolation Forest)进行异常检测
- 支持模型的保存和加载
- 详细的日志记录和分析报告
- 可视化分析结果

## 系统要求

- Python 3.8+
- 相关Python包（见requirements.txt）
- 足够的磁盘空间用于存储PCAP文件和模型
- 适当的网络接口权限（用于实时捕获）

## 文件组织结构

```
./
├── cap.py              # 主程序文件
├── config.yaml         # 配置文件
├── requirements.txt    # 依赖包列表
├── normal_traffic/     # 正常流量PCAP文件目录
├── abnormal_traffic/   # 异常流量PCAP文件目录
├── models/            # 保存训练好的模型
│   ├── model.pkl     # 异常检测模型
│   └── scaler.pkl    # 特征标准化器
└── logs/             # 日志文件目录
```

## 安装

1. 克隆项目到本地
2. 创建并激活虚拟环境（推荐）：
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
```
3. 安装依赖：
```bash
pip install -r requirements.txt
```
4. 创建必要的目录结构：
```bash
mkdir -p normal_traffic abnormal_traffic models logs
```

## 配置说明

### 1. 数据源配置（config.yaml）

```yaml
# 选择数据源类型
data_source: 'pcap'  # 或 'arkime'

# PCAP模式配置
pcap:
  training:
    normal_traffic_dir: './normal_traffic'     # 存放正常流量的PCAP文件
    abnormal_traffic_dir: './abnormal_traffic' # 存放异常流量的PCAP文件
    normal_traffic_pattern: '*.pcap'    # 文件匹配模式
    abnormal_traffic_pattern: '*.pcap'  # 文件匹配模式
  
  detection:
    interface: 'en0'           # 实时捕获的网络接口名称
    pcap_file: null           # 指定PCAP文件路径（留空为实时捕获）
    capture_filter: 'tcp'     # 数据包捕获过滤器

# Arkime模式配置
arkime:
  elasticsearch_host: 'http://your-es-host:9200'
  index: 'sessions3-*'
  time_window_hours: 1
```

### 2. 分析参数配置

```yaml
analysis:
  interval_seconds: 300    # 分析间隔时间
  batch_size: 10000       # 每批处理的最大会话数
  alert_threshold: 0.8    # 异常检测阈值（0-1）

feature_extraction:
  time_window: 60         # 特征提取时间窗口（秒）
  min_packets: 10         # 最小数据包数阈值
  features:               # 要提取的特征列表
    - duration
    - bytes_sent
    - bytes_received
    - packets_sent
    - packets_received
    - avg_packet_size
    - bytes_per_second
    - packets_per_second

model:
  contamination: 0.1      # 预期异常比例
  random_state: 42        # 随机数种子
```

## 使用方法

1. 准备数据
   - PCAP模式：
     - 将正常流量的PCAP文件放入 `normal_traffic/` 目录
     - 将异常流量的PCAP文件放入 `abnormal_traffic/` 目录
   - Arkime模式：
     - 确保Elasticsearch服务可访问
     - 配置正确的索引名称

2. 配置参数
   - 根据需求修改 `config.yaml` 中的参数
   - 特别注意网络接口名称和过滤器设置

3. 运行程序
```bash
python cap.py
```

4. 模型管理
```python
# 训练完成后保存模型
analyzer.save_model(model_path='models/model.pkl', scaler_path='models/scaler.pkl')

# 加载已有模型
analyzer.load_model(model_path='models/model.pkl', scaler_path='models/scaler.pkl')
```

## 日志和结果

- 程序运行日志保存在 `logs/` 目录下
- 日志文件名格式：`traffic_analysis_YYYYMMDD_HHMMSS.log`
- 每次分析的异常检测结果会记录在日志中
- 当检测到异常时，会在日志中标记详细信息

## 注意事项

1. 实时捕获模式需要管理员权限
2. 确保有足够的磁盘空间存储PCAP文件
3. 定期检查和清理日志文件
4. 根据实际网络环境调整时间窗口和阈值参数
5. 建议先使用小数据集进行测试，再逐步增加数据量

## 故障排除

1. 如果无法捕获数据包：
   - 检查网络接口名称是否正确
   - 确认是否有足够的权限
   - 验证捕获过滤器语法

2. 如果内存使用过高：
   - 减小batch_size参数
   - 缩短时间窗口
   - 减少特征数量

3. 如果检测结果不准确：
   - 调整contamination参数
   - 增加训练数据量
   - 修改特征提取参数
   
   # 加载模型
   analyzer.load_model()
   ```

## 主要文件说明

- `cap.py`: 主程序文件，包含特征提取和异常检测逻辑
- `config.yaml`: 系统配置文件，包含数据源、分析参数等配置
- `requirements.txt`: 项目依赖包列表
- `model.pkl`: 保存的模型文件（训练后生成）
- `scaler.pkl`: 保存的标准化器文件（训练后生成）
- `traffic_analysis_*.log`: 分析日志文件

## 输出说明

- CSV格式的特征数据
- 异常检测结果
- 分析日志
- 可视化图表

## 注意事项

- 确保有足够的系统内存处理大型PCAP文件
- 建议定期更新normal_traffic_rules.yaml以适应网络环境变化

## 贡献

欢迎提交Issue和Pull Request来帮助改进项目。

## 许可证

MIT License
