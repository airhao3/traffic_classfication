# 网络流量异常检测系统

这是一个基于机器学习的网络流量异常检测系统，能够分析网络数据包并识别潜在的异常流量。

## 功能特点

- TCP流量特征提取
- 基于时间窗口的流量分析
- 使用隔离森林(Isolation Forest)进行异常检测
- 支持自定义正常流量规则配置
- 详细的日志记录和分析报告
- 可视化分析结果

## 系统要求

- Python 3.8+
- 相关Python包（见requirements.txt）

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

## 使用方法

1. 准备PCAP文件
2. 配置normal_traffic_rules.yaml（可选）
3. 运行分析脚本：
```bash
python cap.py
```

## 主要文件说明

- `cap.py`: 主程序文件，包含特征提取和异常检测逻辑
- `normal_traffic_rules.yaml`: 正常流量规则配置文件
- `requirements.txt`: 项目依赖包列表
- `traffic_analysis.png`: 流量分析可视化结果
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
