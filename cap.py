import pandas as pd
import numpy as np
from collections import defaultdict
import pyshark
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import time
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import nest_asyncio
import re
import logging
import sys
import yaml
import os
import json
import glob

# 确保logs目录存在
os.makedirs('logs', exist_ok=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join('logs', f'traffic_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'))
    ]
)
logger = logging.getLogger(__name__)

nest_asyncio.apply()

def extract_tcp_features_from_pcap(pcap_file, time_window=60):
    """Extract TCP features from a pcap file, group by session and time window."""
    logger.info(f"开始从pcap文件提取TCP特征: {pcap_file}")
    
    capture = pyshark.FileCapture(pcap_file, display_filter='tcp')
    features = []
    flow_data = defaultdict(lambda: {
        'start_time': None,
        'end_time': None,
        'bytes_sent': 0,
        'bytes_received': 0,
        'packets_sent': 0,
        'packets_received': 0,
        'retransmission_count': 0,
        'interarrival_times': [],
        'tcp_flags': defaultdict(int),
        'payload_lengths': [],
        'number_of_syn_packets': 0,
        'number_of_fin_packets': 0,
        'number_of_reset_packets': 0,
        'number_of_push_packets': 0,
    })

    packet_count = 0
    for packet in capture:
        try:
            if 'TCP' not in packet:
                continue

            packet_count += 1
            if packet_count % 1000 == 0:
                logger.info(f"已处理 {packet_count} 个数据包")

            tcp_layer = packet.tcp
            ip_layer = packet.ip
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = int(tcp_layer.srcport)
            dst_port = int(tcp_layer.dstport)

            flow_key = tuple(sorted((src_ip, dst_ip)) + sorted((src_port, dst_port)))
            if flow_data[flow_key]['start_time'] is None:
                flow_data[flow_key]['start_time'] = packet.sniff_time
            flow_data[flow_key]['end_time'] = packet.sniff_time

            payload_len = int(packet.length) - (int(tcp_layer.hdr_len) + int(ip_layer.hdr_len))
            flow_data[flow_key]['payload_lengths'].append(payload_len)

            if packet.ip.src == src_ip:
                flow_data[flow_key]['bytes_sent'] += int(packet.length)
                flow_data[flow_key]['packets_sent'] += 1
            elif packet.ip.src == dst_ip:
                flow_data[flow_key]['bytes_received'] += int(packet.length)
                flow_data[flow_key]['packets_received'] += 1

            if hasattr(tcp_layer, 'flags'):
               flags = str(tcp_layer.flags)
               if 'SYN' in flags:
                   flow_data[flow_key]['number_of_syn_packets'] += 1
               if 'FIN' in flags:
                   flow_data[flow_key]['number_of_fin_packets'] += 1
               if 'RST' in flags:
                   flow_data[flow_key]['number_of_reset_packets'] += 1
               if 'PSH' in flags:
                  flow_data[flow_key]['number_of_push_packets'] += 1

            if hasattr(tcp_layer, 'analysis'):
                if hasattr(tcp_layer.analysis, 'retransmission'):
                    flow_data[flow_key]['retransmission_count'] += 1

            if flow_data[flow_key]['packets_sent'] + flow_data[flow_key]['packets_received'] > 1:
                if flow_data[flow_key]['interarrival_times']:
                    last_arrival_time = flow_data[flow_key]['interarrival_times'][-1]
                else:
                    last_arrival_time = flow_data[flow_key]['start_time']

                if isinstance(last_arrival_time, float):
                    last_arrival_time = datetime.fromtimestamp(last_arrival_time)

                interarrival_time = packet.sniff_time - last_arrival_time
                flow_data[flow_key]['interarrival_times'].append(interarrival_time.total_seconds())
        except AttributeError as e:
            logger.warning(f"处理数据包时出现错误: {str(e)}")
            continue

    logger.info(f"数据包处理完成，共处理 {packet_count} 个数据包")
    capture.close()

    for flow_key, data in flow_data.items():
        src_ip = flow_key[0]
        dst_ip = flow_key[1]
        src_port = flow_key[2]
        dst_port = flow_key[3]

        duration = (data["end_time"] - data["start_time"])
        bytes_sent = data['bytes_sent']
        bytes_received = data['bytes_received']
        packets_sent = data['packets_sent']
        packets_received = data['packets_received']
        retransmission_count = data["retransmission_count"]
        interarrival_times = data['interarrival_times']
        avg_interarrival_time = np.mean(interarrival_times) if interarrival_times else 0
        payload_lengths = data['payload_lengths']
        avg_payload_length = np.mean(payload_lengths) if payload_lengths else 0
        syn_packets = data['number_of_syn_packets']
        fin_packets = data['number_of_fin_packets']
        reset_packets = data['number_of_reset_packets']
        push_packets = data['number_of_push_packets']

        start_time = data['start_time']
        end_time = data['end_time']
        if isinstance(start_time, datetime):
            current_time = start_time
        else:
            current_time = datetime.fromtimestamp(start_time)
        if isinstance(end_time, datetime):
            end_time = end_time
        else:
            end_time = datetime.fromtimestamp(end_time)

        while current_time < end_time:
            next_time = min(current_time + pd.Timedelta(seconds=time_window), end_time)
            window_duration = (next_time - current_time).total_seconds()

            feature_dict = {
                'start_time': current_time.isoformat(),
                'end_time': next_time.isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'duration': duration.total_seconds(),
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'packets_sent': packets_sent,
                'packets_received': packets_received,
                'retransmission_count': retransmission_count,
                'avg_interarrival_time': avg_interarrival_time,
                'avg_payload_length': avg_payload_length,
                'number_of_syn_packets': syn_packets,
                'number_of_fin_packets': fin_packets,
                'number_of_reset_packets': reset_packets,
                'number_of_push_packets': push_packets,
            }
            features.append(feature_dict)
            current_time = next_time

    df = pd.DataFrame(features)
    logger.info(f"特征提取完成，数据形状: {df.shape}")
    return df

def preprocess_tcp_features(df):
    """预处理TCP特征"""
    logger.info("开始数据预处理")
    logger.info(f"输入数据形状: {df.shape}")

    # 类型转换
    df['start_time'] = pd.to_datetime(df['start_time'])
    df['end_time'] = pd.to_datetime(df['end_time'])
    df['src_port'] = df['src_port'].astype(int)
    df['dst_port'] = df['dst_port'].astype(int)
    
    # 处理时间差
    if isinstance(df['duration'].iloc[0], pd.Timedelta):
        df['duration'] = df['duration'].apply(lambda x: x.total_seconds())
    
    # 处理缺失值
    df = df.fillna(0)
    
    logger.info("开始特征缩放")
    numerical_features = [
        'duration', 'bytes_sent', 'bytes_received', 'packets_sent',
        'packets_received', 'retransmission_count', 'avg_interarrival_time',
        'avg_payload_length', 'number_of_syn_packets', 'number_of_fin_packets',
        'number_of_reset_packets', 'number_of_push_packets'
    ]
    
    scaler = StandardScaler()
    df[numerical_features] = scaler.fit_transform(df[numerical_features])
    
    logger.info("开始分类特征编码")
    categorical_features = ['src_ip', 'dst_ip']
    
    # 保存原始IP地址
    original_features = df[categorical_features].copy()
    
    # 使用OneHotEncoder
    encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
    encoded_cats = encoder.fit_transform(df[categorical_features])
    
    # 获取编码后的特征名
    encoded_feature_names = []
    for i, feature in enumerate(categorical_features):
        feature_names = [f"{feature}_{val}" for val in encoder.categories_[i]]
        encoded_feature_names.extend(feature_names)
    
    # 创建编码后的DataFrame
    encoded_cats_df = pd.DataFrame(
        encoded_cats,
        columns=encoded_feature_names,
        index=df.index
    )
    
    # 合并数值特征和编码后的特征
    result_df = pd.concat([
        encoded_cats_df,
        df.drop(columns=categorical_features)
    ], axis=1)
    
    logger.info(f"预处理完成，最终数据形状: {result_df.shape}")
    logger.info(f"特征列: {result_df.columns.tolist()}")
    
    return result_df

def train_and_evaluate_model(df):
    """训练和评估模型"""
    logger.info("开始模型训练和评估")
    logger.info(f"输入数据形状: {df.shape}")

    # 分割数据集
    train_df = df.sample(frac=0.25, random_state=42)
    test_df = df.drop(train_df.index)
    logger.info(f"训练集大小: {train_df.shape}, 测试集大小: {test_df.shape}")

    # 定义特征列
    feature_cols = [col for col in train_df.columns if col not in ['start_time', 'end_time']]
    logger.info(f"使用特征数量: {len(feature_cols)}")

    # 模型训练
    isolation_forest = IsolationForest(
        n_estimators=100,
        max_samples=0.25,
        contamination=0.03,
        random_state=42,
        n_jobs=16
    )
    
    logger.info("开始训练模型")
    isolation_forest.fit(train_df[feature_cols])

    # 模型预测
    logger.info("开始预测")
    y_pred = isolation_forest.predict(test_df[feature_cols])
    y_pred_binary = np.where(y_pred == -1, 1, 0)  # 1 for anomaly, 0 for normal

    # 计算模型评估指标
    accuracy = accuracy_score(np.zeros(len(y_pred_binary)), y_pred_binary)
    precision = precision_score(np.zeros(len(y_pred_binary)), y_pred_binary, zero_division=0)
    recall = recall_score(np.zeros(len(y_pred_binary)), y_pred_binary, zero_division=0)
    f1 = f1_score(np.zeros(len(y_pred_binary)), y_pred_binary, zero_division=0)

    # 输出评估结果
    logger.info("\n=== 模型评估结果 ===")
    logger.info(f"Accuracy: {accuracy:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall: {recall:.4f}")
    logger.info(f"F1-Score: {f1:.4f}")
    
    # 异常检测统计
    anomaly_count = (y_pred == -1).sum()
    logger.info(f"\n检测到的异常数量: {anomaly_count}")
    logger.info(f"异常比例: {anomaly_count/len(y_pred):.2%}")

def extract_tcp_features_from_arkime(es_host, es_index, start_time=None, end_time=None, time_window=60):
    """从Arkime的Elasticsearch中提取TCP特征"""
    logger.info(f"开始从Arkime提取TCP特征: {es_host}, index: {es_index}")
    
    # 连接到Elasticsearch
    es = Elasticsearch([es_host])
    
    # 构建查询
    if start_time is None:
        start_time = datetime.now() - timedelta(hours=1)
    if end_time is None:
        end_time = datetime.now()
        
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"firstPacket": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                    {"term": {"protocol": "tcp"}}
                ]
            }
        },
        "size": 10000  # 调整大小根据需要
    }
    
    # 执行查询
    response = es.search(index=es_index, body=query, scroll='2m')
    scroll_id = response['_scroll_id']
    hits = response['hits']['hits']
    
    features = []
    while hits:
        for hit in hits:
            session = hit['_source']
            
            # 从Arkime会话数据提取特征
            feature = {
                'duration': (session.get('lastPacket', 0) - session.get('firstPacket', 0)) / 1000,  # 转换为秒
                'bytes_sent': session.get('srcBytes', 0),
                'bytes_received': session.get('dstBytes', 0),
                'packets_sent': session.get('srcPackets', 0),
                'packets_received': session.get('dstPackets', 0),
                'avg_packet_size': (session.get('srcBytes', 0) + session.get('dstBytes', 0)) / 
                                  (session.get('srcPackets', 0) + session.get('dstPackets', 0)) if 
                                  (session.get('srcPackets', 0) + session.get('dstPackets', 0)) > 0 else 0,
                'bytes_per_second': (session.get('srcBytes', 0) + session.get('dstBytes', 0)) / 
                                   ((session.get('lastPacket', 0) - session.get('firstPacket', 0)) / 1000) if 
                                   (session.get('lastPacket', 0) - session.get('firstPacket', 0)) > 0 else 0,
                'packets_per_second': (session.get('srcPackets', 0) + session.get('dstPackets', 0)) / 
                                     ((session.get('lastPacket', 0) - session.get('firstPacket', 0)) / 1000) if 
                                     (session.get('lastPacket', 0) - session.get('firstPacket', 0)) > 0 else 0,
                'src_port': session.get('srcPort', 0),
                'dst_port': session.get('dstPort', 0),
                'tcp_flags': session.get('tcpflags', 0),
            }
            
            features.append(feature)
            
        # 获取下一批结果
        response = es.scroll(scroll_id=scroll_id, scroll='2m')
        scroll_id = response['_scroll_id']
        hits = response['hits']['hits']
    
    return pd.DataFrame(features)

def load_config(config_file='config.yaml'):
    """加载配置文件"""
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

class TrafficAnalyzer:
    def __init__(self, config_path='config.yaml', model_dir='models'):
        self.config = load_config(config_path)
        self.model = None
        self.scaler = StandardScaler()
        self.model_dir = model_dir
        self.model_version = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 创建模型目录
        os.makedirs(model_dir, exist_ok=True)
        
        # 尝试加载最新的模型，如果没有则初始化新模型
        if not self.load_latest_model():
            self.initialize_model()
        
    def save_model(self, version=None):
        """保存模型和标准化器到文件
        
        Args:
            version (str, optional): 模型版本号，如果不指定则使用当前时间戳
        """
        if self.model is not None:
            import joblib
            
            # 使用指定版本号或当前版本号
            version = version or self.model_version
            
            # 构建保存路径
            model_path = os.path.join(self.model_dir, f'model_{version}.pkl')
            scaler_path = os.path.join(self.model_dir, f'scaler_{version}.pkl')
            metadata_path = os.path.join(self.model_dir, f'metadata_{version}.json')
            
            # 保存模型和标准化器
            logger.info(f'正在保存模型到 {model_path}')
            joblib.dump(self.model, model_path)
            logger.info(f'正在保存标准化器到 {scaler_path}')
            joblib.dump(self.scaler, scaler_path)
            
            # 保存元数据
            metadata = {
                'version': version,
                'created_at': datetime.now().isoformat(),
                'config': self.config,
                'features': self.get_feature_names()
            }
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
                
            logger.info('模型、标准化器和元数据保存完成')
        else:
            logger.warning('模型未初始化，无法保存')
            
    def load_model(self, version):
        """加载指定版本的模型和标准化器
        
        Args:
            version (str): 模型版本号
        
        Returns:
            bool: 是否成功加载模型
        """
        import joblib
        
        model_path = os.path.join(self.model_dir, f'model_{version}.pkl')
        scaler_path = os.path.join(self.model_dir, f'scaler_{version}.pkl')
        metadata_path = os.path.join(self.model_dir, f'metadata_{version}.json')
        
        try:
            # 检查所有必要文件是否存在
            if not all(os.path.exists(p) for p in [model_path, scaler_path, metadata_path]):
                logger.warning(f'版本 {version} 的模型文件不完整')
                return False
                
            # 加载元数据并验证
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                
            # 验证特征列表是否匹配
            if metadata['features'] != self.get_feature_names():
                logger.warning('模型特征与当前配置不匹配')
                return False
            
            # 加载模型和标准化器
            logger.info(f'正在加载模型从 {model_path}')
            self.model = joblib.load(model_path)
            logger.info(f'正在加载标准化器从 {scaler_path}')
            self.scaler = joblib.load(scaler_path)
            
            self.model_version = version
            logger.info(f'成功加载版本 {version} 的模型')
            return True
            
        except Exception as e:
            logger.error(f'加载模型失败: {str(e)}')
            return False
            
    def load_latest_model(self):
        """加载最新版本的模型
        
        Returns:
            bool: 是否成功加载模型
        """
        try:
            # 获取所有模型文件
            model_files = glob.glob(os.path.join(self.model_dir, 'model_*.pkl'))
            if not model_files:
                logger.info('没有找到已保存的模型')
                return False
                
            # 获取最新版本
            latest_version = max(re.findall(r'model_(.*?).pkl', f)[0] for f in model_files)
            return self.load_model(latest_version)
            
        except Exception as e:
            logger.error(f'加载最新模型失败: {str(e)}')
            return False
            
    def get_feature_names(self):
        """获取特征名列表"""
        return [
            'duration', 'bytes_sent', 'bytes_received', 'packets_sent',
            'packets_received', 'avg_packet_size', 'bytes_per_second',
            'packets_per_second'
        ]
        
    def initialize_model(self):
        """初始化异常检测模型"""
        self.model = IsolationForest(
            contamination=self.config.get('model', {}).get('contamination', 0.1),
            random_state=self.config.get('model', {}).get('random_state', 42)
        )
        
    def process_features(self, df):
        """处理特征数据"""
        if df.empty:
            return None
            
        # 选择数值型特征进行标准化
        numeric_features = [
            'duration', 'bytes_sent', 'bytes_received', 'packets_sent',
            'packets_received', 'avg_packet_size', 'bytes_per_second',
            'packets_per_second'
        ]
        
        # 确保所有必要的特征都存在
        for feature in numeric_features:
            if feature not in df.columns:
                logger.warning(f"缺少特征: {feature}")
                return None
                
        # 标准化特征
        X = self.scaler.fit_transform(df[numeric_features])
        return X
        
    def detect_anomalies(self, X):
        """检测异常流量"""
        if X is None or len(X) == 0:
            return None
            
        # 如果模型未训练，先进行训练
        if not hasattr(self.model, 'offset_'):
            self.model.fit(X)
            
        # 预测异常
        y_pred = self.model.predict(X)
        return y_pred
        
    def analyze_and_alert(self, df, y_pred):
        """分析异常流量并发出警报"""
        if y_pred is None:
            return
            
        anomalies = df[y_pred == -1]
        if not anomalies.empty:
            logger.warning(f"检测到 {len(anomalies)} 个异常流量会话")
            for idx, anomaly in anomalies.iterrows():
                logger.warning(
                    f"异常流量: \n"
                    f"源IP:端口 -> 目标IP:端口: {anomaly.get('src_ip', 'N/A')}:{anomaly.get('src_port', 'N/A')} -> "
                    f"{anomaly.get('dst_ip', 'N/A')}:{anomaly.get('dst_port', 'N/A')}\n"
                    f"持续时间: {anomaly.get('duration', 'N/A')}秒\n"
                    f"总字节数: {anomaly.get('bytes_sent', 0) + anomaly.get('bytes_received', 0)}\n"
                    f"总包数: {anomaly.get('packets_sent', 0) + anomaly.get('packets_received', 0)}"
                )
                
    def run_continuous_analysis(self):
        """持续运行流量分析"""
        logger.info("开始持续流量分析...")
        last_analysis_time = datetime.now() - timedelta(minutes=5)
        
        while True:
            try:
                current_time = datetime.now()
                df = None
                
                # 根据配置选择数据源
                if self.config['data_source'] == 'arkime':
                    logger.info("使用Arkime数据源进行分析")
                    df = extract_tcp_features_from_arkime(
                        es_host=self.config['arkime']['elasticsearch_host'],
                        es_index=self.config['arkime']['index'],
                        start_time=last_analysis_time,
                        end_time=current_time
                    )
                elif self.config['data_source'] == 'pcap':
                    logger.info("使用PCAP数据源进行分析")
                    pcap_config = self.config['pcap']['detection']
                    if pcap_config['pcap_file']:
                        # 从指定的pcap文件读取
                        logger.info(f"从PCAP文件分析: {pcap_config['pcap_file']}")
                        df = extract_tcp_features_from_pcap(
                            pcap_config['pcap_file'],
                            time_window=self.config['feature_extraction']['time_window']
                        )
                    else:
                        # 实时捕获
                        logger.info(f"从网络接口 {pcap_config['interface']} 实时捕获流量")
                        # TODO: 实现实时捕获的特征提取
                        continue
                
                if df is not None and not df.empty:
                    X = self.process_features(df)
                    if X is not None:
                        y_pred = self.detect_anomalies(X)
                        self.analyze_and_alert(df, y_pred)
                
                last_analysis_time = current_time
                # 等待配置的间隔时间
                interval = self.config.get('analysis', {}).get('interval_seconds', 300)
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"分析过程中出现错误: {str(e)}")
                time.sleep(60)  # 发生错误时等待1分钟再重试

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='网络流量异常检测系统')
    parser.add_argument('--mode', choices=['train', 'detect'], required=True,
                        help='运行模式：train-训练模型，detect-检测异常')
    parser.add_argument('--config', default='config.yaml',
                        help='配置文件路径')
    parser.add_argument('--model-dir', default='models',
                        help='模型保存目录')
    args = parser.parse_args()
    
    try:
        analyzer = TrafficAnalyzer(config_path=args.config, model_dir=args.model_dir)
        
        if args.mode == 'train':
            logger.info('开始训练模型...')
            # 从配置的数据源加载训练数据
            if analyzer.config['data_source'] == 'pcap':
                pcap_config = analyzer.config['pcap']['training']
                # 处理正常流量数据
                normal_files = glob.glob(os.path.join(
                    pcap_config['normal_traffic_dir'],
                    pcap_config['normal_traffic_pattern']
                ))
                # 处理异常流量数据
                abnormal_files = glob.glob(os.path.join(
                    pcap_config['abnormal_traffic_dir'],
                    pcap_config['abnormal_traffic_pattern']
                ))
                
                # 提取特征并训练模型
                dfs = []
                
                # 处理正常流量数据
                if normal_files:
                    logger.info(f'正在处理正常流量数据，共 {len(normal_files)} 个文件')
                    df_normal = pd.concat([extract_tcp_features_from_pcap(f) for f in normal_files])
                    df_normal['label'] = 0  # 标记为正常流量
                    dfs.append(df_normal)
                else:
                    logger.warning('没有找到正常流量数据文件')
                
                # 处理异常流量数据
                if abnormal_files:
                    logger.info(f'正在处理异常流量数据，共 {len(abnormal_files)} 个文件')
                    df_abnormal = pd.concat([extract_tcp_features_from_pcap(f) for f in abnormal_files])
                    df_abnormal['label'] = 1  # 标记为异常流量
                    dfs.append(df_abnormal)
                else:
                    logger.warning('没有找到异常流量数据文件')
                
                if not dfs:
                    logger.error('没有找到任何训练数据')
                    sys.exit(1)
                    
                # 合并所有数据
                df = pd.concat(dfs)
                
                # 预处理数据
                df = preprocess_tcp_features(df)
                
                # 训练并评估模型
                train_and_evaluate_model(df)
                
                # 保存模型
                analyzer.save_model()
                logger.info('模型训练和保存完成')
                
        elif args.mode == 'detect':
            # 确保模型已加载
            if analyzer.model is None:
                logger.error('没有可用的模型，请先训练模型')
                sys.exit(1)
            
            logger.info('开始异常检测...')
            analyzer.run_continuous_analysis()
            
    except Exception as e:
        logger.error(f"程序执行出错: {str(e)}")
        raise