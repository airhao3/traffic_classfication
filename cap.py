import pandas as pd
import numpy as np
from collections import defaultdict
import pyshark
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import nest_asyncio
import re
import logging
import sys
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f'traffic_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)

nest_asyncio.apply()

def extract_tcp_features(pcap_file, time_window=60):
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

if __name__ == "__main__":
    try:
        pcap_file = "input.pcap"  # Replace with your pcap file path
        logger.info(f"开始处理pcap文件: {pcap_file}")
        
        time_window = 60
        df = extract_tcp_features(pcap_file, time_window)
        df = preprocess_tcp_features(df)
        train_and_evaluate_model(df)
        
        logger.info("程序执行完成")
    except Exception as e:
        logger.error(f"程序执行出错: {str(e)}")
        raise