import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path
import os
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA

class TrafficVisualizer:
    def __init__(self, save_dir='visualizations'):
        """初始化可视化器
        
        Args:
            save_dir (str): 保存可视化图表的目录
        """
        self.save_dir = save_dir
        os.makedirs(save_dir, exist_ok=True)
        
        # 设置图表样式
        plt.style.use('seaborn')
        sns.set_palette("husl")
        
    def save_plot(self, name):
        """保存图表
        
        Args:
            name (str): 图表名称
        """
        plt.tight_layout()
        save_path = os.path.join(self.save_dir, f"{name}.png")
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
    def plot_feature_distributions(self, df, label_col='label'):
        """绘制特征分布图
        
        Args:
            df (pd.DataFrame): 包含特征的数据框
            label_col (str): 标签列名
        """
        # 选择数值型特征，排除IP地址和时间戳相关的列
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        numeric_cols = [col for col in numeric_cols if col != label_col and 
                       not col.startswith('src_ip_') and 
                       not col.startswith('dst_ip_') and
                       col not in ['start_time', 'end_time']]
        
        for feature in numeric_cols:
            plt.figure(figsize=(10, 6))
            if label_col in df.columns:
                # 分别绘制正常和异常流量的分布
                sns.kdeplot(data=df[df[label_col]==0][feature], label='Normal Traffic', alpha=0.5)
                sns.kdeplot(data=df[df[label_col]==1][feature], label='Anomalous Traffic', alpha=0.5)
            else:
                # 只绘制单个分布
                sns.kdeplot(data=df[feature], alpha=0.5)
                
            plt.title(f'Distribution of {feature}')
            plt.xlabel(feature)
            plt.ylabel('Density')
            plt.legend()
            self.save_plot(f'distribution_{feature}')
            
    def plot_correlation_matrix(self, df, label_col='label'):
        """绘制特征相关性矩阵
        
        Args:
            df (pd.DataFrame): 包含特征的数据框
            label_col (str): 标签列名
        """
        # 选择有意义的数值特征进行相关性分析
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        numeric_cols = [col for col in numeric_cols if 
                       not col.startswith('src_ip_') and 
                       not col.startswith('dst_ip_') and
                       col not in ['start_time', 'end_time', label_col]]
        
        plt.figure(figsize=(12, 10))
        correlation_matrix = df[numeric_cols].corr()
        
        # 绘制热力图
        sns.heatmap(correlation_matrix, 
                   annot=True, 
                   cmap='coolwarm', 
                   center=0,
                   fmt='.2f',
                   square=True)
        
        plt.title('Feature Correlation Matrix')
        self.save_plot('correlation_matrix')
        
    def plot_feature_importance(self, feature_names, importance_scores):
        """绘制特征重要性图
        
        Args:
            feature_names (list): 特征名列表
            importance_scores (list): 特征重要性分数列表
        """
        plt.figure(figsize=(10, 6))
        importance_df = pd.DataFrame({
            'Feature': feature_names,
            'Importance': importance_scores
        }).sort_values('Importance', ascending=True)
        
        sns.barplot(data=importance_df, y='Feature', x='Importance')
        plt.title('Feature Importance')
        plt.xlabel('Importance Score')
        self.save_plot('feature_importance')
        
    def plot_scatter_matrix(self, df, features=None, label_col='label'):
        """绘制散点矩阵
        
        Args:
            df (pd.DataFrame): 包含特征的数据框
            features (list): 要绘制的特征列表，如果为None则使用主要的流量特征
            label_col (str): 标签列名
        """
        if features is None:
            # 选择主要的流量特征
            features = [
                'duration',
                'bytes_sent',
                'bytes_received',
                'packets_sent',
                'packets_received',
                'avg_payload_length',
                'avg_interarrival_time'
            ]
            # 确保所选特征在数据框中存在
            features = [f for f in features if f in df.columns]
        
        if len(features) > 4:
            features = features[:4]  # 限制最多4个特征，否则图表会太密集
            
        plt.figure(figsize=(15, 15))
        sns.pairplot(df, vars=features, hue=label_col if label_col in df.columns else None)
        self.save_plot('scatter_matrix')
        
    def plot_clusters(self, df, n_clusters=3):
        """使用K-means对流量进行聚类并可视化
        
        Args:
            df (pd.DataFrame): 包含特征的数据框
            n_clusters (int): 聚类数量
        """
        # 选择用于聚类的特征
        cluster_features = [
            'duration',
            'bytes_sent',
            'bytes_received',
            'packets_sent',
            'packets_received',
            'avg_payload_length',
            'avg_interarrival_time',
            'retransmission_count',
            'number_of_push_packets'
        ]
        
        # 确保所选特征在数据框中存在
        cluster_features = [f for f in cluster_features if f in df.columns]
        
        if len(cluster_features) < 2:
            print("没有足够的特征用于聚类")
            return
            
        # 准备数据
        X = df[cluster_features].copy()
        
        # 标准化
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # 使用PCA降维到2维
        pca = PCA(n_components=2)
        X_pca = pca.fit_transform(X_scaled)
        
        # 聚类
        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        clusters = kmeans.fit_predict(X_scaled)
        
        # 创建可视化
        plt.figure(figsize=(12, 8))
        
        # 绘制散点图
        scatter = plt.scatter(X_pca[:, 0], X_pca[:, 1], c=clusters, cmap='viridis')
        plt.colorbar(scatter)
        
        # 添加聚类中心
        centers_pca = pca.transform(scaler.transform(kmeans.cluster_centers_))
        plt.scatter(centers_pca[:, 0], centers_pca[:, 1], 
                   c='red', marker='x', s=200, linewidths=3, 
                   label='Cluster Centers')
        
        # 添加标题和标签
        plt.title('流量聚类分析 (PCA降维可视化)')
        plt.xlabel(f'主成分1 (解释方差: {pca.explained_variance_ratio_[0]:.2%})')
        plt.ylabel(f'主成分2 (解释方差: {pca.explained_variance_ratio_[1]:.2%})')
        plt.legend()
        
        self.save_plot('traffic_clusters')
        
        # 分析每个聚类的特征
        cluster_stats = []
        for i in range(n_clusters):
            cluster_data = df[clusters == i]
            stats = cluster_data[cluster_features].mean()
            cluster_stats.append(stats)
        
        # 创建聚类特征分析图
        plt.figure(figsize=(15, 8))
        cluster_stats_df = pd.DataFrame(cluster_stats, 
                                      columns=cluster_features)
        
        # 标准化特征值以便比较
        cluster_stats_normalized = (cluster_stats_df - cluster_stats_df.min()) / \
                                 (cluster_stats_df.max() - cluster_stats_df.min())
        
        # 绘制热力图
        sns.heatmap(cluster_stats_normalized, 
                    annot=cluster_stats_df.round(2), 
                    fmt='.2f',
                    cmap='YlOrRd')
        plt.title('聚类特征分析')
        plt.xlabel('特征')
        plt.ylabel('聚类')
        
        self.save_plot('cluster_features_analysis')
        
        return clusters
        
    def plot_time_series(self, df, time_col, feature_cols, label_col='label'):
        """绘制时间序列图
        
        Args:
            df (pd.DataFrame): 包含特征的数据框
            time_col (str): 时间列名
            feature_cols (list): 要绘制的特征列表
            label_col (str): 标签列名
        """
        plt.figure(figsize=(15, 5 * len(feature_cols)))
        
        for i, feature in enumerate(feature_cols, 1):
            plt.subplot(len(feature_cols), 1, i)
            
            if label_col in df.columns:
                # 分别绘制正常和异常流量
                normal = df[df[label_col]==0]
                anomaly = df[df[label_col]==1]
                
                plt.scatter(normal[time_col], normal[feature], 
                          label='Normal', alpha=0.5, s=20)
                plt.scatter(anomaly[time_col], anomaly[feature], 
                          label='Anomaly', alpha=0.5, s=20, color='red')
            else:
                plt.plot(df[time_col], df[feature], alpha=0.5)
                
            plt.title(f'Time Series of {feature}')
            plt.xlabel('Time')
            plt.ylabel(feature)
            plt.legend()
            
        plt.tight_layout()
        self.save_plot('time_series')
