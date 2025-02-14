import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path
import os
import logging
from datetime import datetime
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import silhouette_score
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TrafficVisualizer:
    def __init__(self, save_dir='visualizations', interactive=True):
        """Initialize the visualizer
        
        Args:
            save_dir (str): Directory to save visualization plots
            interactive (bool): Whether to use interactive Plotly plots
        """
        self.save_dir = save_dir
        self.interactive = interactive
        
        # Create directories for both static and interactive visualizations
        self.static_dir = os.path.join(save_dir, 'static')
        self.interactive_dir = os.path.join(save_dir, 'interactive')
        os.makedirs(self.static_dir, exist_ok=True)
        os.makedirs(self.interactive_dir, exist_ok=True)
        
        # Set plot style
        if not interactive:
            plt.style.use('seaborn')
            sns.set_palette("husl")
        
        # Initialize scalers
        self.standard_scaler = StandardScaler()
        self.minmax_scaler = MinMaxScaler()
        
    def save_plot(self, name, fig=None, interactive=None):
        """保存图表
        
        Args:
            name (str): 图表名称
            fig: 图表对象 (plt.Figure 或 plotly.Figure)
            interactive (bool): 是否为交互式图表，如果为None则使用类的默认设置
        """
        if fig is None:
            logger.debug(f"No figure provided for {name}, skipping save")
            return
            
        if interactive is None:
            interactive = self.interactive
            
        try:
            if interactive:
                if not isinstance(fig, go.Figure):
                    logger.warning(f"Expected plotly.Figure for interactive plot, got {type(fig)}")
                    return
                save_path = os.path.join(self.interactive_dir, f"{name}.html")
                fig.write_html(save_path)
                logger.debug(f"Saved interactive plot to {save_path}")
            else:
                save_path = os.path.join(self.static_dir, f"{name}.png")
                if isinstance(fig, plt.Figure):
                    fig.savefig(save_path, dpi=300, bbox_inches='tight')
                else:
                    plt.figure()
                    plt.tight_layout()
                    plt.savefig(save_path, dpi=300, bbox_inches='tight')
                plt.close()
                logger.debug(f"Saved static plot to {save_path}")
        except Exception as e:
            logger.error(f"Error saving plot {name}: {str(e)}")
        
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
        
    def plot_dimensionality_reduction(self, df, method='tsne', label_col=None, perplexity=30, n_components=2):
        """Visualize data distribution using dimensionality reduction
        
        Args:
            df (pd.DataFrame): Input DataFrame
            method (str): Reduction method, 'tsne' or 'pca'
            label_col (str): Label column for color coding
            perplexity (int): t-SNE perplexity parameter
            n_components (int): Number of components (2 or 3)
        """
        try:
            # Select numeric features and remove low variance ones
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            numeric_cols = [col for col in numeric_cols if 
                           not col.startswith('src_ip_') and 
                           not col.startswith('dst_ip_') and
                           col not in ['start_time', 'end_time'] and
                           (label_col is None or col != label_col)]
            
            # Calculate feature variances
            variances = df[numeric_cols].var()
            selected_features = variances[variances > 1e-10].index.tolist()
            
            if len(selected_features) == 0:
                logger.warning("No valid numeric features found for dimensionality reduction")
                return
            
            # Prepare data
            X = df[selected_features].copy()
            X_scaled = self.standard_scaler.fit_transform(X)
            
            # Dimensionality reduction
            if method.lower() == 'tsne':
                reducer = TSNE(
                    n_components=n_components,
                    perplexity=min(perplexity, len(X) - 1),
                    random_state=42,
                    n_iter=1000,
                    init='pca'
                )
                X_reduced = reducer.fit_transform(X_scaled)
                explained_var = None
            else:  # PCA
                reducer = PCA(n_components=n_components)
                X_reduced = reducer.fit_transform(X_scaled)
                explained_var = reducer.explained_variance_ratio_
            
            if self.interactive:
                return self._plot_interactive_reduction(X_reduced, df, label_col, method, explained_var, n_components)
            else:
                return self._plot_static_reduction(X_reduced, df, label_col, method, explained_var, n_components)
                
        except Exception as e:
            logger.error(f"Error in dimensionality reduction: {str(e)}")
            raise
        
    def _plot_interactive_reduction(self, X_reduced, df, label_col, method, explained_var, n_components):
        """Create interactive plot using Plotly
        
        Args:
            X_reduced (np.array): Reduced dimensionality data
            df (pd.DataFrame): Original dataframe
            label_col (str): Column name for labels
            method (str): Reduction method used
            explained_var (np.array): Explained variance ratios for PCA
            n_components (int): Number of components
        """
        if n_components == 2:
            fig = go.Figure()
            
            if label_col is not None and label_col in df.columns:
                for label in sorted(df[label_col].unique()):
                    mask = df[label_col] == label
                    fig.add_trace(go.Scatter(
                        x=X_reduced[mask, 0],
                        y=X_reduced[mask, 1],
                        mode='markers',
                        name=f'Class {label}',
                        marker=dict(size=8, opacity=0.7)
                    ))
            else:
                fig.add_trace(go.Scatter(
                    x=X_reduced[:, 0],
                    y=X_reduced[:, 1],
                    mode='markers',
                    marker=dict(size=8, opacity=0.7)
                ))
            
            title = f'{method.upper()} Visualization'
            if method == 'pca' and explained_var is not None:
                title += f'\nExplained variance: {explained_var[0]:.2%}, {explained_var[1]:.2%}'
            
            fig.update_layout(
                title=title,
                xaxis_title='First Component',
                yaxis_title='Second Component',
                template='plotly_white',
                showlegend=True
            )
            
        else:  # 3D plot
            if label_col is not None and label_col in df.columns:
                fig = px.scatter_3d(
                    x=X_reduced[:, 0],
                    y=X_reduced[:, 1],
                    z=X_reduced[:, 2],
                    color=df[label_col],
                    opacity=0.7
                )
            else:
                fig = px.scatter_3d(
                    x=X_reduced[:, 0],
                    y=X_reduced[:, 1],
                    z=X_reduced[:, 2],
                    opacity=0.7
                )
            
            title = f'3D {method.upper()} Visualization'
            if method == 'pca' and explained_var is not None:
                title += f'\nExplained variance: {explained_var[0]:.2%}, {explained_var[1]:.2%}, {explained_var[2]:.2%}'
            
            fig.update_layout(
                title=title,
                scene=dict(
                    xaxis_title='First Component',
                    yaxis_title='Second Component',
                    zaxis_title='Third Component'
                ),
                template='plotly_white'
            )
        
        # Save interactive plot
        self.save_plot(f'{method}_visualization', fig, interactive=True)
        
        return fig
    
    def _plot_static_reduction(self, X_reduced, df, label_col, method, explained_var, n_components):
        """Create static plot using Matplotlib
        
        Args:
            X_reduced (np.array): Reduced dimensionality data
            df (pd.DataFrame): Original dataframe
            label_col (str): Column name for labels
            method (str): Reduction method used
            explained_var (np.array): Explained variance ratios for PCA
            n_components (int): Number of components
        """
        if n_components == 2:
            fig = plt.figure(figsize=(12, 8))
            
            if label_col is not None and label_col in df.columns:
                unique_labels = sorted(df[label_col].unique())
                colors = plt.cm.viridis(np.linspace(0, 1, len(unique_labels)))
                
                for label, color in zip(unique_labels, colors):
                    mask = df[label_col] == label
                    plt.scatter(X_reduced[mask, 0], X_reduced[mask, 1],
                               c=[color], label=f'Class {label}',
                               alpha=0.7)
                plt.legend()
            else:
                plt.scatter(X_reduced[:, 0], X_reduced[:, 1],
                           alpha=0.7, c='blue')
            
            title = f'{method.upper()} Visualization'
            if method == 'pca' and explained_var is not None:
                title += f'\nExplained variance: {explained_var[0]:.2%}, {explained_var[1]:.2%}'
            
            plt.title(title)
            plt.xlabel('First Component')
            plt.ylabel('Second Component')
            plt.grid(True, linestyle='--', alpha=0.3)
            
            # Save 2D static plot
            self.save_plot(f'{method}_visualization_2d', fig, interactive=False)
            
        else:  # 3D plot
            fig = plt.figure(figsize=(12, 8))
            ax = fig.add_subplot(111, projection='3d')
            
            if label_col is not None and label_col in df.columns:
                unique_labels = sorted(df[label_col].unique())
                colors = plt.cm.viridis(np.linspace(0, 1, len(unique_labels)))
                
                for label, color in zip(unique_labels, colors):
                    mask = df[label_col] == label
                    ax.scatter(X_reduced[mask, 0],
                              X_reduced[mask, 1],
                              X_reduced[mask, 2],
                              c=[color],
                              label=f'Class {label}',
                              alpha=0.7)
                ax.legend()
            else:
                ax.scatter(X_reduced[:, 0],
                          X_reduced[:, 1],
                          X_reduced[:, 2],
                          alpha=0.7,
                          c='blue')
            
            title = f'3D {method.upper()} Visualization'
            if method == 'pca' and explained_var is not None:
                title += f'\nExplained variance: {explained_var[0]:.2%}, {explained_var[1]:.2%}, {explained_var[2]:.2%}'
            
            ax.set_title(title)
            ax.set_xlabel('First Component')
            ax.set_ylabel('Second Component')
            ax.set_zlabel('Third Component')
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.save_plot(f'{method}_visualization_{timestamp}')
        
    def plot_anomaly_scores(self, scores, threshold=None, interactive=None):
        """Visualize anomaly scores distribution
        
        Args:
            scores (np.array): Array of anomaly scores
            threshold (float): Optional threshold for anomaly detection
            interactive (bool): Whether to use interactive plot (overrides class setting)
        """
        interactive = self.interactive if interactive is None else interactive
        
        if interactive:
            fig = go.Figure()
            
            # Add histogram of scores
            fig.add_trace(go.Histogram(
                x=scores,
                name='Score Distribution',
                nbinsx=50,
                opacity=0.7
            ))
            
            # Add threshold line if provided
            if threshold is not None:
                fig.add_vline(
                    x=threshold,
                    line_dash="dash",
                    line_color="red",
                    annotation_text="Anomaly Threshold",
                    annotation_position="top right"
                )
            
            fig.update_layout(
                title='Anomaly Score Distribution',
                xaxis_title='Anomaly Score',
                yaxis_title='Count',
                template='plotly_white',
                showlegend=True
            )
            
            # Save interactive plot
            self.save_plot('anomaly_scores', fig, interactive=True)
            
            return fig
            
        else:
            fig = plt.figure(figsize=(12, 6))
            plt.hist(scores, bins=50, alpha=0.7, color='blue')
            
            # Save static plot
            self.save_plot('anomaly_scores', fig, interactive=False)
            
            if threshold is not None:
                plt.axvline(x=threshold, color='red', linestyle='--',
                           label='Anomaly Threshold')
                plt.legend()
            
            plt.title('Anomaly Score Distribution')
            plt.xlabel('Anomaly Score')
            plt.ylabel('Count')
            plt.grid(True, linestyle='--', alpha=0.3)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.save_plot(f'anomaly_scores_{timestamp}')
    def plot_cluster_analysis(self, df, clusters, features, interactive=None):
        """Visualize cluster analysis results
        
        Args:
            df (pd.DataFrame): Input DataFrame
            clusters (np.array): Cluster assignments
            features (list): Features used for clustering
            interactive (bool): Whether to use interactive plot (overrides class setting)
        """
        interactive = self.interactive if interactive is None else interactive
        n_clusters = len(np.unique(clusters))
        
        # Calculate cluster statistics
        cluster_stats = []
        for i in range(n_clusters):
            cluster_data = df[clusters == i]
            stats = cluster_data[features].mean()
            cluster_stats.append(stats)
        
        cluster_stats_df = pd.DataFrame(cluster_stats, columns=features)
        cluster_stats_normalized = self.minmax_scaler.fit_transform(cluster_stats_df)
        cluster_stats_normalized = pd.DataFrame(cluster_stats_normalized, columns=features)
        
        # Calculate silhouette scores
        try:
            silhouette_avg = silhouette_score(df[features], clusters)
            logger.info(f'Average silhouette score: {silhouette_avg:.3f}')
        except Exception as e:
            logger.warning(f'Could not calculate silhouette score: {str(e)}')
            silhouette_avg = None
        
        if interactive:
            # Create subplot figure
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=(
                    'Cluster Feature Analysis',
                    'Cluster Size Distribution',
                    'Feature Importance by Cluster',
                    'Cluster Separation (2D PCA)'
                )
            )
            
            # 1. Heatmap of cluster characteristics
            heatmap = go.Heatmap(
                z=cluster_stats_normalized.values,
                x=features,
                y=[f'Cluster {i}' for i in range(n_clusters)],
                colorscale='YlOrRd',
                showscale=True
            )
            fig.add_trace(heatmap, row=1, col=1)
            
            # 2. Cluster size distribution
            cluster_sizes = pd.Series(clusters).value_counts().sort_index()
            bar = go.Bar(
                x=[f'Cluster {i}' for i in range(n_clusters)],
                y=cluster_sizes.values,
                marker_color='lightblue'
            )
            fig.add_trace(bar, row=1, col=2)
            
            # 3. Feature importance by cluster
            feature_variance = cluster_stats_df.var()
            feature_importance = go.Bar(
                x=features,
                y=feature_variance.values,
                marker_color='lightgreen'
            )
            fig.add_trace(feature_importance, row=2, col=1)
            
            # 4. PCA visualization of clusters
            pca = PCA(n_components=2)
            X_pca = pca.fit_transform(self.standard_scaler.fit_transform(df[features]))
            
            for i in range(n_clusters):
                mask = clusters == i
                scatter = go.Scatter(
                    x=X_pca[mask, 0],
                    y=X_pca[mask, 1],
                    mode='markers',
                    name=f'Cluster {i}',
                    marker=dict(size=8)
                )
                fig.add_trace(scatter, row=2, col=2)
            
            # Update layout
            fig.update_layout(
                height=800,
                width=1200,
                showlegend=True,
                title={
                    'text': f'Cluster Analysis Overview (Silhouette Score: {silhouette_avg:.3f if silhouette_avg else "N/A"})',
                    'y':0.95
                },
                template='plotly_white'
            )
            
            # Save interactive plot
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            html_path = os.path.join(self.save_dir, f'cluster_analysis_{timestamp}.html')
            fig.write_html(html_path)
            
            return fig
            
        else:
            # Create static plots using matplotlib
            fig = plt.figure(figsize=(20, 15))
            
            # 1. Heatmap of cluster characteristics
            plt.subplot(2, 2, 1)
            sns.heatmap(
                cluster_stats_normalized,
                annot=cluster_stats_df.round(2),
                fmt='.2f',
                cmap='YlOrRd'
            )
            plt.title('Cluster Feature Analysis')
            plt.xlabel('Features')
            plt.ylabel('Clusters')
            
            # 2. Cluster size distribution
            plt.subplot(2, 2, 2)
            cluster_sizes = pd.Series(clusters).value_counts().sort_index()
            cluster_sizes.plot(kind='bar')
            plt.title('Cluster Size Distribution')
            plt.xlabel('Cluster')
            plt.ylabel('Number of Samples')
            
            # 3. Feature importance by cluster
            plt.subplot(2, 2, 3)
            feature_variance = cluster_stats_df.var()
            feature_variance.plot(kind='bar')
            plt.title('Feature Importance by Cluster')
            plt.xlabel('Features')
            plt.ylabel('Variance')
            plt.xticks(rotation=45)
            
            # 4. PCA visualization of clusters
            plt.subplot(2, 2, 4)
            pca = PCA(n_components=2)
            X_pca = pca.fit_transform(self.standard_scaler.fit_transform(df[features]))
            
            for i in range(n_clusters):
                mask = clusters == i
                plt.scatter(X_pca[mask, 0], X_pca[mask, 1],
                           label=f'Cluster {i}', alpha=0.7)
            
            plt.title('Cluster Separation (2D PCA)')
            plt.xlabel('First Principal Component')
            plt.ylabel('Second Principal Component')
            plt.legend()
            
            plt.suptitle(
                f'Cluster Analysis Overview\nSilhouette Score: {silhouette_avg:.3f if silhouette_avg else "N/A"}',
                fontsize=16
            )
            
            plt.tight_layout()
            
            # Save static plot
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.save_plot(f'cluster_analysis_{timestamp}')
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
