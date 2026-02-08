import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file
from werkzeug.utils import secure_filename
import base64
from io import BytesIO
import json

from ml_models import MLModelTrainer
from data_preprocessing import DataPreprocessor

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "your-secret-key-here")

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create necessary directories
os.makedirs('models', exist_ok=True)
os.makedirs('results', exist_ok=True)
os.makedirs('uploads', exist_ok=True)

# Initialize components
preprocessor = DataPreprocessor()
ml_trainer = MLModelTrainer()

# Global variables to store data and models
current_data = None
trained_models = {}
performance_metrics = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def plot_to_base64(fig):
    """Convert matplotlib figure to base64 string"""
    img = BytesIO()
    fig.savefig(img, format='png', bbox_inches='tight', dpi=150)
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()
    plt.close(fig)
    return plot_url

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/upload_dataset', methods=['POST'])
def upload_dataset():
    global current_data
    
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('home'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('home'))
    
    if file and file.filename and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Load and preprocess data
            current_data = pd.read_csv(filepath)
            flash(f'Dataset loaded successfully! Shape: {current_data.shape}')
            
            # Preprocess the data
            preprocessor.fit(current_data)
            
            return redirect(url_for('eda'))
        except Exception as e:
            flash(f'Error loading dataset: {str(e)}')
            return redirect(url_for('home'))
    else:
        flash('Invalid file type. Please upload a CSV file.')
        return redirect(url_for('home'))

@app.route('/eda')
def eda():
    global current_data
    
    if current_data is None:
        flash('Please upload a dataset first')
        return redirect(url_for('home'))
    
    try:
        # Generate EDA plots
        eda_plots = generate_eda_plots(current_data)
        return render_template('eda.html', plots=eda_plots, data_info=get_data_info(current_data))
    except Exception as e:
        flash(f'Error generating EDA: {str(e)}')
        return redirect(url_for('home'))

def generate_eda_plots(df):
    """Generate EDA plots and return as base64 strings"""
    plots = {}
    
    # Set style
    plt.style.use('default')
    sns.set_palette("husl")
    
    # 1. Distribution of target variables
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('Target Variable Distributions', fontsize=16, fontweight='bold')
    
    if 'denial_of_service' in df.columns:
        targets = ['denial_of_service', 'sybil_attack_attempts', 'blackhole_attack_attempts']
        df_melted = df[targets].melt(var_name='Attack Type', value_name='Status')
        sns.countplot(data=df_melted, x='Status', hue='Attack Type', ax=axes[0,0])
        axes[0,0].set_title('Attack Types Distribution')
        axes[0,0].set_xlabel('Status (0=No, 1=Yes)')
        axes[0,0].set_ylabel('Count')
        axes[0,0].legend(title='Attack Type')

    # denial_of_service distribution
    if 'denial_of_service' in df.columns:
        sns.countplot(data=df, x='denial_of_service', ax=axes[0,1])
        axes[0,1].set_title('denial_of_service Distribution')
        axes[0,1].set_xlabel('denial_of_service Level')
    
    # sybil_attack_attempts distribution
    if 'sybil_attack_attempts' in df.columns:
        sns.countplot(data=df, x='sybil_attack_attempts', ax=axes[1,0])
        axes[1,0].set_title('sybil_attack_attempts Distribution')
        axes[1,0].set_xlabel('sybil_attack_attempts Level')
    
    # blackhole_attack_attempts distribution
    if 'blackhole_attack_attempts' in df.columns:
        sns.countplot(data=df, x='blackhole_attack_attempts', ax=axes[1,1])
        axes[1,1].set_title('blackhole_attack_attempts Distribution')
        axes[1,1].set_xlabel('blackhole_attack_attempts Level')
    
    plt.tight_layout()
    plots['target_distributions'] = plot_to_base64(fig)
    
    # 2. Feature correlations
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 1:
        fig, ax = plt.subplots(figsize=(12, 10))
        correlation_matrix = df[numeric_cols].corr()
        sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0, ax=ax)
        ax.set_title('Feature Correlation Heatmap', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plots['correlation_heatmap'] = plot_to_base64(fig)
    
    # 3. Signal strength vs malicious nodes
    if 'signal_strength' in df.columns and 'is_malicious' in df.columns:
        fig, ax = plt.subplots(figsize=(10, 6))
        sns.boxplot(data=df, x='is_malicious', y='signal_strength', ax=ax)
        ax.set_title('Signal Strength vs Malicious Nodes', fontsize=14, fontweight='bold')
        ax.set_xlabel('is_malicious (0=Normal, 1=Malicious)')
        plt.tight_layout()
        plots['signal_strength_boxplot'] = plot_to_base64(fig)
    
    # 4. Latency distribution
    if 'latency' in df.columns and 'is_malicious' in df.columns:
        fig, ax = plt.subplots(figsize=(10, 6))
        sns.violinplot(data=df, x='is_malicious', y='latency', ax=ax)
        ax.set_title('Latency Distribution by Malicious Status', fontsize=14, fontweight='bold')
        ax.set_xlabel('is_malicious (0=Normal, 1=Malicious)')
        plt.tight_layout()
        plots['latency_violin'] = plot_to_base64(fig)
    
    return plots

def get_data_info(df):
    """Get basic information about the dataset"""
    info = {
        'shape': df.shape,
        'columns': list(df.columns),
        'missing_values': df.isnull().sum().to_dict(),
        'data_types': df.dtypes.to_dict()
    }
    return info

@app.route('/train_models', methods=['POST'])
def train_models():
    global current_data, trained_models, performance_metrics
    
    if current_data is None:
        return jsonify({'error': 'No dataset loaded'})
    
    try:
        # Get selected algorithms
        request_data = request.get_json() or {}
        selected_algorithms = request_data.get('algorithms', ['knn', 'svc', 'nb', 'STT'])
        
        # Train models for all targets
        targets = ['is_malicious', 'denial_of_service', 'sybil_attack_attempts', 'blackhole_attack_attempts']
        
        results = {}
        for target in targets:
            if target in current_data.columns:
                target_results = ml_trainer.train_all_models(
                    current_data, target, selected_algorithms
                )
                results[target] = target_results
        
        trained_models = ml_trainer.models
        performance_metrics = results
        
        return jsonify({'success': True, 'results': results})
    
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/performance')
def performance():
    global performance_metrics
    
    if not performance_metrics:
        flash('Please train models first')
        return redirect(url_for('home'))
    
    return render_template('performance.html', metrics=performance_metrics)

@app.route('/predict_single')
def predict_single():
    return render_template('predict_single.html')

@app.route('/predict_single_submit', methods=['POST'])
def predict_single_submit():
    global trained_models
    
    try:
        # Get form data
        input_data = {}
        for key, value in request.form.items():
            try:
                input_data[key] = float(value)
            except ValueError:
                input_data[key] = value
        
        input_df = pd.DataFrame([input_data])
        predictions = {}
        probabilities = {}
        
        targets = ['denial_of_service', 'sybil_attack_attempts', 'blackhole_attack_attempts']
        
        for target in targets:
            if target in trained_models:
                target_predictions = {}
                target_probabilities = {}
                
                # Load target-specific scaler from models folder
                scaler_path = os.path.join('models', f'{target}_scaler.joblib')
                if os.path.exists(scaler_path):
                    from joblib import load
                    scaler = load(scaler_path)
                    input_scaled = scaler.transform(input_df)
                    print("..........")
                else:
                    input_scaled = input_df.values  # fallback
                    print("..........")

                
                for algo_name, model in trained_models[target].items():
                    try:
                        pred = model.predict(input_scaled)[0]
                        
                        target_predictions[algo_name] = int(pred)
                        target_probabilities[algo_name] = None  # Always None
                    except Exception as e:
                        print(f"Prediction error for {target}_{algo_name}: {e}")
                        target_predictions[algo_name] = 0
                        target_probabilities[algo_name] = None
                
                predictions[target] = target_predictions
                probabilities[target] = target_probabilities
        
        return render_template('predict_single.html', 
                               predictions=predictions, 
                               probabilities=probabilities,
                               input_data=input_data)
    
    except Exception as e:
        flash(f'Error making prediction: {str(e)}')
        return redirect(url_for('predict_single'))



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
