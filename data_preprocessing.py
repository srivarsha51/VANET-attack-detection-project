import pandas as pd
import numpy as np
from sklearn.preprocessing import RobustScaler, LabelEncoder
from sklearn.impute import SimpleImputer
import os

class DataPreprocessor:
    def __init__(self):
        self.scaler = RobustScaler()
        self.label_encoders = {}
        self.feature_columns = None
        self.fitted = False
        self.target_scalers = {}
        self.target_selectors = {}
        self.target_pcas = {}
        self.expected_columns = None
    
    def fit(self, data):
        """Fit the preprocessor on training data"""
        # Store the expected columns from training data
        self.expected_columns = [col for col in data.columns if col not in [
            'is_malicious', 'denial_of_service', 'sybil_attack_attempts', 'blackhole_attack_attempts', 'node_id'
        ]]
        
        # Select only numeric columns for features
        numeric_columns = data[self.expected_columns].select_dtypes(include=[np.number]).columns.tolist()
        self.feature_columns = numeric_columns
        
        # Fit scaler on numeric features
        feature_data = data[self.feature_columns]
        feature_data = feature_data.fillna(feature_data.mean())  # Handle missing values
        self.scaler.fit(feature_data)
        
        self.fitted = True
        return self
    
    def transform(self, data):
        """Transform data using fitted preprocessor"""
        if not self.fitted:
            raise ValueError("Preprocessor must be fitted before transform")
        
        # Ensure we have the right columns
        if isinstance(data, pd.DataFrame):
            # Remove node_id if it exists
            data_clean = data.copy()
            if 'node_id' in data_clean.columns:
                data_clean = data_clean.drop('node_id', axis=1)
            
            # Select only the feature columns that exist in both training and test data
            available_features = [col for col in self.feature_columns if col in data_clean.columns]
            missing_features = [col for col in self.feature_columns if col not in data_clean.columns]
            
            # Add missing features with default values (mean from training)
            for col in missing_features:
                data_clean[col] = 0.0  # Default value
            
            feature_data = data_clean[self.feature_columns].copy()
        else:
            feature_data = pd.DataFrame(data, columns=self.feature_columns)
        
        # Handle missing values
        feature_data = feature_data.fillna(0.0)
        
        # Scale features
        scaled_data = self.scaler.transform(feature_data)
        
        return scaled_data
    
    def fit_transform(self, data):
        """Fit and transform data in one step"""
        return self.fit(data).transform(data)
    
    def get_feature_names(self):
        """Get the names of features used by the preprocessor"""
        return self.feature_columns
    
    def transform_for_target(self, data, target_name):
        """Transform data for a specific target with its preprocessing pipeline"""
        # First apply general preprocessing
        scaled_data = self.transform(data)
        
        # For now, skip target-specific feature engineering to avoid dimension mismatch
        # The models will be retrained with consistent preprocessing
        return scaled_data