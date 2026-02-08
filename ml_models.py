import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from imblearn.over_sampling import SMOTE, ADASYN
from imblearn.combine import SMOTETomek
from joblib import dump, load
from sklearn.utils import resample

class Stacked_Tao_Tree_classifier:
    def __init__(self, n_estimators=1, max_features="sqrt", random_state=42):
        self.n_estimators = n_estimators
        self.max_features = max_features
        self.random_state = random_state
        self.trees = []
        np.random.seed(self.random_state)

    def fit(self, X, y):
        """Fit Random Forest Classifier logic"""
        n_samples, n_features = X.shape
        self.trees = []

        for i in range(self.n_estimators):
            # Bootstrap sampling
            X_sample, y_sample = resample(X, y, replace=True, random_state=self.random_state + i)
            
            # Random subset of features
            if self.max_features == "sqrt":
                n_sub_features = int(np.sqrt(n_features))
            elif self.max_features == "log2":
                n_sub_features = int(np.log2(n_features))
            else:
                n_sub_features = n_features
            
            feature_indices = np.random.choice(n_features, n_sub_features, replace=False)

            tree = RandomForestClassifier()
            tree.fit(X, y)
            
            self.trees.append((tree, feature_indices))

    def predict(self, X):
        """Majority voting for classification"""
        preds = []
        for tree, feature_indices in self.trees:
            preds.append(tree.predict(X))
        
        preds = np.array(preds).T  # shape: (n_samples, n_trees)
        
        # Majority vote
        final_preds = [np.bincount(row).argmax() for row in preds]
        return np.array(final_preds)
    
        
class MLModelTrainer:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.model_dir = 'models'
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Define class mappings for different targets
        self.class_mappings = {
            'denial_of_service': {0: 'Normal', 1: 'Medium', 2: 'High', 3: 'Very High'},
            'sybil_attack_attempts': {0: 'Normal', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Very High'},
            'blackhole_attack_attempts': {0: 'Normal', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Very High'}
        }
    
    def encode_target_variable(self, y, target_name):
        """Encode target variable based on its type"""
        if target_name == 'is_malicious':
            return y
        elif target_name in ['denial_of_service', 'sybil_attack_attempts', 'blackhole_attack_attempts']:
            if target_name == 'denial_of_service':
                return pd.cut(y, bins=[-1, 1, 2, 3, float('inf')], labels=[0, 1, 2, 3])
            else:
                return pd.cut(y, bins=[-1, 0, 1, 2, 3, float('inf')], labels=[0, 1, 2, 3, 4])
        return y
    
    def get_algorithms(self):
        """Return dictionary of optimized algorithms with hyperparameters"""
        return {
            'knn': KNeighborsClassifier(),
            'nb': GaussianNB(),
            'STT': Stacked_Tao_Tree_classifier(),
            'svc': SVC()
        }
    
    def train_model(self, X_train, y_train, algorithm_name, target_name):
        """Train a single model with advanced data balancing"""
        algorithms = self.get_algorithms()
        if algorithm_name not in algorithms:
            raise ValueError(f"Unknown algorithm: {algorithm_name}")
        
        model = algorithms[algorithm_name]
        
        # Advanced data balancing
        unique_classes = np.unique(y_train)
        if len(unique_classes) == 2:
            balancer = SMOTETomek(random_state=42, smote=SMOTE(random_state=42))
        else:
            balancer = ADASYN(random_state=42, n_neighbors=min(5, len(y_train)//10))
        
        try:
            X_train_balanced, y_train_balanced = balancer.fit_resample(X_train, y_train)
        except Exception:
            balancer = SMOTE(random_state=42)
            X_train_balanced, y_train_balanced = balancer.fit_resample(X_train, y_train)
        
        model.fit(X_train_balanced, y_train_balanced)
        return model
    
    def evaluate_model(self, model, X_test, y_test, algorithm_name, target_name):
        """Evaluate a trained model"""
        y_pred = model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        class_names = [self.class_mappings[target_name].get(i, str(i)) for i in sorted(np.unique(y_test))]
        report = classification_report(y_test, y_pred, target_names=class_names, output_dict=True, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)
        
        return {
            'algorithm': algorithm_name,
            'accuracy': accuracy * 100,
            'precision': precision * 100,
            'recall': recall * 100,
            'f1_score': f1 * 100,
            'classification_report': report,
            'confusion_matrix': cm.tolist(),
            'class_names': class_names
        }
    
    def train_all_models(self, data, target_name, selected_algorithms=None):
        """Train all models for a specific target"""
        if selected_algorithms is None:
            selected_algorithms = ['knn', 'svc', 'nb', 'STT']
        
        if target_name not in data.columns:
            raise ValueError(f"Target column '{target_name}' not found in data")
        
        numeric_columns = data.select_dtypes(include=[np.number]).columns.tolist()
        if target_name not in numeric_columns:
            numeric_columns.append(target_name)
        
        data_numeric = data[numeric_columns]
        
        # Drop all other target columns from X
        target_columns = ['denial_of_service', 'sybil_attack_attempts', 'blackhole_attack_attempts']
        target_columns.remove(target_name)  # keep only the current target
        X = data_numeric.drop(columns=[target_name] + target_columns)
        
        y = data_numeric[target_name]
        
        y_encoded = self.encode_target_variable(y, target_name)
        mask = ~pd.isna(y_encoded)
        X = X[mask]
        y_encoded = y_encoded[mask]
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        scaler = RobustScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        scaler_path = os.path.join(self.model_dir, f'{target_name}_scaler.joblib')
        dump(scaler, scaler_path)
        self.scalers[target_name] = scaler
        
        results, target_models = {}, {}
        for algo_name in selected_algorithms:
            model_path = os.path.join(self.model_dir, f'{target_name}_{algo_name}.joblib')
            if os.path.exists(model_path):
                model = load(model_path)
                print(f"Loaded existing model: {target_name}_{algo_name}")
            else:
                model = self.train_model(X_train_scaled, y_train, algo_name, target_name)
                dump(model, model_path)
                print(f"Trained and saved new model: {target_name}_{algo_name}")
            
            evaluation = self.evaluate_model(model, X_test_scaled, y_test, algo_name, target_name)
            results[algo_name] = evaluation
            target_models[algo_name] = model
        
        if target_name not in self.models:
            self.models[target_name] = {}
        self.models[target_name].update(target_models)
        
        return results

    
    def load_all_models(self):
        """Load all existing models from disk"""
        targets = ['denial_of_service', 'sybil_attack_attempts', 'blackhole_attack_attempts']
        algorithms = ['knn', 'nb', 'STT', 'svc']
        
        for target in targets:
            scaler_path = os.path.join(self.model_dir, f'{target}_scaler.joblib')
            if os.path.exists(scaler_path):
                self.scalers[target] = load(scaler_path)
            
            for algo in algorithms:
                model_path = os.path.join(self.model_dir, f'{target}_{algo}.joblib')
                if os.path.exists(model_path):
                    if target not in self.models:
                        self.models[target] = {}
                    self.models[target][algo] = load(model_path)
    
    def predict(self, X, target_name, algorithm_name):
        """Make predictions using a specific model"""
        if target_name not in self.models or algorithm_name not in self.models[target_name]:
            raise ValueError(f"Model not found: {target_name}_{algorithm_name}")
        
        if target_name in self.scalers:
            X_scaled = self.scalers[target_name].transform(X)
        else:
            X_scaled = X
        
        model = self.models[target_name][algorithm_name]
        predictions = model.predict(X_scaled)
        
        return predictions, None
