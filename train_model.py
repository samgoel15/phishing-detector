import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# 1. Download dataset from Grega Vrbančič GitHub repo (small variant)
print("Downloading dataset...")
dataset_url = "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv"
data = pd.read_csv(dataset_url)
print(f"Dataset loaded with {len(data)} rows and {len(data.columns)} columns")

# 2. Sample 2000 rows for quicker training
sample_size = min(2000, len(data))
data = data.sample(sample_size, random_state=42).reset_index(drop=True)

# 3. Select features for training (choosing some representative URL-based features)
features = [
    'qty_dot_url', 'qty_hyphen_url', 'qty_underline_url', 'qty_slash_url',
    'qty_questionmark_url', 'qty_equal_url', 'qty_at_url', 'qty_and_url',
    'qty_exclamation_url', 'qty_comma_url', 'qty_plus_url', 'qty_asterisk_url',
    'qty_hashtag_url', 'qty_dollar_url', 'qty_percent_url', 'length_url',
    'qty_dot_domain', 'qty_hyphen_domain', 'domain_length'
]

X = data[features]
y = data['phishing']  # 1 = phishing, 0 = legitimate

# 4. Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. Train Random Forest classifier
print("Training model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 6. Evaluate model performance
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}")

# 7. Save the trained model
joblib.dump(model, "phishing_model.pkl")
print("Model saved as phishing_model.pkl")