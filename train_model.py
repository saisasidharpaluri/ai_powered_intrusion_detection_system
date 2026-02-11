import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import numpy as np

# Define the column names for the dataset (since the CSV doesn't have a header)
# Based on NSL-KDD documentation
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
    'dst_host_srv_rerror_rate', 'class', 'difficulty_level'
]

# We will only use a subset of features that are easy to extract from live packets
# This makes our packet sniffer simpler to write for this project.
selected_features = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes'
]

print("Loading dataset...")
# Load the training dataset
df = pd.read_csv('dataset/KDDTrain+.txt', names=columns)

print("Preprocessing data...")
# Filter only the columns we want + the class label
data = df[selected_features + ['class']]

# Initialize encoders for categorical data
# We need to save these to use them in the real-time system later
protocol_encoder = LabelEncoder()
service_encoder = LabelEncoder()
flag_encoder = LabelEncoder()
class_encoder = LabelEncoder()

# Fit and transform the categorical columns
data['protocol_type'] = protocol_encoder.fit_transform(data['protocol_type'])
data['service'] = service_encoder.fit_transform(data['service'])
data['flag'] = flag_encoder.fit_transform(data['flag'])
data['class'] = class_encoder.fit_transform(data['class'])

# Define X (features) and y (labels)
X = data[selected_features]
y = data['class']

print("Training Random Forest Classifier...")
# Initialize and train the classifier
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X, y)

print("Saving model and encoders...")
# Save everything using joblib so we can load it in the sniffer
joblib.dump(clf, 'rf_model.pkl')
joblib.dump(protocol_encoder, 'protocol_encoder.pkl')
joblib.dump(service_encoder, 'service_encoder.pkl')
joblib.dump(flag_encoder, 'flag_encoder.pkl')
joblib.dump(class_encoder, 'class_encoder.pkl')

print("Training complete! Model saved as 'rf_model.pkl'")
