import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Load cleaned dataset
file_path = r"D:\AI based network threat detection system\dataset\cleaned_dataset.csv"

df = pd.read_csv(file_path)

# Remove spaces from column names
df.columns = df.columns.str.strip()

# Separate features and labels
X = df.drop("Label", axis=1)
y = df["Label"]

print("Features:", X.shape)
print("Labels:", y.shape)

# Encode attack labels
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

print("\nAttack Classes:")
for i, label in enumerate(label_encoder.classes_):
    print(f"{i} -> {label}")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)

print("\nTraining Data:", X_train.shape)
print("Testing Data :", X_test.shape)

# Save encoder
os.makedirs(r"D:\AI based network threat detection system\models", exist_ok=True)

joblib.dump(
    label_encoder,
    r"D:\AI based network threat detection system\models\label_encoder.pkl"
)

print("\nLabel encoder saved successfully!")