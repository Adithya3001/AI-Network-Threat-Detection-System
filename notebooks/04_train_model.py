import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# ==============================
# Load Dataset
# ==============================

file_path = r"D:\AI based network threat detection system\dataset\cleaned_dataset.csv"

df = pd.read_csv(file_path)

# Remove spaces from column names
df.columns = df.columns.str.strip()

print("Original Dataset Shape:", df.shape)

# ==============================
# Remove Rare Classes
# ==============================

label_counts = df["Label"].value_counts()

print("\nOriginal Label Distribution:")
print(label_counts)

# Keep only classes having at least 50 samples
valid_labels = label_counts[label_counts >= 50].index

df = df[df["Label"].isin(valid_labels)]

print("\nAfter Removing Rare Classes:")
print(df["Label"].value_counts())

# ==============================
# Take Sample
# ==============================

sample_size = 200000

if len(df) > sample_size:
    df = df.sample(n=sample_size, random_state=42)

print("\nTraining Sample Shape:", df.shape)

# ==============================
# Features & Labels
# ==============================

X = df.drop("Label", axis=1)
y = df["Label"]

# Encode Labels
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

print("\nEncoded Classes:")

for i, label in enumerate(encoder.classes_):
    print(f"{i} -> {label}")

# ==============================
# Train-Test Split
# ==============================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)

print("\nTraining Data :", X_train.shape)
print("Testing Data  :", X_test.shape)

# ==============================
# Train Random Forest
# ==============================

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Training Complete!")

# ==============================
# Evaluation
# ==============================

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", accuracy)

print("\nClassification Report:\n")
print(classification_report(
    y_test,
    y_pred,
    target_names=encoder.classes_
))

# ==============================
# Save Model
# ==============================

model_folder = r"D:\AI based network threat detection system\models"

os.makedirs(model_folder, exist_ok=True)

joblib.dump(model, os.path.join(model_folder, "model.pkl"))
joblib.dump(encoder, os.path.join(model_folder, "label_encoder.pkl"))

print("\nModel Saved Successfully!")

print("Location:", model_folder)