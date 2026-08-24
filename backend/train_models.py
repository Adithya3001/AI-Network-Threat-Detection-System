import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression

# Try importing XGBoost
try:
    from xgboost import XGBClassifier
    xgboost_available = True
except ImportError:
    xgboost_available = False

# --------------------------
# Load Dataset
# --------------------------

file_path = r"D:\AI based network threat detection system\dataset\cleaned_dataset.csv"

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

# Remove rare classes
counts = df["Label"].value_counts()
valid = counts[counts >= 50].index
df = df[df["Label"].isin(valid)]

# Sample for faster training
df = df.sample(n=200000, random_state=42)

X = df.drop("Label", axis=1)
y = df["Label"]

encoder = LabelEncoder()
y = encoder.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# --------------------------
# Models
# --------------------------

models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    ),

    "Decision Tree": DecisionTreeClassifier(
        random_state=42
    ),

    "Logistic Regression": LogisticRegression(
        max_iter=1000
    )
}

if xgboost_available:
    models["XGBoost"] = XGBClassifier(
        eval_metric="mlogloss",
        random_state=42
    )

results = []

best_model = None
best_score = 0
best_name = ""

print("\nTraining Models...\n")

for name, model in models.items():

    print(f"Training {name}...")

    model.fit(X_train, y_train)

    pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, pred)
    precision = precision_score(y_test, pred, average="weighted", zero_division=0)
    recall = recall_score(y_test, pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, pred, average="weighted", zero_division=0)

    results.append({
        "Model": name,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1
    })

    if accuracy > best_score:
        best_score = accuracy
        best_model = model
        best_name = name

print("\nTraining Complete!\n")

results_df = pd.DataFrame(results)

print(results_df)

# --------------------------
# Save Best Model
# --------------------------

os.makedirs(r"D:\AI based network threat detection system\models", exist_ok=True)

joblib.dump(best_model,
            r"D:\AI based network threat detection system\models\best_model.pkl")

joblib.dump(encoder,
            r"D:\AI based network threat detection system\models\label_encoder.pkl")

results_df.to_csv(
    r"D:\AI based network threat detection system\models\model_comparison.csv",
    index=False
)

print(f"\nBest Model: {best_name}")
print(f"Accuracy : {best_score:.4f}")

print("\nSaved:")
print("best_model.pkl")
print("label_encoder.pkl")
print("model_comparison.csv")