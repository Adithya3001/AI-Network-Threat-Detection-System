import pandas as pd
import joblib
import os

# Load model
model = joblib.load(
    r"D:\AI based network threat detection system\models\model.pkl"
)

# Load dataset
df = pd.read_csv(
    r"D:\AI based network threat detection system\dataset\cleaned_dataset.csv"
)

df.columns = df.columns.str.strip()

X = df.drop("Label", axis=1)

# Feature importance
importance = model.feature_importances_

feature_importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": importance
})

feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

print(feature_importance.head(20))

# Save feature importance
feature_importance.to_csv(
    r"D:\AI based network threat detection system\models\feature_importance.csv",
    index=False
)

print("\nFeature importance saved successfully!")