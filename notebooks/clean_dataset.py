import pandas as pd
import numpy as np
import glob
import os

folder_path = r"D:\AI based network threat detection system\dataset\CICIDS2017"

csv_files = glob.glob(os.path.join(folder_path, "*.csv"))

df_list = []

for file in csv_files:
    df = pd.read_csv(file)
    df_list.append(df)

df = pd.concat(df_list, ignore_index=True)

print("Original Shape:", df.shape)

# Replace infinity values
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Remove rows containing missing values
df.dropna(inplace=True)

# Remove duplicate rows
df.drop_duplicates(inplace=True)

print("Cleaned Shape:", df.shape)

print("\nMissing Values:")
print(df.isnull().sum().sum())

print("\nAttack Labels:")
print(df[" Label"].value_counts())

# Remove spaces from column names
df.columns = df.columns.str.strip()

# Save cleaned dataset
output_path = r"D:\AI based network threat detection system\dataset\cleaned_dataset.csv"

df.to_csv(output_path, index=False)

print("\nCleaned dataset saved successfully!")
print(f"Location: {output_path}")