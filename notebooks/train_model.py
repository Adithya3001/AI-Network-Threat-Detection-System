import pandas as pd
import glob
import os

folder_path = r"D:\AI based network threat detection system\dataset\CICIDS2017"

csv_files = glob.glob(os.path.join(folder_path, "*.csv"))

print("CSV Files Found:")
for file in csv_files:
    print(os.path.basename(file))

df_list = []

for file in csv_files:
    print(f"Loading {os.path.basename(file)}...")
    df = pd.read_csv(file)
    df_list.append(df)

combined_df = pd.concat(df_list, ignore_index=True)

print("\nDataset Shape:", combined_df.shape)

print("\nAttack Labels:")
print(combined_df[" Label"].value_counts())