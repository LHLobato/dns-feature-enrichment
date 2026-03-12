import pandas as pd
from sklearn.model_selection import train_test_split
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--random_state", type=int, default=0)
args = parser.parse_args()

df = pd.read_csv("dataset.csv")
labels = df['malicious']

df_train, df_rest, y_train, y_rest = train_test_split(
    df, labels, test_size=0.30, stratify=labels, random_state=args.random_state
)

ben_train = df_train[df_train['malicious'] == 0]
mal_train = df_train[df_train['malicious'] == 1]

print(f"Train total:  {len(df_train)}")
print(f"  Benignas:   {len(ben_train)}")
print(f"  Malignas:   {len(mal_train)}")
"""
n_subset_samples = 50*1000
n = min(n_subset_samples//2, len(ben), len(mal))

ben_sample = ben.sample(n=n, random_state=42)
mal_sample = mal.sample(n=n, random_state=42)

subset = pd.concat([ben_sample, mal_sample]).sample(frac=1, random_state=42)

print(f"Total: {len(subset)}")
print(f"Benignos: {len(ben_sample)}")
print(f"Maliciosos: {len(mal_sample)}")

subset.to_csv("subset_50k.csv", index=False)"""