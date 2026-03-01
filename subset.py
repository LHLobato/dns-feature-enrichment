import pandas as pd

df = pd.read_csv("dataset.csv")

ben = df[df['malicious'] == 0]
mal = df[df['malicious'] == 1]

n_subset_samples = 50*1000
n = min(n_subset_samples//2, len(ben), len(mal))

ben_sample = ben.sample(n=n, random_state=42)
mal_sample = mal.sample(n=n, random_state=42)

subset = pd.concat([ben_sample, mal_sample]).sample(frac=1, random_state=42)

print(f"Total: {len(subset)}")
print(f"Benignos: {len(ben_sample)}")
print(f"Maliciosos: {len(mal_sample)}")

subset.to_csv("subset_50k.csv", index=False)