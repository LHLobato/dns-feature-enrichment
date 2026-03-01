import pandas as pd

df = pd.read_csv("dataset.csv")

ben = df[df['malicious'] == 0]
mal = df[df['malicious'] == 1]

n = min(50000, len(ben), len(mal))

ben_sample = ben.sample(n=n, random_state=42)
mal_sample = mal.sample(n=n, random_state=42)

subset = pd.concat([ben_sample, mal_sample]).sample(frac=1, random_state=42)

print(f"Total: {len(subset)}")
print(f"Benignos: {len(ben_sample)}")
print(f"Maliciosos: {len(mal_sample)}")

subset.to_csv("subset_100k.csv", index=False)