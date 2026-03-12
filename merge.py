import pandas as pd 

df1 = pd.read_csv("whois-query-result.csv", index_col=False)
df2 = pd.read_csv("part2-whois-enriched.csv", index_col=False)

df3 = pd.read_csv("dataset.csv", index_col=False)
df3 = df3.head(232839)

for col in df1.columns:
    if col not in ["name", "malicious"]:
        df3[col] = df1[col]

        


df_final = pd.concat([df3, df2], axis=0, ignore_index=True)
df_final.to_csv("whois-final.csv", index=False)