import pandas as pd 

df1 = pd.read_csv("whois-part1.csv", index_col=False)[25000:]
df2 = pd.read_csv("whois-part2.csv", index_col=False)[:25000]


df_final = pd.concat([df1, df2], axis=0, ignore_index=True)
df_final.to_csv("whois-final.csv", index=False)