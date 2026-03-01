import ast
import pandas as pd 

df = pd.read_csv("100kcountry_enriched.csv")


df["ips"] = df["ips"].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else [])
df["countries"] = df["countries"].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else [])

has_country = df["has_country"].sum()

df_exp = df.explode(["ips", "countries"])
paises_unicos = df.explode("countries")["countries"].unique()
print(paises_unicos)
print(f"Total de países únicos: {len(paises_unicos)}")
print(f"Total de IPs:          {len(df_exp)}")
print(f"IPs sem país:          {df_exp['countries'].isna().sum()}")
print(f"% IPs sem país:        {df_exp['countries'].isna().mean():.1%}")
print(f"Domínios com algum None: {df_exp[df_exp['countries'].isna()]['name'].nunique()}")
print(f"Domínios com algum país {has_country}")
print(df.explode("countries")["countries"].value_counts())