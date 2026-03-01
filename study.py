import ast
import pandas as pd 

df = pd.read_csv("100kcountry_enriched.csv")


df["ips"] = df["ips"].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else [])
df["countries"] = df["countries"].apply(lambda x: ast.literal_eval(x) if pd.notna(x) else [])

has_country = df["has_country"].sum()

df_exp = df.explode(["ips", "countries"])

print(f"Total de IPs:          {len(df_exp)}")
print(f"IPs sem país:          {df_exp['countries'].isna().sum()}")
print(f"% IPs sem país:        {df_exp['countries'].isna().mean():.1%}")
print(f"Domínios com algum None: {df_exp[df_exp['countries'].isna()]['name'].nunique()}")
print(f"Domínios com algum país {has_country}")
print(df['countries'].str.unique())
df = pd.read_csv("whois_featuresw.csv")

m_part = df.iloc[50:]
m_count = len(m_part[m_part['has_whois']==True])

b_part = df.iloc[:50]
b_count = len(b_part[b_part['has_whois']==True])

print(f"Benignos que tem whois {b_count}")
print(f"Maliciosos que tem whois {m_count}")