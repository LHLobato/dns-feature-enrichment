import pandas as pd 

df = pd.read_csv("whois_featuresw.csv")

m_part = df.iloc[50:]
m_count = len(m_part[m_part['has_whois']==True])

b_part = df.iloc[:50]
b_count = len(b_part[b_part['has_whois']==True])

print(f"Benignos que tem whois {b_count}")
print(f"Maliciosos que tem whois {m_count}")