import ast
import pandas as pd 

# Carregando o dataset enriquecido (supondo que o novo CSV já tenha a coluna 'asns')
df = pd.read_csv("50kcountry_enriched.csv")

# Conversão de strings para listas (incluindo a nova coluna de asns)
for col in ["ips", "countries", "asns"]:
    df[col] = df[col].apply(lambda x: ast.literal_eval(x) if pd.notna(x) and x.startswith('[') else [])

# 1. Explodindo para análise a nível de IP/ASN individual
# O pandas permite explodir múltiplas colunas simultaneamente se elas tiverem o mesmo tamanho
df_exp = df.explode(["ips", "countries", "asns"])
df_bad_exp = df[df['malicious']==1].explode(["ips", "countries", "asns"])

asns_unicos = df_exp["asns"].unique()
total_asns = df_exp["asns"].nunique()
top_asns = df_exp["asns"].value_counts().head(10)

print(f"--- Relatório de Infraestrutura (ASN) ---")
print(f"Total de ASNs únicos encontrados: {total_asns}")
print(f"IPs sem identificação de ASN:     {df_exp['asns'].isin(['UNKNOWN', None]).sum()}")
print(f"\nTop 10 ASNs mais frequentes:\n{top_asns}")

# --- Cruzamento ASN vs País (Opcional, mas útil para o relatório) ---
# Isso ajuda a ver se um ASN específico está distribuído em vários países
asn_country_dist = df_exp.groupby("asns")["countries"].nunique().sort_values(ascending=False)
print(f"\nASNs com maior dispersão geográfica:\n{asn_country_dist.head(5)}")

# --- Salvando os resultados ---
# Tabela de contagem por ASN para sua análise de features
df_asn_counts = df_exp["asns"].value_counts().reset_index()
df_asn_counts.columns = ['asn', 'count']
bad_counts = df_bad_exp["asns"].value_counts()
df_asn_counts['bad_count'] = df_asn_counts['asn'].map(bad_counts).fillna(0).astype(int)

df_asn_counts.to_csv("asntable.csv", index=False)

# Mantendo sua exportação original de países
bad_country_counts = df_bad_exp["countries"].value_counts()
df_country_counts = df_exp["countries"].value_counts().reset_index()
df_country_counts.columns = ['country', 'count']
df_country_counts['bad_count'] = df_country_counts['country'].map(bad_country_counts).fillna(0).astype(int)
df_country_counts.to_csv("countrytable.csv", index=False)