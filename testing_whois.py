import whois 
from datetime import datetime
import csv
import pandas as pd 
from concurrent.futures import ThreadPoolExecutor
import time
import random 
from common_functions import get_whois_features, whois_query

df = pd.read_csv("dataset.csv")

ben = df[df['malicious']==0]['name'].values
mal = df[df['malicious']==1]['name'].values

dominios = list(ben[:50]) + list(mal[:50])

resultados = []

with ThreadPoolExecutor(max_workers=4) as executor:
    resultados = list(executor.map(get_whois_features, dominios))

with open("whois_featuresw.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["dominio", "has_whois", "creation_date", "expiration_date","update_date"])
    writer.writeheader()
    writer.writerows(resultados)

print("Salvo em whois_featuresw.csv!")