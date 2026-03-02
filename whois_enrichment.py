import whois 
from datetime import datetime
import csv
import pandas as pd 
from concurrent.futures import ThreadPoolExecutor
import time
import random 
from common_functions import get_whois_features

df = pd.read_csv("subset_50k.csv")

dominios = df['name'].values[:25000]
resultados = []


with ThreadPoolExecutor(max_workers=4) as executor:
    resultados = list(executor.map(get_whois_features, dominios))
    
resultados = pd.DataFrame(resultados)
resultados["name"] = dominios

df = df.merge(resultados, on="name", how="left")
df.to_csv("50kwhois_enriched.csv", index=False)
print("Salvo em 50kwhois_enriched.csv!")

