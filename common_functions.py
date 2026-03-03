import re
import socket 
import dns.resolver
import numpy as np
import whois 
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import time
import random 
import pandas as pd
import requests
from whois.exceptions import WhoisDomainNotFoundError
from geoip2fast import GeoIP2Fast
import threading
_reader = None

def close_reader():
    global _reader
    if _reader is not None:
        _reader.close()
        _reader = None

_local = threading.local()

def get_reader():
    if not hasattr(_local, "reader"):
        _local.reader = GeoIP2Fast(geoip2fast_data_file="geoip2fast-asn-ipv6.dat.gz")
    return _local.reader

def get_country(domain: str) -> dict:
    try:
        print(f"----Testing {domain}----")
        reader = get_reader()
        ans = dns.resolver.resolve(domain, "A")
        ips = [r.address for r in ans]
        countries = []
        asns = []
        for ip in ips:
            result = reader.lookup(ip)
            code = result.country_name or "UNKNOWN"
            asn = result.asn_name or (str(result.asn) if hasattr(result, 'asn') and result.asn else "UNKNOWN")
            countries.append(code)
            asns.append(asn)
        has_country = any(c != "UNKNOWN" for c in countries)
        return {"name": domain, "ips": ips, "countries": countries, "asns": asns, "has_country": has_country}
    except Exception as e:
        return {"name": domain, "ips": [], "countries": ["UNKNOWN"], "asns": ["UNKNOWN"], "has_country": False}

def whois_query(domain: str, retries: int = 3) -> dict:
    for attempt in range(retries):
        try:
            time.sleep(random.uniform(0.5, 1))
            w = whois.whois(domain)
            creation_date   = w.creation_date[0]   if isinstance(w.creation_date, list)   else w.creation_date
            expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            update_date     = w.updated_date[0]    if isinstance(w.updated_date, list)    else w.updated_date
            has_whois = creation_date is not None
            return {
                "has_whois":       has_whois,
                "creation_date":   creation_date,
                "expiration_date": expiration_date,
                "update_date":     update_date,
            }
        except WhoisDomainNotFoundError:
            break
        except (socket.timeout, ConnectionResetError, TimeoutError):

            if attempt < retries - 1:
                wait = 2 * (attempt + 1)
                print(f"Timeout em {domain}, aguardando {wait}s antes de tentar novamente...")
                time.sleep(wait)
        except Exception:
            break

    return {"has_whois": False, "creation_date": None, "expiration_date": None, "update_date": None}




def rdap_query(domain: str) -> dict:
    try:
        r = requests.get(f"https://rdap.iana.org/domain/{domain}", timeout=10)
        data = r.json()
        creation_date = expiration_date = update_date = None
        for event in data.get("events", []):
            action = event.get("eventAction")
            date   = event.get("eventDate")
            if action == "registration":
                creation_date = datetime.fromisoformat(date)
            elif action == "expiration":
                expiration_date = datetime.fromisoformat(date)
            elif action == "last changed":
                update_date = datetime.fromisoformat(date)
        return {
            "has_whois":       creation_date is not None,  # <- validação
            "creation_date":   creation_date,
            "expiration_date": expiration_date,
            "update_date":     update_date,
        }
    except Exception:
        return {"has_whois": False, "creation_date": None, "expiration_date": None, "update_date": None}

def registro_br_query(domain: str) -> dict:
    try:
        r = requests.get(f"https://rdap.registro.br/domain/{domain}", timeout=10)
        data = r.json()
        creation_date = expiration_date = update_date = None
        for event in data.get("events", []):
            action = event.get("eventAction")
            date   = event.get("eventDate")
            if action == "registration":
                creation_date = datetime.fromisoformat(date)
            elif action == "expiration":
                expiration_date = datetime.fromisoformat(date)
            elif action == "last changed":
                update_date = datetime.fromisoformat(date)
        return {
            "has_whois":       creation_date is not None,  # <- fix
            "creation_date":   creation_date,
            "expiration_date": expiration_date,
            "update_date":     update_date,
        }
    except Exception:
        return {"has_whois": False, "creation_date": None, "expiration_date": None, "update_date": None}
    
def get_whois_features(domain: str) -> dict:
    print(f"----Testing {domain}----")
    result = whois_query(domain)
    if result["has_whois"]:
        return result


    if domain.endswith(".br"):
        result = registro_br_query(domain)
        if result["has_whois"]:
            return result

    result = rdap_query(domain)
    return result    

def get_date_features(df: pd.DataFrame) -> pd.DataFrame:
    for col in ['creation_date', 'expiration_date', 'update_date']:
        df[col] = pd.to_datetime(df[col], errors='coerce', utc=True)
    
    df['lifetime'] = (df['expiration_date'] - df['creation_date']).dt.days / 365
    df['active_time'] = (df['update_date'] - df['creation_date']).dt.days / 365
    
    return df


def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    _, counts = np.unique(list(s), return_counts=True)
    prob = counts / len(s)
    return -np.sum(prob * np.log2(prob))

def vowel_ratio(s: str) -> float:
    s = re.sub(r'[^a-z]', '', s.lower())
    if not s: return 0.0
    vowels = sum(ch in 'aeiou' for ch in s)
    return vowels / len(s) if len(s) > 0 else 0.0

def digit_ratio(s: str) -> float:
    if not s: return 0.0
    digits = sum(ch.isdigit() for ch in s)
    return digits / len(s) if len(s) > 0 else 0.0

def consonant_ratio(s: str) -> float:
    s = re.sub(r'[^a-z]', '', s.lower())
    if not s: return 0.0
    consonants = sum(ch not in 'aeiou' for ch in s)
    return consonants / len(s) if len(s) > 0 else 0.0

def special_char_ratio(s: str) -> float:
    if not s: return 0.0
    specials = sum(ch in '-_.' for ch in s)
    return specials / len(s) if len(s) > 0 else 0.0

def extract_lexical_features(domain: str) -> list:
    domain_original = str(domain).lower().strip() 
    
    if not domain_original or domain_original == 'nan':
        return [0.0] * 13 # Corrigido para 13 (tamanho real do vetor)
        
    domain_no_www = re.sub(r'^www\.', '', domain_original)

    consonants = re.findall(r'[^aeiou\d\W_]+', domain_original)
    max_consonant_seq = max(len(s) for s in consonants) if consonants else 0
    digits_seq = re.findall(r'\d+', domain_original)
    max_digit_seq = max(len(s) for s in digits_seq) if digits_seq else 0
    unique_char_ratio = len(set(domain_original)) / len(domain_original)

    return [
        float(len(domain_original)),
        float(sum(c.isdigit() for c in domain_original)),
        digit_ratio(domain_original),
        vowel_ratio(domain_original),
        consonant_ratio(domain_original),
        special_char_ratio(domain_original),
        shannon_entropy(domain_original),
        float(domain_original.count('-')),
       float(1 if domain_original[0].isdigit() else 0),
        float(1 if re.search(r'(.)\1{2,}', domain_original) else 0),
        float(max_consonant_seq),
        float(max_digit_seq),
        round(float(unique_char_ratio), 4)
    ]

def get_numeric_features(dataframe:pd.DataFrame) -> np.array: 
    print("Calculando features léxicas...")
    lex = np.array(dataframe['name'].apply(extract_lexical_features).to_list())
    
    dns_cols = [c for c in dataframe.columns if c not in ['malicious', 'name']]
    dataframe[dns_cols] = dataframe[dns_cols].fillna(0)
    dns = dataframe[dns_cols].values.astype(float)
    
    return np.hstack([lex, dns])