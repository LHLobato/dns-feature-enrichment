import socket 
import dns.resolver
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
    def calcular(row):
        if pd.notna(row["creation_date"]) and pd.notna(row["expiration_date"]):
            row["lifetime"] = (row["expiration_date"] - row["creation_date"]).days / 365
        else:
            row["lifetime"] = None
            
        if pd.notna(row["creation_date"]) and pd.notna(row["update_date"]):
            row["active_time"] = (row["update_date"] - row["creation_date"]).days / 365
        else:
            row["active_time"] = None
            
        return row
    
    return df.apply(calcular, axis=1)