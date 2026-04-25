#!/usr/bin/env python3
"""Threat intelligence providers for IP enrichment."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
import os


@dataclass
class ThreatIntelResult:
    """Standardized threat intelligence result."""
    ip: str
    provider: str
    is_malicious: bool = False
    confidence: int = 0
    country: str = ""
    country_code: str = ""
    isp: str = ""
    is_tor: bool = False
    is_proxy: bool = False
    is_vpn: bool = False
    is_datacenter: bool = False
    abuse_score: int = 0
    report_count: int = 0
    last_reported: str = ""
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "provider": self.provider,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "country": self.country,
            "country_code": self.country_code,
            "isp": self.isp,
            "is_tor": self.is_tor,
            "is_proxy": self.is_proxy,
            "is_vpn": self.is_vpn,
            "is_datacenter": self.is_datacenter,
            "abuse_score": self.abuse_score,
            "report_count": self.report_count,
            "last_reported": self.last_reported,
            "categories": self.categories,
            "tags": self.tags,
        }


class ThreatIntelProvider(ABC):
    """Base class for threat intelligence providers."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or self._get_api_key()
        self.enabled = bool(self.api_key)
        self._client = None
    
    def _get_api_key(self) -> str:
        env_var = self.__class__.__name__.replace("Provider", "").upper()
        return os.environ.get(f"{env_var}_API_KEY", "")
    
    @property
    def name(self) -> str:
        return self.__class__.__name__.replace("Provider", "")
    
    @abstractmethod
    def lookup(self, ip: str) -> ThreatIntelResult:
        """Look up IP and return threat intel result."""
        pass
    
    def _make_request(self, method: str, url: str, **kwargs) -> dict:
        """Make HTTP request with retries."""
        import httpx
        if not self._client:
            self._client = httpx.Client(timeout=30.0)
        
        headers = kwargs.pop("headers", {})
        if self.api_key:
            headers["X-Apikey"] = self.api_key
        
        response = self._client.request(method, url, headers=headers, **kwargs)
        response.raise_for_status()
        return response.json()


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal API provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")
        super().__init__(self.api_key)
    
    def _get_api_key(self) -> str:
        return os.environ.get("VT_API_KEY", "")
    
    def lookup(self, ip: str) -> ThreatIntelResult:
        result = ThreatIntelResult(ip=ip, provider="VirusTotal")
        
        if not self.enabled:
            return result
        
        try:
            data = self._make_request(
                "GET",
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            )
            
            attributes = data.get("data", {}).get("attributes", {})
            
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            
            result.is_malicious = malicious > 0 or suspicious > 0
            result.confidence = min((malicious * 10 + suspicious * 5), 100)
            result.country = attributes.get("country", "")
            result.country_code = attributes.get("country", "")
            result.isp = attributes.get("network", "")
            result.tags = attributes.get("tags", [])
            
            if attributes.get("last_analysis_date"):
                result.last_reported = str(attributes["last_analysis_date"])
            
            result.raw_data = data
            return result
            
        except Exception as e:
            result.raw_data = {"error": str(e)}
            return result


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB API provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        super().__init__(self.api_key)
    
    def _get_api_key(self) -> str:
        return os.environ.get("ABUSEIPDB_API_KEY", "")
    
    def lookup(self, ip: str) -> ThreatIntelResult:
        result = ThreatIntelResult(ip=ip, provider="AbuseIPDB")
        
        if not self.enabled:
            return result
        
        try:
            import httpx
            with httpx.Client() as client:
                response = client.get(
                    f"https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": self.api_key},
                    params={"ipAddress": ip, "maxAgeInDays": 90}
                )
                response.raise_for_status()
                data = response.json()
            
            attrs = data.get("data", {})
            
            result.is_malicious = attrs.get("isWhitelisted", False) == False and attrs.get("totalReports", 0) > 0
            result.confidence = attrs.get("confidenceScore", 0)
            result.country = attrs.get("countryName", "")
            result.country_code = attrs.get("countryCode", "")
            result.isp = attrs.get("isp", "")
            result.abuse_score = attrs.get("abuseConfidenceScore", 0)
            result.report_count = attrs.get("totalReports", 0)
            result.last_reported = attrs.get("lastReportedAt", "")
            
            categories = attrs.get("reports", [])
            if categories:
                result.categories = [str(c) for c in categories[:5]]
            
            result.is_tor = attrs.get("isTor", False)
            result.is_proxy = attrs.get("isProxy", False)
            result.is_vpn = attrs.get("isVpn", False)
            result.is_datacenter = attrs.get("isDatacenter", False)
            
            result.raw_data = data
            return result
            
        except Exception as e:
            result.raw_data = {"error": str(e)}
            return result


class AlienVaultOTXProvider(ThreatIntelProvider):
    """AlienVault OTX API provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OTX_API_KEY", "")
        super().__init__(self.api_key)
    
    def _get_api_key(self) -> str:
        return os.environ.get("OTX_API_KEY", "")
    
    def lookup(self, ip: str) -> ThreatIntelResult:
        result = ThreatIntelResult(ip=ip, provider="AlienVaultOTX")
        
        if not self.enabled:
            return result
        
        try:
            data = self._make_request(
                "GET",
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}"
            )
            
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            result.is_malicious = pulse_count > 0
            result.confidence = min(pulse_count * 10, 100)
            
            country = data.get("country_code", "")
            result.country_code = country
            result.country = country
            
            result.tags = [p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])[:5]]
            result.categories = list(set(data.get("categories", {}).values()))[:5]
            
            result.raw_data = data
            return result
            
        except Exception as e:
            result.raw_data = {"error": str(e)}
            return result


class ShodanProvider(ThreatIntelProvider):
    """Shodan API provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY", "")
        super().__init__(self.api_key)
    
    def _get_api_key(self) -> str:
        return os.environ.get("SHODAN_API_KEY", "")
    
    def lookup(self, ip: str) -> ThreatIntelResult:
        result = ThreatIntelResult(ip=ip, provider="Shodan")
        
        if not self.enabled:
            return result
        
        try:
            data = self._make_request(
                "GET",
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.api_key}
            )
            
            result.country = data.get("country_name", "")
            result.country_code = data.get("country_code", "")
            result.isp = data.get("isp", "")
            result.os = data.get("os", "")
            
            tags = data.get("tags", [])
            result.is_datacenter = "datacenter" in tags
            result.is_vpn = "vpn" in tags
            result.tags = tags
            
            result.raw_data = data
            return result
            
        except Exception as e:
            result.raw_data = {"error": str(e)}
            return result


class ThreatIntelAggregator:
    """Aggregate results from multiple threat intel providers."""
    
    def __init__(self):
        self.providers: list[ThreatIntelProvider] = [
            VirusTotalProvider(),
            AbuseIPDBProvider(),
            AlienVaultOTXProvider(),
            ShodanProvider(),
        ]
    
    def lookup(self, ip: str) -> dict:
        """Query all enabled providers and aggregate results."""
        results = {
            "ip": ip,
            "providers_queried": [],
            "providers_available": [],
            "is_malicious": False,
            "malicious_votes": 0,
            "max_confidence": 0,
            "aggregated": {
                "country": "",
                "country_code": "",
                "isp": "",
                "is_tor": False,
                "is_proxy": False,
                "is_vpn": False,
                "is_datacenter": False,
            },
            "details": []
        }
        
        for provider in self.providers:
            if provider.enabled:
                results["providers_queried"].append(provider.name)
                
                try:
                    result = provider.lookup(ip)
                    results["details"].append(result.to_dict())
                    
                    if result.is_malicious:
                        results["malicious_votes"] += 1
                    results["max_confidence"] = max(results["max_confidence"], result.confidence)
                    
                    if not results["aggregated"]["country"] and result.country:
                        results["aggregated"]["country"] = result.country
                        results["aggregated"]["country_code"] = result.country_code
                    if not results["aggregated"]["isp"] and result.isp:
                        results["aggregated"]["isp"] = result.isp
                    
                    results["aggregated"]["is_tor"] = results["aggregated"]["is_tor"] or result.is_tor
                    results["aggregated"]["is_proxy"] = results["aggregated"]["is_proxy"] or result.is_proxy
                    results["aggregated"]["is_vpn"] = results["aggregated"]["is_vpn"] or result.is_vpn
                    results["aggregated"]["is_datacenter"] = results["aggregated"]["is_datacenter"] or result.is_datacenter
                    
                except Exception as e:
                    results["details"].append({"provider": provider.name, "error": str(e)})
            else:
                results["providers_available"].append(provider.name)
        
        results["is_malicious"] = results["malicious_votes"] > 0
        
        for prefix, data in FALLBACK_THREAT_INTEL.items():
            if ip.startswith(prefix):
                if data.get("reputation") in ["malicious", "suspicious"]:
                    results["is_malicious"] = True
                    results["malicious_votes"] += 1
                if not results["aggregated"]["country"]:
                    results["aggregated"]["country"] = data.get("country", "")
                break
        
        return results


FALLBACK_THREAT_INTEL = {
    "185.220.": {"type": "Tor Exit Node", "reputation": "malicious", "country": "Multiple"},
    "91.121.": {"type": "Known Scanner", "reputation": "suspicious", "country": "France"},
    "45.33.32.": {"type": "Proxy/VPN", "reputation": "suspicious", "country": "US"},
    "103.45.67.": {"type": "Dynamic IP", "reputation": "neutral", "country": ""},
}


def check_ip_reputation(ip: str) -> str:
    """Quick reputation check for an IP."""
    for prefix, data in FALLBACK_THREAT_INTEL.items():
        if ip.startswith(prefix):
            if data["reputation"] == "malicious":
                return "tor_exit_node" if "Tor" in data.get("type", "") else "malicious"
            return data["reputation"]
    
    result = enrich_ip(ip)
    
    if result["malicious_votes"] >= 2:
        return "malicious"
    elif result["malicious_votes"] == 1:
        return "suspicious"
    elif result["max_confidence"] >= 50:
        return "concerning"
    elif result["aggregated"].get("is_tor"):
        return "tor_exit_node"
    elif result["aggregated"].get("is_vpn"):
        return "vpn"
    elif result["aggregated"].get("is_proxy"):
        return "proxy"
    elif result["aggregated"].get("is_datacenter"):
        return "datacenter"
    else:
        return "clean"


def enrich_ip(ip: str) -> dict:
    """Enrich a single IP with threat intelligence from all providers."""
    aggregator = ThreatIntelAggregator()
    return aggregator.lookup(ip)