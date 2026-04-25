#!/usr/bin/env python3
"""SIEM export module for Elasticsearch and Splunk."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
import os


@dataclass
class SIEMEvent:
    """Standardized event format for SIEM export."""
    timestamp: str
    source: str
    event_type: str
    message: str
    source_ip: str = ""
    destination_ip: str = ""
    user: str = ""
    host: str = ""
    severity: str = "info"
    metadata: dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> dict:
        return {
            "@timestamp": self.timestamp,
            "event.kind": "event",
            "event.category": "authentication",
            "event.type": self.event_type,
            "log.level": self.severity,
            "message": self.message,
            "source.ip": self.source_ip,
            "destination.ip": self.destination_ip,
            "user.name": self.user,
            "host.name": self.host,
            "log.source.name": self.source,
            **self.metadata
        }


class SIEMExporter(ABC):
    """Base class for SIEM exporters."""
    
    def __init__(self, endpoint: Optional[str] = None, api_key: Optional[str] = None):
        self.endpoint = endpoint or self._get_env("ENDPOINT")
        self.api_key = api_key or self._get_env("API_KEY")
        self._client = None
    
    def _get_env(self, key: str) -> str:
        return os.environ.get(f"SIEM_{key}", "")
    
    @abstractmethod
    def export(self, events: list[SIEMEvent]) -> dict:
        """Export events to SIEM."""
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        """Test connection to SIEM."""
        pass
    
    def _get_client(self):
        import httpx
        if not self._client:
            self._client = httpx.Client(timeout=30.0)
        return self._client


class ElasticsearchExporter(SIEMExporter):
    """Elasticsearch export via bulk API."""
    
    def __init__(self, endpoint: Optional[str] = None, api_key: Optional[str] = None, index: str = "logsentry-logs"):
        super().__init__(endpoint, api_key)
        self.index = index
        self.endpoint = self.endpoint or os.environ.get("ES_ENDPOINT", "http://localhost:9200")
        self.api_key = self.api_key or os.environ.get("ES_API_KEY", "")
    
    def test_connection(self) -> bool:
        try:
            client = self._get_client()
            response = client.get(f"{self.endpoint}/_cluster/health")
            return response.status_code == 200
        except Exception:
            return False
    
    def export(self, events: list[SIEMEvent]) -> dict:
        if not events:
            return {"status": "no_events", "exported": 0}
        
        try:
            client = self._get_client()
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"ApiKey {self.api_key}"
            
            bulk_body = ""
            for event in events:
                doc = event.to_dict()
                action_meta = f'{{"index": {{"_index": "{self.index}"}}}}\n'
                bulk_body += action_meta + self._to_json(doc) + "\n"
            
            response = client.post(
                f"{self.endpoint}/_bulk",
                content=bulk_body,
                headers={**headers, "Content-Type": "application/x-ndjson"}
            )
            
            if response.status_code in (200, 201):
                result = response.json()
                return {
                    "status": "success",
                    "exported": len(events),
                    "index": self.index,
                    "errors": result.get("errors", False)
                }
            else:
                return {"status": "error", "message": response.text}
                
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _to_json(self, doc: dict) -> str:
        import json
        return json.dumps(doc, default=str)


class SplunkExporter(SIEMExporter):
    """Splunk HEC (HTTP Event Collector) export."""
    
    def __init__(self, endpoint: Optional[str] = None, api_key: Optional[str] = None, index: str = "logsentry", source: str = "logsentry"):
        super().__init__(endpoint, api_key)
        self.endpoint = self.endpoint or os.environ.get("SPLUNK_ENDPOINT", "https://localhost:8088/services/collector")
        self.api_key = self.api_key or os.environ.get("SPLUNK_HEC_TOKEN", "")
        self.index = index
        self.source = source
        self.sourcetype = "logsentry:json"
    
    def test_connection(self) -> bool:
        try:
            client = self._get_client()
            response = client.get(
                f"{self.endpoint}/health",
                headers={"Authorization": f"Splunk {self.api_key}"}
            )
            return response.status_code in (200, 404)
        except Exception:
            return False
    
    def export(self, events: list[SIEMEvent]) -> dict:
        if not events:
            return {"status": "no_events", "exported": 0}
        
        try:
            client = self._get_client()
            headers = {"Authorization": f"Splunk {self.api_key}", "Content-Type": "application/json"}
            
            results = {"exported": 0, "failed": 0, "errors": []}
            
            for event in events:
                doc = event.to_dict()
                payload = {
                    "event": doc,
                    "host": doc.get("host.name", ""),
                    "index": self.index,
                    "source": self.source,
                    "sourcetype": self.sourcetype
                }
                
                response = client.post(self.endpoint, json=payload, headers=headers)
                if response.status_code in (200, 201):
                    results["exported"] += 1
                else:
                    results["failed"] += 1
                    results["errors"].append(response.text[:100])
            
            results["status"] = "success" if results["failed"] == 0 else "partial"
            return results
            
        except Exception as e:
            return {"status": "error", "message": str(e)}


class SumoLogicExporter(SIEMExporter):
    """Sumo Logic HTTP Source export."""
    
    def __init__(self, endpoint: Optional[str] = None, api_key: Optional[str] = None):
        super().__init__(endpoint, api_key)
        self.endpoint = self.endpoint or os.environ.get("SUMO_ENDPOINT", "")
        self.api_key = self.api_key or os.environ.get("SUMO_API_KEY", "")
    
    def test_connection(self) -> bool:
        return bool(self.endpoint and self.api_key)
    
    def export(self, events: list[SIEMEvent]) -> dict:
        if not events:
            return {"status": "no_events", "exported": 0}
        
        try:
            client = self._get_client()
            headers = {
                "Content-Type": "application/json",
                "X-Sumo-Client": "logsentry"
            }
            
            results = {"exported": 0, "failed": 0}
            
            for event in events:
                doc = event.to_dict()
                response = client.post(self.endpoint, json=doc, headers=headers)
                if response.status_code in (200, 201, 202):
                    results["exported"] += 1
                else:
                    results["failed"] += 1
            
            results["status"] = "success" if results["failed"] == 0 else "partial"
            return results
            
        except Exception as e:
            return {"status": "error", "message": str(e)}


def records_to_events(records: list[dict]) -> list[SIEMEvent]:
    """Convert parsed log records to SIEM events."""
    events = []
    for r in records:
        event = SIEMEvent(
            timestamp=r.get("timestamp", ""),
            source=r.get("host", "unknown"),
            event_type=r.get("event_type", "unknown"),
            message=r.get("raw_message", "") or r.get("message", ""),
            source_ip=r.get("source_ip", ""),
            destination_ip=r.get("destination_ip", ""),
            user=r.get("user", ""),
            host=r.get("host", ""),
            severity=r.get("severity", "info"),
            metadata={
                "mitre_tactic": r.get("mitre_tactic", ""),
                "mitre_technique": r.get("mitre_technique", ""),
            }
        )
        events.append(event)
    return events


def export_to_siem(
    records: list[dict],
    provider: str = "auto",
    **kwargs
) -> dict:
    """Export records to specified SIEM platform."""
    events = records_to_events(records)
    
    if not events:
        return {"status": "no_events", "exported": 0}
    
    exporters = {
        "elasticsearch": ElasticsearchExporter,
        "splunk": SplunkExporter,
        "sumologic": SumoLogicExporter,
    }
    
    if provider == "auto":
        for name, cls in exporters.items():
            if cls().test_connection():
                return cls(**kwargs).export(events)
        return {"status": "no_exporter", "message": "No SIEM connection configured"}
    
    exporter_class = exporters.get(provider.lower())
    if not exporter_class:
        return {"status": "unknown_provider", "message": f"Unknown provider: {provider}"}
    
    exporter = exporter_class(**kwargs)
    return exporter.export(events)