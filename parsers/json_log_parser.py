import json


JSON_LOG_KEYS = {"timestamp", "time", "@timestamp", "ts", "level", "severity", "message", "msg", "log"}


def parse_json_log(line: str) -> dict | None:
    line = line.strip()
    if not (line.startswith("{") and line.endswith("}")):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    # Skip if it's CloudTrail (those have eventVersion + eventTime)
    if "eventVersion" in data and "eventTime" in data:
        return None

    ts = (
        data.get("timestamp")
        or data.get("time")
        or data.get("@timestamp")
        or data.get("ts", "")
    )
    msg = (
        data.get("message")
        or data.get("msg")
        or data.get("log", "")
        or json.dumps(data, default=str)
    )
    level = (data.get("level") or data.get("severity") or "info").lower()
    src_ip = data.get("source_ip") or data.get("src_ip") or data.get("client_ip") or ""
    user = data.get("user") or data.get("username") or data.get("user_name") or ""
    host = data.get("host") or data.get("hostname") or data.get("server") or ""

    event_type = data.get("event_type") or data.get("event") or "json_log"

    return {
        "timestamp": str(ts),
        "host": host,
        "user": user,
        "source_ip": src_ip,
        "destination_ip": data.get("destination_ip", data.get("dest_ip", "")),
        "event_type": event_type,
        "process": data.get("process") or data.get("app") or data.get("service") or "",
        "severity": level,
        "raw_message": msg,
        "format": "json",
        "_data": data,
    }
