import re

_rules = []
_rules_by_id = {}


def init_rules():
    """Инициализация правил безопасности"""
    global _rules, _rules_by_id
    rules_data = [
        {
            "id": 1,
            "name": "SQL Injection - UNION SELECT",
            "pattern": re.compile(r"(?i)(union\s+select\s+.+from)"),
            "target": "both",
            "severity": "high"
        },
        {
            "id": 2,
            "name": "SQL Injection - OR/AND Injection",
            "pattern": re.compile(r"(?i)([\w']+\s+(or|and)\s+[\w']+\s*=\s*[\w']+)"),
            "target": "both",
            "severity": "high"
        },
        {
            "id": 3,
            "name": "SQL Injection - Comment injection",
            "pattern": re.compile(r"(?i)(--|\#|\/\*|\*\/)"),
            "target": "both",
            "severity": "medium"
        },
        {
            "id": 4,
            "name": "XSS - Script tag",
            "pattern": re.compile(r"(?i)(<script[^>]*>.*?</script>)"),
            "target": "both",
            "severity": "high"
        },
        {
            "id": 5,
            "name": "XSS - Event handlers",
            "pattern": re.compile(r"(?i)(on\w+\s*=\s*['\"]?[^'\">]*)"),
            "target": "both",
            "severity": "high"
        },
        {
            "id": 6,
            "name": "XSS - Javascript protocol",
            "pattern": re.compile(r"(?i)(javascript\s*:\s*)"),
            "target": "both",
            "severity": "high"
        },
        {
            "id": 7,
            "name": "Path Traversal - Unix",
            "pattern": re.compile(r"(\.\./|\.\.\\)"),
            "target": "url",
            "severity": "high"
        },
        {
            "id": 8,
            "name": "Path Traversal - Windows",
            "pattern": re.compile(r"(\.\.\\|\.\./)"),
            "target": "url",
            "severity": "high"
        },
        {
            "id": 9,
            "name": "Command Injection - Pipe and semicolon",
            "pattern": re.compile(r"(\||;|\&\&|\$\(|`|\|&)"),
            "target": "both",
            "severity": "critical"
        },
        {
            "id": 10,
            "name": "Suspicious User-Agent - Scanner",
            "pattern": re.compile(r"(sqlmap|nikto|nmap|acunetix|nessus|burp|wpscan|dirbuster|gobuster)", re.IGNORECASE),
            "target": "headers",
            "severity": "medium"
        },
        {
            "id": 11,
            "name": "SQL Injection - Equal OR pattern",
            "pattern": re.compile(r"'\s+or\s+'\w+'\s*=\s*'\w+'", re.IGNORECASE),
            "target": "both",
            "severity": "high"
        },
        {
            "id": 12,
            "name": "SQL Injection - Numeric OR pattern",
            "pattern": re.compile(r"\d+\s+or\s+\d+\s*=\s*\d+", re.IGNORECASE),
            "target": "both",
            "severity": "high"
        }
    ]

    for rule_data in rules_data:
        rule = {
            "id": rule_data["id"],
            "name": rule_data["name"],
            "pattern": rule_data["pattern"],
            "target": rule_data["target"],
            "enabled": True,
            "severity": rule_data["severity"]
        }
        _rules.append(rule)
        _rules_by_id[rule_data["id"]] = rule


def get_rules():
    """Получить все правила"""
    return _rules


def get_rule(rule_id):
    """Получить правило по ID"""
    return _rules_by_id.get(rule_id)


def toggle_rule(rule_id, enabled):
    """Включить/выключить правило"""
    rule = _rules_by_id.get(rule_id)
    if rule:
        rule["enabled"] = enabled
        return True
    return False


def check_request(method, path, headers, query_string=None, body=None):
    """Проверить запрос на наличие атак"""
    triggered_rules = []
    # Нормализуем данные для проверки
    import urllib.parse
    decoded_path = urllib.parse.unquote(path)
    decoded_query = urllib.parse.unquote(query_string or "")
    # Нормализуем тело запроса
    decoded_body = ""
    if body:
        try:
            decoded_body = urllib.parse.unquote(body)
        except:
            decoded_body = body
    for rule in _rules:
        if not rule["enabled"]:
            continue
        pattern = rule["pattern"]
        target = rule["target"]
        # Проверка URL
        if target in ["url", "both"]:
            if pattern.search(decoded_path):
                triggered_rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "location": "URL"
                })
                continue
        # Проверка параметров запроса (query string)
        if target in ["query", "both"] and decoded_query:
            if pattern.search(decoded_query):
                triggered_rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "location": "Query string"
                })
                continue
        # Проверка тела POST запроса
        if target in ["body", "both"] and decoded_body:
            if pattern.search(decoded_body):
                triggered_rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "location": "Body"
                })
                continue
        # Проверка заголовков
        if target == "headers":
            headers_str = f"{headers.get('User-Agent', '')} {headers.get('Referer', '')}".lower()
            if pattern.search(headers_str):
                triggered_rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "location": "Headers"
                })
                continue

    return triggered_rules


# Инициализация
init_rules()