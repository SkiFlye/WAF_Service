import time
from collections import defaultdict
from database.database import log_statistic, block_ip, is_ip_blocked, get_user_rules_enabled
from core.rules import get_rules

# Правила безопасности
RULES = get_rules()


class RateLimiter:
    """Rate limiter для каждого пользователя"""
    def __init__(self):
        self.requests = defaultdict(list)

    def check_and_record(self, user_id, client_ip, limit_per_minute):
        """Проверить и записать запрос"""
        key = f"{user_id}:{client_ip}"
        current_time = time.time()
        # Очищаем старые записи
        self.requests[key] = [ts for ts in self.requests[key] if current_time - ts < 60]
        current_count = len(self.requests[key])
        allowed = current_count < limit_per_minute
        if allowed:
            self.requests[key].append(current_time)
            remaining = limit_per_minute - current_count - 1
        else:
            remaining = 0
        return allowed, remaining


class WAFCore:
    """Ядро WAF для проверки запросов"""
    def __init__(self):
        self.rate_limiter = RateLimiter()

    def check_request(self, user_id, method, path, headers, query_string, body=None):
        """Проверить запрос на атаки (включая тело POST запроса)"""
        user_rules = get_user_rules_enabled(user_id)
        triggered_rules = []

        # Нормализуем данные
        import urllib.parse
        decoded_path = urllib.parse.unquote(path)
        decoded_query = urllib.parse.unquote(query_string or "")

        # Декодируем тело запроса
        decoded_body = ""
        if body:
            try:
                # Декодируем URL-encoding
                decoded_body = urllib.parse.unquote(body)
            except:
                decoded_body = body

        for rule in RULES:
            if str(rule["id"]) in user_rules and not user_rules[str(rule["id"])]:
                continue
            pattern = rule["pattern"]
            target = rule.get("target", "both")
            # 1. Проверка URL
            if target in ["url", "both"]:
                if pattern.search(decoded_path):
                    triggered_rules.append({
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "location": "URL"
                    })
                    continue
            # 2. Проверка параметров запроса
            if target in ["query", "both"] and decoded_query:
                if pattern.search(decoded_query):
                    triggered_rules.append({
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "location": "Query string"
                    })
                    continue
            # 3. Проверка декодированного тела POST запроса
            if target in ["body", "both"] and decoded_body:
                if pattern.search(decoded_body):
                    triggered_rules.append({
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "location": "Body"
                    })
                    continue
            # 4. Проверка заголовков
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

    def check_rate_limit(self, user_id, client_ip, rate_limit):
        """Проверить rate limit"""
        return self.rate_limiter.check_and_record(user_id, client_ip, rate_limit)

    def process_request(self, user_id, client_ip, method, path, headers, query_string, rate_limit, body=None):
        """Обработать запрос и вернуть решение"""
        # 1. Проверка блокировки IP
        if is_ip_blocked(user_id, client_ip):
            log_statistic(user_id, "rate_limited", method, path, client_ip)
            return {"action": "block", "reason": "rate_limit", "status": 429}
        # 2. Проверка rate limit
        allowed, remaining = self.check_rate_limit(user_id, client_ip, rate_limit)
        if not allowed:
            block_ip(user_id, client_ip, 60, "Rate limit exceeded")
            log_statistic(user_id, "rate_limited", method, path, client_ip)
            return {"action": "block", "reason": "rate_limit", "status": 429}
        # 3. Проверка на атаки
        triggered_rules = self.check_request(user_id, method, path, headers, query_string, body)
        if triggered_rules:
            # Логируем атаку
            rule_names = [r["name"] for r in triggered_rules]
            log_statistic(user_id, "blocked", method, path, client_ip,
                          rule_names[0] if rule_names else None,
                          triggered_rules[0]["severity"] if triggered_rules else None)
            # При множественных атаках блокируем IP дольше
            return {
                "action": "block",
                "reason": "attack",
                "status": 403,
                "rules": triggered_rules
            }
        # 4. Обычный запрос
        log_statistic(user_id, "normal", method, path, client_ip)
        return {"action": "pass", "status": 200}


waf_core = WAFCore()