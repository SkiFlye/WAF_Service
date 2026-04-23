# Конфигурация WAF сервиса

# Прокси сервер
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 8080

# Upstream сервер
UPSTREAM_HOST = "httpbin.org"  # тестовый сервер
UPSTREAM_PORT = 80
UPSTREAM_SSL = False

# Flask
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
FLASK_DEBUG = True

RATE_LIMIT = 60  # запросов в минуту

# Логи
LOG_FILE = "../logs/waf.log"
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 3