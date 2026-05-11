import requests

PROXY_URL = "https://waf-service--matveynikiforof.replit.app/"
API_KEY = "C_hMdJIDzOv9YGWx0JSG2s1hMiTZZQyXjeeC8k90YnI"

def print_result(test_name, response, expected_status):
    print(f" {test_name}")
    print(f" Статус: {response.status_code} (ожидался {expected_status})")
    if response.status_code == expected_status:
        print(f"   ✅ УСПЕШНО")
    else:
        print(f"   ❌ ОШИБКА")

# GET ЗАПРОСЫ
print("GET ЗАПРОСЫ:")

# 1. Нормальный GET
resp = requests.get(f"{PROXY_URL}/", headers={"X-API-Key": API_KEY})
print_result("Нормальный GET", resp, 200)

# 2. SQL инъекция
resp = requests.get(f"{PROXY_URL}/get?id=1' OR '1'='1", headers={"X-API-Key": API_KEY})
print_result("GET с SQL инъекцией", resp, 403)

# 3. XSS атака
resp = requests.get(f"{PROXY_URL}/get?q=<script>alert(1)</script>", headers={"X-API-Key": API_KEY})
print_result("GET с XSS", resp, 403)

# POST ЗАПРОСЫ
print("\n" + "POST ЗАПРОСЫ:")

# 4. SQL инъекция в теле
resp = requests.post(f"{PROXY_URL}/login",
                     headers={"X-API-Key": API_KEY},
                     data="username=admin' OR '1'='1&password=123")
print_result("POST с SQL инъекцией", resp, 403)

# 5. XSS в теле
resp = requests.post(f"{PROXY_URL}/comment",
                     headers={"X-API-Key": API_KEY},
                     data="comment=<script>alert('XSS')</script>")
print_result("POST с XSS", resp, 403)

# 6. UNION SELECT
resp = requests.post(f"{PROXY_URL}/search",
                     headers={"X-API-Key": API_KEY},
                     data="q=test UNION SELECT password FROM users")
print_result("POST с UNION SELECT", resp, 403)

# 7. JSON с SQL инъекцией
resp = requests.post(f"{PROXY_URL}/api/login",
                     headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
                     json={"username": "admin' OR '1'='1", "password": "123"})
print_result("POST JSON с SQL инъекцией", resp, 403)

# PUT ЗАПРОСЫ

print("\n" + "PUT ЗАПРОСЫ:")
# 8. PUT с SQL инъекцией
resp = requests.put(f"{PROXY_URL}/users/1",
                    headers={"X-API-Key": API_KEY},
                    json={"id": "1' OR '1'='1", "name": "Hacked"})
print_result("PUT с SQL инъекцией", resp, 403)

# 9. PUT с XSS
resp = requests.put(f"{PROXY_URL}/users/1",
                    headers={"X-API-Key": API_KEY},
                    json={"comment": "<script>alert('XSS')</script>"})
print_result("PUT с XSS", resp, 403)

# 10. PUT с Command Injection
resp = requests.put(f"{PROXY_URL}/exec",
                    headers={"X-API-Key": API_KEY},
                    json={"cmd": "; ls -la"})
print_result("PUT с Command Injection", resp, 403)

# DELETE ЗАПРОСЫ

print("\n" + "DELETE ЗАПРОСЫ:")

# 11. DELETE с SQL инъекцией
resp = requests.delete(f"{PROXY_URL}/users/1?id=1' OR '1'='1",
                       headers={"X-API-Key": API_KEY})
print_result("DELETE с SQL инъекцией", resp, 403)

# 12. DELETE с XSS
resp = requests.delete(f"{PROXY_URL}/users/1?name=<script>alert(1)</script>",
                       headers={"X-API-Key": API_KEY})
print_result("DELETE с XSS", resp, 403)

# 13. DELETE с Path Traversal
resp = requests.delete(f"{PROXY_URL}/users/1?file=../../../etc/passwd",
                       headers={"X-API-Key": API_KEY})
print_result("DELETE с Path Traversal", resp, 403)