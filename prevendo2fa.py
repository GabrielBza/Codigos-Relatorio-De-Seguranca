from datetime import datetime, timezone, timedelta
from hashlib import sha256

ano = 2025#Sinalize aqui o ano
mes = 10#Sinalize aqui o mês
dia = 17#Sinalize aqui o dia
hora = 23#Sinalize aqui a hora
minuto = 59#Sinalize aqui o minuto
segundo = 59#Sinalize aqui o segundo


# Data-Hora para segundos
tz_minus3 = timezone(timedelta(hours=-3))
dt_loc_brasil = datetime(ano, mes, dia, hora, minuto, segundo, tzinfo=tz_minus3)
epoch_loc_brasil = int(dt_loc_brasil.timestamp())
print("'Agora' em segundos:", epoch_loc_brasil)

# Janela de tempo = Data-Hora/TTL
t_window_brasil = epoch_loc_brasil//15
print("Time Window: ", t_window_brasil)

# Seed
seed_brasil = "glhf_secret:"+str(t_window_brasil)
print("Seed: ", seed_brasil)

# Tira o hash da seed_brasil
digest_hex_brasil = sha256(seed_brasil.encode("utf-8")).hexdigest()
print("SHA-256 (hex):", digest_hex_brasil)

# Pega os 8 primeiros hex (32 bits)
prefix8_brasil = digest_hex_brasil[:8]
print("Primeiros 8 hex:", prefix8_brasil)

# Converte para inteiro base 16
value_32bits_brasil = int(prefix8_brasil, 16)
print("Inteiro (base16 -> dec):", value_32bits_brasil)

code4_brasil = str(value_32bits_brasil % 10000).zfill(4)
print("Código 4 dígitos:", code4_brasil)