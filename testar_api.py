import requests

API_KEY = "a183b8f33e7517797fbb37e9e97cc10ed66c0abe99c77b5a010dbfe8f5cd95ebdd959782"
URL_BLING = "https://bling.com.br/Api/v2/produtos/json"  # Endpoint de produtos (exemplo)

params = {
    "apikey": API_KEY  # O Bling geralmente usa a chave como parâmetro "apikey"
}

try:
    response = requests.get(URL_BLING, params=params)
    
    if response.status_code == 200:
        print("✅ Chave válida! Resposta do Bling:")
        print(response.json())  # Dados dos produtos (exemplo)
    else:
        print(f"❌ Erro HTTP {response.status_code}")
        print("Resposta do servidor:", response.text)

except requests.exceptions.SSLError:
    # Caso persista erro de SSL (improvável no Bling, mas pode ocorrer em redes restritas)
    print("⚠️ Erro de SSL. Tentando sem verificação (NÃO RECOMENDADO PARA PRODUÇÃO):")
    response = requests.get(URL_BLING, params=params, verify=False)
    print("Resposta (sem verificação SSL):", response.json())

except requests.exceptions.RequestException as e:
    print(f"⚠️ Falha na conexão: {e}")