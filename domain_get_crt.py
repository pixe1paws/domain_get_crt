import requests
import re
import sys
import datetime
import socket

def get_subdomains(domain):
    try:
        # Формируем URL для запроса
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        
        # Отправляем GET-запрос
        response = requests.get(url)
        response.raise_for_status() # Проверяем успешность запроса
        
        # Извлекаем данные в формате JSON
        data = response.json()
        
        # Извлекаем поддомены из JSON-ответа
        subdomains = set()
        for entry in data:
            # Извлекаем все поддомены из поля common_name
            found_subdomains = re.findall(r'\b\w.+\.' + re.escape(domain) + r'\b', entry['name_value'])
            subdomains.update(found_subdomains)
        
        return subdomains
        
    except requests.RequestException as e:
        print(f"Ошибка при запросе к crt.sh: {e}")
        return set()

def resolve_ip(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except socket.gaierror:
        return "Не удалось получить IP"

def save_scan_results(domain, subdomains):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{domain}_{timestamp}.txt"
    
    with open(filename, 'w') as file:
        file.write(f"Отчет по сканированию домена: {domain}\n")
        file.write(f"Дата сканирования: {timestamp}\n\n")
        file.write(f"Найдено поддоменов: {len(subdomains)}\n\n")
        
        if subdomains:
            for subdomain in sorted(subdomains):
                ip = resolve_ip(subdomain)
                file.write(f"{subdomain} - {ip}\n")
        else:
            file.write("Поддомены не найдены\n")

def main():
    if len(sys.argv) != 2:
        print("Использование: python script.py example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    subdomains = get_subdomains(domain)
    
    if subdomains:
        print(f"Найдено поддоменов для {domain}:")
        for subdomain in sorted(subdomains):
            ip = resolve_ip(subdomain)
            print(f"{subdomain} - {ip}")
            
        save_scan_results(domain, subdomains)
        print(f"\nРезультаты сохранены в файл: {domain}_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt")
    else:
        print("Поддомены не найдены")

if __name__ == "__main__":
    main()