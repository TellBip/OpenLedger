from curl_cffi import requests
from fake_useragent import FakeUserAgent
from datetime import datetime
from colorama import *
import asyncio, random, base64, uuid, json, os, pytz
from web3 import Web3
from eth_account import Account
import binascii
import re
import hashlib
from eth_account.messages import encode_defunct
import sys
import urllib.parse

# Инициализация colorama для правильного отображения цветов
init(autoreset=True)

wib = pytz.timezone('Europe/Berlin')

class OepnLedger:
    def __init__(self) -> None:
        self.extension_id = "chrome-extension://ekbbplmjjgoobhdlffmgeokalelnmjjc"
        self.headers = {
            "Accept": "*/*",
            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
            "Origin": self.extension_id,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Storage-Access": "active",
            "User-Agent": FakeUserAgent().random
        }
        self.proxies = []
        self.proxy_index = 0
        self.account_proxies = {}

    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def log(self, message):
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().strftime('%x %X')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}{message}",
            flush=True
        )

    def welcome(self):
        telegram_link = "https://t.me/+1fc0or8gCHsyNGFi"
        print(f"""
        {Fore.GREEN + Style.BRIGHT}
  ____                   _              _                 
 / __ \                 | |            | |                
| |  | |_ __   ___ _ __ | |     ___  __| | __ _  ___ _ __ 
| |  | | '_ \ / _ \ '_ \| |    / _ \/ _` |/ _` |/ _ \ '__|
| |__| | |_) |  __/ | | | |___|  __/ (_| | (_| |  __/ |   
 \____/| .__/ \___|_| |_|______\___|\__,_|\__, |\___|_|   
       | |                                 __/ |          
       |_|                                |___/           
     
        {Style.RESET_ALL}
{Fore.GREEN + Style.BRIGHT}Developed by: {Fore.BLUE + Style.BRIGHT}@Tell_Bip{Style.RESET_ALL}
{Fore.GREEN + Style.BRIGHT}Our Telegram channel:{Style.RESET_ALL} {Fore.BLUE + Style.BRIGHT}\x1b]8;;{telegram_link}\x07{telegram_link}\x1b]8;;\x07{Style.RESET_ALL}
        """)

    def format_seconds(self, seconds):
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    
    def load_accounts(self):
        filename = "data/accounts.json"
        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED}File {filename} not found.{Style.RESET_ALL}")
                return

            with open(filename, 'r') as file:
                data = json.load(file)
                if isinstance(data, list):
                    return data
                return []
        except json.JSONDecodeError:
            return []
    
    async def load_proxies(self, use_proxy_choice: int):
        filename = "data/proxy.txt"
        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED + Style.BRIGHT}File {filename} not found.{Style.RESET_ALL}")
                return
            with open(filename, 'r') as f:
                self.proxies = f.read().splitlines()
            
            if not self.proxies:
                self.log(f"{Fore.RED + Style.BRIGHT}No proxies found.{Style.RESET_ALL}")
                return

            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Total proxies: {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{len(self.proxies)}{Style.RESET_ALL}"
            )
        
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}Failed To Load Proxies: {e}{Style.RESET_ALL}")
            self.proxies = []

    def check_proxy_schemes(self, proxies):
        schemes = ["http://", "https://", "socks4://", "socks5://"]
        if any(proxies.startswith(scheme) for scheme in schemes):
            return proxies
        return f"http://{proxies}"

    def format_proxy_url(self, proxy_str):
        """Форматирует URL прокси для безопасного использования со сложными именами пользователей и паролями"""
        if not proxy_str:
            return None
            
        # Проверяем, содержит ли прокси схему
        schemes = ["http://", "https://", "socks4://", "socks5://"]
        scheme = "http://"
        for s in schemes:
            if proxy_str.startswith(s):
                scheme = s
                proxy_str = proxy_str[len(s):]
                break
        
        # Разделяем на части: user:pass@host:port
        if '@' in proxy_str:
            auth, hostport = proxy_str.split('@', 1)
            
            # Кодируем только имя пользователя и пароль
            if ':' in auth:
                user, password = auth.split(':', 1)
                auth = f"{urllib.parse.quote(user)}:{urllib.parse.quote(password)}"
            else:
                auth = urllib.parse.quote(auth)
                
            return f"{scheme}{auth}@{hostport}"
        else:
            return f"{scheme}{proxy_str}"
        
    def get_next_proxy_for_account(self, account):
        if account not in self.account_proxies:
            if not self.proxies:
                return None
            proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
            self.account_proxies[account] = proxy
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.format_proxy_url(self.account_proxies[account])

    def rotate_proxy_for_account(self, account):
        if not self.proxies:
            return None
        proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
        self.account_proxies[account] = proxy
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.format_proxy_url(proxy)
    
    def generate_register_message(self, address: str, worker_id: str, browser_id: str, msg_type: str):
        register_message = {
            "workerID":worker_id,
            "msgType":msg_type,
            "workerType":"LWEXT",
            "message":{
                "id":browser_id,
                "type":msg_type,
                "worker":{
                    "host":self.extension_id,
                    "identity":worker_id,
                    "ownerAddress":address,
                    "type":"LWEXT"
                }
            }
        }
        return register_message
    
    def generate_heartbeat_message(self, address: str, worker_id: str, msg_type: str, memory: int, storage: str):
        heartbeat_message = {
            "message":{
                "Worker":{
                    "Identity":worker_id,
                    "ownerAddress":address,
                    "type":"LWEXT",
                    "Host":self.extension_id,
                    "pending_jobs_count":0
                },
                "Capacity":{
                    "AvailableMemory":memory,
                    "AvailableStorage":storage,
                    "AvailableGPU":"",
                    "AvailableModels":[]
                }
            },
            "msgType":msg_type,
            "workerType":"LWEXT",
            "workerID":worker_id
        }
        return heartbeat_message
    
    def generate_browser_id(self):
        browser_id = str(uuid.uuid4())
        return browser_id
        
    def generate_worker_id(self, account: str):
        identity = base64.b64encode(account.encode("utf-8")).decode("utf-8")
        return identity
    
    def print_message(self, account, proxy, color, message):
        self.log(
            f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} {account} {Style.RESET_ALL}"
            f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
            f"{Fore.CYAN + Style.BRIGHT} Proxy: {Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT}{proxy}{Style.RESET_ALL}"
            f"{Fore.MAGENTA + Style.BRIGHT} - {Style.RESET_ALL}"
            f"{Fore.CYAN + Style.BRIGHT}Status:{Style.RESET_ALL}"
            f"{color + Style.BRIGHT} {message} {Style.RESET_ALL}"
            f"{Fore.CYAN + Style.BRIGHT}]{Style.RESET_ALL}"
        )

    def print_question(self):
        while True:
            try:
                print(f"{Fore.GREEN + Style.BRIGHT}1. Farm & Claim Daily Reward with Proxy{Style.RESET_ALL}")
                print(f"{Fore.GREEN + Style.BRIGHT}2. Farm & Claim Daily Reward without Proxy{Style.RESET_ALL}")
                print(f"{Fore.RED + Style.BRIGHT}3. Exit{Style.RESET_ALL}")
                choose = int(input("Choose action [1/2/3] -> ").strip())

                if choose == 1:
                    print(f"{Fore.GREEN + Style.BRIGHT}Starting Farm mode with proxy.{Style.RESET_ALL}")
                    return 1
                elif choose == 2:
                    print(f"{Fore.GREEN + Style.BRIGHT}Starting Farm mode without proxy.{Style.RESET_ALL}")
                    return 2
                elif choose == 3:
                    print(f"{Fore.RED + Style.BRIGHT}Exiting program.{Style.RESET_ALL}")
                    sys.exit(0)
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Please enter 1, 2 or 3.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter a number (1, 2 or 3).{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print(f"\n{Fore.RED + Style.BRIGHT}Program interrupted by user.{Style.RESET_ALL}")
                sys.exit(0)
    
    async def get_private_key(self, address):
        accounts = self.load_accounts()
        for acc in accounts:
            if acc["Address"].lower() == address.lower():
                try:
                    private_key = acc["Private_Key"]
                    
                    # Check key format (64 hex characters)
                    if len(private_key) == 64 and all(c in "0123456789abcdefABCDEF" for c in private_key):
                        formatted_key = "0x" + private_key
                        try:
                            account = Account.from_key(formatted_key)
                            if account.address.lower() == address.lower():
                                self.print_message(address, '', Fore.GREEN, "Found valid key")
                                return formatted_key
                        except Exception:
                            pass
                    
                    self.log(f"{Fore.RED}Invalid private key format for address: {address}{Style.RESET_ALL}")
                    return None
                    
                except Exception as e:
                    self.log(f"{Fore.RED}Error processing private key: {e}{Style.RESET_ALL}")
                    return None
                
        self.log(f"{Fore.RED}No account found for address: {address}{Style.RESET_ALL}")
        return None
    
    def decrypt_data(self, encrypted_hex, email):
        # Убираем префикс 0x
        if encrypted_hex.startswith("0x"):
            encrypted_hex = encrypted_hex[2:]
            
        # Создаем секретный ключ на основе email
        secret_key = base64.b64encode(email.encode("utf-8")).decode("utf-8")
        
        # Генерируем ключ шифрования с помощью SHA256
        key_bytes = hashlib.sha256(secret_key.encode("utf-8")).digest()
        
        # Преобразуем hex в байты
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        
        # Первые 16 байт - IV (вектор инициализации)
        iv = encrypted_bytes[:16]
        encrypted_data = encrypted_bytes[16:]
        
        # Расшифровываем используя XOR
        decrypted = bytearray(len(encrypted_data))
        for i in range(len(encrypted_data)):
            decrypted[i] = encrypted_data[i] ^ key_bytes[i % len(key_bytes)]
            
        # Возвращаем первые 64 символа в виде hex строки
        decrypted_hex = decrypted.hex()
        if len(decrypted_hex) >= 64:
            return "0x" + decrypted_hex[:64]

    def decrypt_direct(self, encrypted_hex, email):
        # Используем последний вариант из extension
        if encrypted_hex.startswith("0x"):
            encrypted_hex = encrypted_hex[2:]
        
        # Используем email как соль напрямую
        key_bytes = hashlib.sha256(email.encode("utf-8")).digest()
        
        # Дополнительное логирование
        self.log(f"Email: {email}, Key hash: {key_bytes.hex()[:10]}...")
        
        # Расшифровка без разделения на IV
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        decrypted = bytearray(len(encrypted_bytes))
        
        for i in range(len(encrypted_bytes)):
            decrypted[i] = encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)]
        
        # Возвращаем весь результат для анализа
        self.log(f"Full decrypted: {decrypted.hex()}")
        
        # Ищем возможные ключи в результате
        return "0x" + decrypted.hex()[:64]

    async def claim_checkin_reward(self, address: str, token: str, use_proxy: bool, proxy=None, checkin_data=None):
        try:
            # Если данные о чекине не переданы, используем уже имеющиеся
            if not checkin_data or not checkin_data.get('claimed', True) == False:
                self.print_message(address, proxy, Fore.YELLOW, "Daily Check-In Reward Is Already Claimed or Data Missing")
                return {'claimed': True}
                
            # Получаем приватный ключ для подписи транзакции
            private_key = await self.get_private_key(address)
            if not private_key:
                self.print_message(address, proxy, Fore.RED, "Private key not found or invalid")
                return None
                
            #self.log(f"{Fore.CYAN}Creating and signing transaction for claim_reward{Style.RESET_ALL}")
            
            # 1. Получаем необходимые данные для транзакции через RPC
            try:
                # Создаем общую сессию для всех запросов
                import requests
                from requests.adapters import HTTPAdapter
                from urllib3.util.retry import Retry
                
                # Создаем сессию с повторными попытками
                session = requests.Session()
                retry = Retry(total=3, backoff_factor=0.5)
                adapter = HTTPAdapter(max_retries=retry)
                session.mount('http://', adapter)
                session.mount('https://', adapter)
                
                # Если используем прокси, применяем его к сессии
                if use_proxy and proxy:
                    formatted_proxy = self.format_proxy_url(proxy)
                    session.proxies = {'http': formatted_proxy, 'https': formatted_proxy}
                    self.print_message(address, proxy, Fore.GREEN, "Using proxy for API/RPC connections")
                
                # Создаем провайдер с поддержкой прокси
                provider = Web3.HTTPProvider("https://rpctn.openledger.xyz/", session=session)
                w3 = Web3(provider)
                
                # Получаем chainId
                chain_id = w3.eth.chain_id
                #self.log(f"{Fore.CYAN}Chain ID: {chain_id}{Style.RESET_ALL}")
                
                # Получаем nonce для адреса
                nonce = w3.eth.get_transaction_count(Web3.to_checksum_address(address))
                #self.log(f"{Fore.CYAN}Nonce: {nonce}{Style.RESET_ALL}")
                
                # Получаем текущую цену газа
                gas_price = w3.eth.gas_price
                #self.log(f"{Fore.CYAN}Gas price: {gas_price}{Style.RESET_ALL}")
                
                # Адрес контракта
                contract_address = "0x5d2cd1059b67ed3ae2d153149c8cedceb3344b9b"
                
                # Получаем текущие timestamp и данные о награде
                try:
                    reward_point = int(checkin_data.get('dailyPoint', 10))
                except:
                    #self.log(f"{Fore.YELLOW}Не удалось преобразовать dailyPoint в число, используем значение по умолчанию 10{Style.RESET_ALL}")
                    reward_point = 10
                
                # Получаем соль и подпись из данных сервера
                server_signature = checkin_data.get('signature')
                salt = checkin_data.get('salt')
                
                if not server_signature or salt is None:
                    #self.log(f"{Fore.RED}Не найдена подпись или соль в данных чекина!{Style.RESET_ALL}")
                    return None
                
                salt_value = int(salt) if isinstance(salt, (int, str)) else salt
                #self.log(f"{Fore.CYAN}Параметры из сервера: reward_point={reward_point}, salt={salt_value}, signature={server_signature}{Style.RESET_ALL}")
                
                # Расшифровываем подпись сервера
                try:
                    sig = server_signature
                    if sig.startswith('0x'):
                        sig = sig[2:]
                    
                    # Стандартная структура подписи - последние 2 символа v, первые 64 - r, следующие 64 - s
                    v = int(sig[-2:], 16)
                    r_hex = sig[:64]  # без 0x
                    s_hex = sig[64:128]  # без 0x
                    
                    # Ethereum подписи обычно имеют v = 27 или 28
                    if v < 27:
                        v += 27
                    
                    #self.log(f"{Fore.CYAN}Расшифрованная подпись сервера: v={v}, r={r_hex[:10]}..., s={s_hex[:10]}...{Style.RESET_ALL}")
                except Exception as e:
                    #self.log(f"{Fore.RED}Ошибка при разборе подписи сервера: {str(e)}{Style.RESET_ALL}")
                    return None
                
                # Проверяем длину параметров подписи
                if len(r_hex) != 64 or len(s_hex) != 64:
                    #self.log(f"{Fore.RED}Неверная длина параметров подписи: r={len(r_hex)}, s={len(s_hex)}, должно быть 64{Style.RESET_ALL}")
                    return None
                
                # Формируем данные для вызова dailyClaim(uint256 pointsValue, uint256 salt, Sign calldata sign)
                # Используем функцию dailyClaim из контракта (0x8aca7c1a)
                function_selector = "0x8aca7c1a"  # Селектор функции dailyClaim
                
                # Кодируем параметры в соответствии с ABI
                data = function_selector
                
                # pointsValue (uint256)
                data += hex(reward_point)[2:].zfill(64)
                
                # salt (uint256)
                data += hex(salt_value)[2:].zfill(64)
                
                # Sign структура (v, r, s) - v должно быть закодировано как uint8
                data += hex(v)[2:].zfill(64)  # v
                data += r_hex  # r (без 0x)
                data += s_hex  # s (без 0x)
                
                # Обеспечиваем префикс 0x
                if not data.startswith('0x'):
                    data = '0x' + data
                
                #self.log(f"{Fore.CYAN}Данные транзакции для dailyClaim: {data}{Style.RESET_ALL}")
                
                # Формируем полную транзакцию
                tx_params = {
                    'chainId': chain_id,
                    'nonce': nonce,
                    'gasPrice': gas_price,
                    'gas': 300000,  # Фиксированный газлимит
                    'to': Web3.to_checksum_address(contract_address),
                    'value': 0,
                    'data': data,
                    'accessList': []
                }
                #self.log(f"{Fore.CYAN}Параметры транзакции: {tx_params}{Style.RESET_ALL}")
                
                # Проверяем длину параметров подписи
                try:
                    if len(r_hex) != 64:
                        #self.log(f"{Fore.RED}ОШИБКА: неправильная длина r={len(r_hex)}, должно быть 64{Style.RESET_ALL}")
                        if len(r_hex) > 64:
                            r_hex = r_hex[-64:]  # берем последние 64 символа (32 байта)
                            #self.log(f"{Fore.YELLOW}Обрезаем r до 64 символов{Style.RESET_ALL}")
                        else:
                            r_hex = r_hex.zfill(64)  # дополняем до 64 символов
                            #self.log(f"{Fore.YELLOW}Дополняем r до 64 символов{Style.RESET_ALL}")
                    
                    if len(s_hex) != 64:
                        #self.log(f"{Fore.RED}ОШИБКА: неправильная длина s={len(s_hex)}, должно быть 64{Style.RESET_ALL}")
                        if len(s_hex) > 64:
                            s_hex = s_hex[-64:]  # берем последние 64 символа (32 байта)
                            #self.log(f"{Fore.YELLOW}Обрезаем s до 64 символов{Style.RESET_ALL}")
                        else:
                            s_hex = s_hex.zfill(64)  # дополняем до 64 символов
                            #self.log(f"{Fore.YELLOW}Дополняем s до 64 символов{Style.RESET_ALL}")
                except Exception as e:
                    self.log(f"{Fore.RED}Ошибка при проверке длины подписи: {str(e)}{Style.RESET_ALL}")
                
                #self.log(f"{Fore.CYAN}Данные транзакции для claimReward: {data}{Style.RESET_ALL}")
                
                contract_address = "0x5d2cd1059b67ed3ae2d153149c8cedceb3344b9b"
                gas_limit = 300000
                
                # Транзакция типа EIP-2930 (0x01)
                tx_params = {
                    'chainId': chain_id,
                    'nonce': nonce,
                    'gasPrice': gas_price,
                    'gas': 300000,  # Фиксированный газлимит
                    'to': Web3.to_checksum_address(contract_address),
                    'value': 0,
                    'data': data,
                    'accessList': []
                }
                #self.log(f"{Fore.CYAN}Параметры перед подписью: {tx_params}{Style.RESET_ALL}")
                
                # Добавляем эту строку - создаем объект аккаунта
                account = Account.from_key(private_key)
                
                signed_tx = account.sign_transaction(tx_params)
                if hasattr(signed_tx, 'rawTransaction'):
                    signed_tx_hex = signed_tx.rawTransaction.hex()
                else:
                    signed_tx_hex = signed_tx.raw_transaction.hex()
                
                if not signed_tx_hex.startswith('0x'):
                    signed_tx_hex = '0x' + signed_tx_hex
                    
                #self.log(f"{Fore.CYAN}Подписанная транзакция: {signed_tx_hex}{Style.RESET_ALL}")
                
                # Проверка, что данные включены в подписанную транзакцию
                function_selector_bytes = "8aca7c1a"
                if function_selector_bytes not in signed_tx_hex:
                    #self.log(f"{Fore.RED}КРИТИЧЕСКАЯ ОШИБКА: data отсутствует в подписанной транзакции!{Style.RESET_ALL}")
                    # Попробуем исправить, добавив prefix 0x к данным
                    if not data.startswith('0x'):
                        data = '0x' + data
                        
                    tx_params['data'] = data
                    signed_tx = account.sign_transaction(tx_params)
                    if hasattr(signed_tx, 'rawTransaction'):
                        signed_tx_hex = signed_tx.rawTransaction.hex()
                    else:
                        signed_tx_hex = signed_tx.raw_transaction.hex()
                    
                    if not signed_tx_hex.startswith('0x'):
                        signed_tx_hex = '0x' + signed_tx_hex
                    
                    # Проверим еще раз
                    if function_selector_bytes not in signed_tx_hex:
                        #self.log(f"{Fore.RED}Не удалось исправить: data отсутствует в подписанной транзакции!{Style.RESET_ALL}")
                        return None
                    #self.log(f"{Fore.GREEN}Транзакция исправлена, данные добавлены: {signed_tx_hex}{Style.RESET_ALL}")
                
                # Инициализация переменных для отслеживания результатов
                blockchain_success = False
                claim_response = None
                api_success = False
                
                # Сначала отправляем через API
                try:
                    #self.log(f"{Fore.CYAN}Сначала отправляем запрос через API{Style.RESET_ALL}")
                    
                    # Обновляем nonce перед отправкой в API
                    api_nonce = w3.eth.get_transaction_count(Web3.to_checksum_address(address), 'pending')
                    #self.log(f"{Fore.CYAN}Nonce для API-запроса: {api_nonce}{Style.RESET_ALL}")
                    
                    # Создаем транзакцию с текущим nonce для API
                    tx_params_api = tx_params.copy()
                    tx_params_api['nonce'] = api_nonce
                    
                    # Подписываем транзакцию
                    signed_tx_api = account.sign_transaction(tx_params_api)
                    if hasattr(signed_tx_api, 'rawTransaction'):
                        signed_tx_hex_api = signed_tx_api.rawTransaction.hex()
                    else:
                        signed_tx_hex_api = signed_tx_api.raw_transaction.hex()
                    
                    if not signed_tx_hex_api.startswith('0x'):
                        signed_tx_hex_api = '0x' + signed_tx_hex_api
                    
                    claim_url = "https://rewardstn.openledger.xyz/ext/api/v2/claim_reward"
                    headers = {
                        **self.headers,
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json"
                    }
                    
                    api_payload = {
                        "signedTx": signed_tx_hex_api
                    }
                    
                    #self.log(f"{Fore.CYAN}Отправляем в API signedTx: {api_payload}{Style.RESET_ALL}")
                    
                    # Используем созданную сессию для API-запроса вместо прямого вызова curl_cffi
                    from curl_cffi import requests as curl_requests
                    claim_response = await asyncio.to_thread(
                        curl_requests.post,
                        url=claim_url,
                        headers=headers,
                        json=api_payload,
                        proxy=formatted_proxy if use_proxy and proxy else None,
                        timeout=60,
                        impersonate="safari15_5",
                        verify=False
                    )
                    #self.log(f"{Fore.CYAN}Ответ API: {claim_response.text}{Style.RESET_ALL}")
                    
                    # Определяем успех API-ответа
                    try:
                        response_data = claim_response.json()
                        api_success = claim_response.status_code == 200 and response_data.get('status') == 'SUCCESS'
                        
                        # Проверим, не содержит ли ошибка сообщение о том, что награда уже получена
                        if not api_success and response_data.get('message') and ('already claimed' in response_data.get('message').lower() or 'has been claimed' in response_data.get('message').lower() or 'claim already executed' in response_data.get('message').lower()):
                            self.log(f"{Fore.GREEN}API reports that reward has already been claimed{Style.RESET_ALL}")
                            api_success = True
                    except Exception as e:
                        self.log(f"{Fore.RED}Error processing API response: {str(e)}{Style.RESET_ALL}")
                    
                    if api_success:
                        self.print_message(address, proxy, Fore.GREEN, "Reward successfully claimed via API")
                        return {'claimed': True}  # Возвращаем успех если API сообщает об успехе
                
                except Exception as api_e:
                    self.print_message(address, proxy, Fore.RED, f"Error processing reward via API: {str(api_e)}")
                
                # Проверяем текущий статус награды
                try:
                    checkin_status = await self.checkin_details(address, token, use_proxy, proxy)
                    if checkin_status and checkin_status.get('claimed', False):
                        #self.log(f"{Fore.GREEN}Проверка показала, что награда уже получена!{Style.RESET_ALL}")
                        self.print_message(address, proxy, Fore.GREEN, "Reward successfully claimed (status check)")
                        return {'claimed': True}
                except Exception as check_e:
                    self.log(f"{Fore.RED}Error processing status check: {str(check_e)}{Style.RESET_ALL}")
                
                # Если мы дошли до этой точки, значит и API, и проверка статуса не подтвердили успех
                error_message = "Error processing reward via API"
                #if claim_response and hasattr(claim_response, 'text'):
                    #error_message += f": {claim_response.text}"
                #self.print_message(address, proxy, Fore.RED, error_message)
                return None
                
            except Exception as e:
                self.print_message(address, proxy, Fore.RED, f"Transaction creation or signing failed: {Fore.YELLOW + Style.BRIGHT}{str(e)}")
                proxy = self.rotate_proxy_for_account(address) if use_proxy else None
                await asyncio.sleep(5)
                return None
                
        except Exception as e:
            self.print_message(address, proxy, Fore.RED, f"Claim Daily Check-In Reward Failed: {Fore.YELLOW + Style.BRIGHT}{str(e)}")
            proxy = self.rotate_proxy_for_account(address) if use_proxy else None
            await asyncio.sleep(5)
            return None
            
    async def checkin_details(self, address: str, token: str, use_proxy: bool, proxy=None):
        url = "https://rewardstn.openledger.xyz/ext/api/v2/claim_details"
        headers = {
            **self.headers,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        try:
            formatted_proxy = self.format_proxy_url(proxy) if use_proxy and proxy else None
            response = await asyncio.to_thread(requests.get, url=url, headers=headers, proxy=formatted_proxy, timeout=60, impersonate="safari15_5", verify=False)
            response.raise_for_status()
            result = response.json()
            return result['data']
        except Exception as e:
            self.print_message(address, proxy, Fore.RED, f"GET Daily Check-In Data Failed: {Fore.YELLOW + Style.BRIGHT}{str(e)}")
            proxy = self.rotate_proxy_for_account(address) if use_proxy else None
            await asyncio.sleep(5)
            return None
        
    async def process_claim_checkin_reward(self, address: str, token: str, use_proxy: bool):
        while True:
            proxy = self.get_next_proxy_for_account(address) if use_proxy else None
            checkin = await self.checkin_details(address, token, use_proxy, proxy)
            if checkin:
                is_claimed = checkin['claimed']
                #is_claimed = ''
                reward = checkin['dailyPoint']

                if not is_claimed:
                    claim = await self.claim_checkin_reward(address, token, use_proxy, proxy, checkin)

                    if claim and claim.get('claimed'):
                        self.print_message(address, proxy, Fore.GREEN,
                            f"Daily Check-In Reward Is Claimed "
                            f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                            f"{Fore.CYAN + Style.BRIGHT} Reward: {Style.RESET_ALL}"
                            f"{Fore.WHITE + Style.BRIGHT}{reward} PTS{Style.RESET_ALL}"
                        )
                    else:
                        self.print_message(address, proxy, Fore.RED,
                            "Daily Check-In Reward Isn't Claimed"
                        )
                else:
                    self.print_message(address, proxy, Fore.YELLOW,
                        "Daily Check-In Reward Is Already Claimed"
                    )
            await asyncio.sleep(24 * 60 * 60)

    async def nodes_communicate(self, address: str, token: str, msg_type: str, payload: dict, use_proxy: bool, proxy=None):
        url = "https://apitn.openledger.xyz/ext/api/v2/nodes/communicate"
        data = json.dumps(payload)
        headers = {
            **self.headers,
            "Authorization": f"Bearer {token}",
            "Content-Length": str(len(data)),
            "Content-Type": "application/json"
        }
        while True:
            try:
                formatted_proxy = self.format_proxy_url(proxy) if use_proxy and proxy else None
                response = await asyncio.to_thread(requests.post, url=url, headers=headers, data=data, proxy=formatted_proxy, timeout=60, impersonate="safari15_5", verify=False)
                response.raise_for_status()
                return response.json()
            except Exception as e:
                self.print_message(address, proxy, Fore.RED, f"{msg_type} Failed: {Fore.YELLOW + Style.BRIGHT}{str(e)}")
                proxy = self.rotate_proxy_for_account(address) if use_proxy else None
                await asyncio.sleep(5)
        
    async def process_accounts(self, address: str, token: str, use_proxy: bool):
        worker_id = self.generate_worker_id(address)
        browser_id = self.generate_browser_id()
        memory = round(random.uniform(0, 32), 2)
        storage = str(round(random.uniform(0, 500), 2))

        for msg_type in ["REGISTER", "HEARTBEAT"]:
            if msg_type == "REGISTER":
                proxy = self.get_next_proxy_for_account(address) if use_proxy else None
                payload = self.generate_register_message(address, worker_id, browser_id, msg_type)
                register = await self.nodes_communicate(address, token, msg_type, payload, use_proxy, proxy)
                if register:
                    self.print_message(address, proxy, Fore.GREEN, f"{msg_type} Success: {Fore.BLUE + Style.BRIGHT}{register}")
                print(
                    f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().astimezone(wib).strftime('%x %X %Z')} ]{Style.RESET_ALL}"
                    f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
                    f"{Fore.BLUE + Style.BRIGHT}Wait For 5 Minutes For Next Ping...{Style.RESET_ALL}",
                    end="\r"
                )
                await asyncio.sleep(5 * 60)
            elif msg_type == "HEARTBEAT":
                payload = self.generate_heartbeat_message(address, worker_id, msg_type, memory, storage)
                while True:
                    proxy = self.get_next_proxy_for_account(address) if use_proxy else None
                    heartbeat = await self.nodes_communicate(address, token, msg_type, payload, use_proxy, proxy)
                    if heartbeat:
                        self.print_message(address, proxy, Fore.GREEN, f"{msg_type} Success: {Fore.BLUE + Style.BRIGHT}{heartbeat}")
                    print(
                        f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().astimezone(wib).strftime('%x %X %Z')} ]{Style.RESET_ALL}"
                        f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
                        f"{Fore.BLUE + Style.BRIGHT}Wait For 5 Minutes For Next Ping...{Style.RESET_ALL}",
                        end="\r"
                    )
                    await asyncio.sleep(5 * 60)

    async def main(self):
        try:
            accounts = self.load_accounts()
            if not accounts:
                self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded.{Style.RESET_ALL}")
                return
            self.welcome()
            choice = self.print_question()  # Now method returns 1 (Farm with proxy), 2 (Farm without proxy) or exits program

            self.clear_terminal()
            self.welcome()
            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Total accounts: {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{len(accounts)}{Style.RESET_ALL}"
            )

            # Загружаем прокси только если выбран режим с прокси
            use_proxy = (choice == 1)
            if use_proxy:
                await self.load_proxies(choice)
                if not self.proxies:
                    self.log(f"{Fore.RED+Style.BRIGHT}No proxies loaded. Cannot continue in proxy mode.{Style.RESET_ALL}")
                    return
                self.log(f"{Fore.GREEN + Style.BRIGHT}Using proxy mode for farming.{Style.RESET_ALL}")
            else:
                self.log(f"{Fore.GREEN + Style.BRIGHT}Using direct connection mode (no proxy) for farming.{Style.RESET_ALL}")
                
            self.log(f"{Fore.CYAN + Style.BRIGHT}-{Style.RESET_ALL}"*75)

            while True:
                tasks = []
                for account in accounts:
                    if account:
                        address = account["Address"]
                        token = account["Access_Token"]
                        if address and token:
                            tasks.append(asyncio.create_task(self.process_accounts(address, token, use_proxy)))
                            tasks.append(asyncio.create_task(self.process_claim_checkin_reward(address, token, use_proxy)))

                await asyncio.gather(*tasks)
                await asyncio.sleep(10)

        except Exception as e:
            self.log(f"{Fore.RED+Style.BRIGHT}Error: {e}{Style.RESET_ALL}")
            raise e
            
if __name__ == "__main__":
    try:
        bot = OepnLedger()
        asyncio.run(bot.main())
    except KeyboardInterrupt:
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().astimezone(wib).strftime('%x %X %Z')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
            f"{Fore.RED + Style.BRIGHT}[ EXIT ] OpenLedger - BOT STOPPED{Style.RESET_ALL}                                       "                              
        )