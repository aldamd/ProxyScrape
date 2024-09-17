import requests
from bs4 import BeautifulSoup
from requests.exceptions import ConnectTimeout
import json
import re
import cloudscraper
import threading

# %%

class FreeProxyList:
    def __init__(self):
        self.url = 'https://free-proxy-list.net/'
        self.proxies = self.get_proxies()
    

    def get_proxies(self):
        formatted_list = []
        
        r = requests.get(self.url)
        if r.status_code != 200:
            print('ERROR: could not collect freeproxylist proxies')
        else:
            soup = BeautifulSoup(r.text, 'html.parser')
            table = soup.find('table')

            rows = table.find_all('tr')
            for row in rows[1:]:
                ip, port, _, _, _, _, proto, _ = [i.text for i in row.find_all('td')]
                formatted_list.append({'ip': ip, 'port': port, 'proto': proto})
        
        return formatted_list


class VPNFail:
    def __init__(self):
        self.url = "https://vpn.fail/free-proxy/json"
        self.proxies = self.get_proxies()


    def get_proxies(self):
        formatted_list = []
        
        r = requests.get(self.url)
        if not r.ok:
            print('ERROR: could not collect vpnfail proxies')
        else:
            proxy_list = json.loads(r.text)
            for proxy in proxy_list:
                if ':' in proxy['proxy']:
                    ip, port = proxy['proxy'].split(':')
                    formatted_list.append({'ip': ip, 'port': port, 'proto': proxy['type']})
        
        return formatted_list


class Proxyscrape:
    def __init__(self):
        url = {'http': "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000",
               "https": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=10000",
               'socks4': "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000",
               'socks5': "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000"}
        proxies = []
        threads = []
        for protocol, url in url.items():
            thread = threading.Thread(target=self.get_proxies, 
                                      args=(protocol, url, proxies,))
            thread.start()
            threads.append(thread)
        # Wait for all threads to finish
        for thread in threads:
            thread.join()
        
        self.proxies = proxies


    @staticmethod
    def get_proxies(protocol, url, proxy_list):        
        r = requests.get(url)
        if not r.ok:
            print(f'ERROR Could not collect {protocol} proxies from proxyscrape')
            return
        
        proxies = r.text.splitlines()
        for proxy in proxies:
            if ':' in proxy:
                ip, port = proxy.split(':')
                proxy_list.append({'ip': ip, 'port': port, "proto": protocol})
            else:
                continue


class OpenProxyList:
    def __init__(self):
        url = {'http': "https://openproxylist.xyz/http.txt",
               'socks4': "https://openproxylist.xyz/socks4.txt",
               'socks5': "https://openproxylist.xyz/socks5.txt"}
        proxies = []
        threads = []
        for protocol, url in url.items():
            thread = threading.Thread(target=self.get_proxies, 
                                      args=(protocol, url, proxies,))
            thread.start()
            threads.append(thread)
        # Wait for all threads to finish
        for thread in threads:
            thread.join()
        
        self.proxies = proxies


    @staticmethod
    def get_proxies(protocol, url, proxy_list):    
        r = requests.get(url)
        if not r.ok:
            print(f'ERROR Could not collect {protocol} proxies from openproxylist')
            return
        
        proxies = r.text.splitlines()
        for proxy in proxies:
            if ':' in proxy:
                ip, port = proxy.split(':')
                proxy_list.append({'ip': ip, 'port': port, "proto": protocol})
            else:
                continue
        

class Geonode:
    def __init__(self):
        self.url = {'http': "https://openproxylist.xyz/http.txt",
                    'socks4': "https://openproxylist.xyz/socks4.txt",
                    'socks5': "https://openproxylist.xyz/socks5.txt"}
        self.proxies = self.get_proxies()


    def get_proxies(self):
        formatted_list = []
        with requests.Session() as s:
            s.get('https://geonode.com/free-proxy-list')
            for protocol, url in self.url.items():
                r = s.get(url)
                if not r.ok:
                    print(f'ERROR Could not collect {protocol} proxies from geonode')
                    continue

                proxies = r.text.splitlines()
                for proxy in proxies:
                    if ':' in proxy:
                        ip, port = proxy.split(':')
                        formatted_list.append({'ip': ip, 'port': port, "proto": protocol})
                    else:
                        continue
        
        return formatted_list


class SpysOne:
    def __init__(self):
        proxies = []
        threads = []
        for url in ['https://spys.one/proxies/', 'https://spys.one/socks/']:
            thread = threading.Thread(target=self.scrape_proxies, args=(url, proxies,))
            thread.start()
            threads.append(thread)
        # Wait for all threads to finish
        for thread in threads:
            thread.join()
        
        self.proxies = proxies


    @staticmethod
    def base36encode(number, alphabet='0123456789abcdefghijklmnopqrstuvwxyz'):
        """Converts an integer to a base36 string."""
        if not isinstance(number, int):
            raise TypeError('number must be an integer')

        base36 = ''
        sign = ''

        if number < 0:
            sign = '-'
            number = -number

        if 0 <= number < len(alphabet):
            return sign + alphabet[number]

        while number != 0:
            number, i = divmod(number, len(alphabet))
            base36 = alphabet[i] + base36

        return sign + base36

    def find_string_representation(self, num, radix=60):
        """Assigns alphanumeric equivalent to input number [A-Za-z0-9]."""
        if num < radix:
            result = ""
        else:
            result = self.find_string_representation(int(num/radix))
        
        num = num % radix
        if num > 35:
            result += chr(num+29)
        else:
            result += self.base36encode(num)

        return result

    def assemble_decoder(self, keychain):
        """Creates decoder hashmap. Will be used to decode Spys.One port numbers"""
        decoder = {}
        for num in range(59,9,-1):
            character = self.find_string_representation(num)
            key = keychain[num]
            decoder[character] = key
        
        return decoder

    @staticmethod
    def alchemy(equation, decoder):
        """Deconstructs original encoded string, decodes, and reconstructs. 
        Adds the discovered, 2nd layer encryptions to the decoder for further
        future decryption"""
        if not equation:
            return equation
        
        lhs, rhs = equation.split('=')
        if lhs in decoder:
            lhs = decoder[lhs]

        components = rhs.split('^')
        for idx, component in enumerate(components):
            if component in decoder:
                new_component = decoder[component]
                components[idx] = new_component

        decoder[lhs] = rhs
        equation = '='.join([lhs, rhs])

        return equation

    @staticmethod
    def rectify_decoder(decoder):
        """Finds and stores any 3rd and final layer decryptions in the decoder hashmap
        given the 2nd layer decryption items already stored during the alchemy() function"""
        for key, val in decoder.items():
            if '^' in val:
                operand1, operand2 = val.split('^')
                while True:
                    if operand1 in decoder:
                        operand1 = decoder[operand1]
                    elif operand2 in decoder:
                        operand2 = decoder[operand2]
                    else:
                        break
                val = int(operand1) ^ int(operand2)
                decoder[key] = val

    def unlock_str(self, locked_str, decoder):
        """Decrypts the encrypted port string variables and compiles the workable decoder"""
        unlocked_chunks = []
        for chunk in locked_str.split(';'):
            unlocked_chunks.append(self.alchemy(chunk, decoder))
        
        unlocked_str = ';'.join(unlocked_chunks)
        self.rectify_decoder(decoder)
        
        return unlocked_str, decoder

    @staticmethod
    def get_decoder_variables(soup):
        """Finds the webpage's encrypted port string and the variable keychain"""
        obf_script = soup.find('script', {'type': 'text/javascript'}).text

        locked_str = re.search(r"\w=[\da-zA-z][\^;].*;", obf_script).group() #[' or ;](word_character=[digit or a-z or A-Z][^ or ;]ANYTHING;)
        keychain = re.search(r"\^{2,}[\w\^]+", obf_script).group().split('^') #at least 2 "^" followed by either word characters or ^'s

        return locked_str, keychain

    @staticmethod
    def get_session_id(resp):
        """Finds the webpage's session ID (for post request to see more than 25 proxies)"""
        soup = BeautifulSoup(resp.text, 'html.parser')
        session_id = soup.find('input', {'name': 'xx0'}).attrs['value']

        return session_id

    def scrape_proxies(self, url, proxies):        
        """Scrapes input Spys.One webpage for proxies"""
        with cloudscraper.create_scraper() as session:
            resp = session.post(url)
            if resp.status_code != 200:
                print('ERROR: Could not get proxies from Spys.one')
                return
            
            data = {'xx0': self.get_session_id(resp), 'xpp': '3'}
            resp = session.post(url, data=data)
        
        soup = BeautifulSoup(resp.text, 'html.parser')

        locked_str, keychain = self.get_decoder_variables(soup)
        decoder = self.assemble_decoder(keychain)
        unlocked_str, decoder = self.unlock_str(locked_str, decoder)

        rows = soup.find_all('tr', {'class': 'spy1x'})[1:] \
            + soup.find_all('tr', {'class': 'spy1xx'})[1:]
        
        for row in rows:
            ip, protocol = [i.text for i in row.find_all('td')[:2]]
            protocol = protocol.split()[0].lower()
            port = row.find('script').contents[0]
            port = re.findall("\w+\^\w+", port) #word_character(s)^word_character(s)
            for idx, operation in enumerate(port):
                lhs, rhs = [int(decoder[i]) for i in operation.split('^')]
                port[idx] = str(lhs ^ rhs)
            port = ''.join(port)
            
            proxies.append({'ip': ip, 'port': port, "proto": protocol})


class Proxies:
    def __init__(self):
        self.freeproxylist = FreeProxyList()
        self.vpnfail = VPNFail()
        self.proxyscrape = Proxyscrape()
        self.openproxylist = OpenProxyList()
        self.geonode = Geonode()
        self.spysone = SpysOne()
        self.unique_proxies = self.get_unique_proxies()

    def get_unique_proxies(self):
        masterlist = self.freeproxylist.proxies + self.vpnfail.proxies + \
            self.proxyscrape.proxies + self.openproxylist.proxies + \
                self.geonode.proxies + self.spysone.proxies
        unique_proxies = list({f"{x['ip']}:{x['port']}": x for x in masterlist}.values())

        return unique_proxies


# %%

#https://checkerproxy.net/
#https://xseo.in/proxylist
#https://www.proxynova.com/proxy-server-list/country-us/
#https://www.my-proxy.com/free-proxy-list.html
#http://free-proxy.cz/en/
#https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-1
