from fetch_proxies import Proxies
import random
import requests
from time import time
import threading

# %%

class ProxyVault:
    def __init__(self):
        self.judges = ['http://azenv.net/', 'http://httpheader.net/azenv.php', 
                       'http://mojeip.net.pl/asdfa/azenv.php', 
                       'http://httpbin.org/get?show_env', 
                       'https://httpbin.org/get?show_env', 
                       'https://www.proxy-listen.de/azenv.php', 
                       'http://www.proxy-listen.de/azenv.php']
        self.user_agent = ['Mozilla/5.0 (X11; Linux i686; rv:64.0) Gecko/20100101 Firefox/64.0',
                           'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9a1) Gecko/20060814 Firefox/51.0',
                           'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/58.0.1',
                           'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1944.0 Safari/537.36',
                           'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.74 Safari/537.36 Edg/79.0.309.43']
        
        self.ip_addrs = self.get_ip_addrs()
        self.proxies = Proxies()
    

    def get_ip_addrs(self):
        urls = ['http://ipinfo.io/ip', 'https://api.ipify.org/']
        random.shuffle(urls)
        for url in urls:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return r.text.strip()
    
    def adjudicate(self, proxy, ls):
        ip = proxy['ip']
        port = proxy['port']
        advertised_proto = proxy['proto']
        if 'http' in advertised_proto:
            protocols = ['http']
        else:
            protocols = ['socks4', 'socks5', 'http']
        
        print(f'{ip}:{port}')

        proxytype = []
        for proto in protocols:
            proxy_dict = {'http': f'{proto}://{ip}:{port}',
                          'https': f'{proto}://{ip}:{port}'}
            headers = {'User-Agent': random.choice(self.user_agent)}
            
            results = {'ip': ip, 'port':port}
            try:
                start = time()
                r = requests.get(self.judges[0], headers=headers, 
                                 proxies=proxy_dict, timeout=5)
                runtime = time() - start

                proxytype.append(proto)
                results['type'] = proxytype
                results['runtime'] = f'{runtime:.3f}'
                results['active'] = True
                if self.ip_addrs in r.text:
                    results['anon'] = False
                else:
                    results['anon'] = True

            except Exception as e:
                continue
        
        if 'active' not in results:
            results['active'] = False
        
        ls.append(results)
    
    def google_verify(self, proxy, ls):
        ip = proxy['ip']
        port = proxy['port']
        for proto in proxy['type']:
            proxy_dict = {'http': f'{proto}://{ip}:{port}',
                        'https': f'{proto}://{ip}:{port}'}
            headers = {'User-Agent': random.choice(self.user_agent)}
            
            try:
                r = requests.get('https://www.google.com/', headers=headers, proxies=proxy_dict, timeout=5)
                print(f'success on {proto}\t{ip}:{port}')
                ls.append(proxy)
            except Exception as e:
                return



proxy_vault = ProxyVault() #TODO multiple adjudicators, geolocation

results = []
threads = []
for proxy in proxy_vault.proxies.unique_proxies:
    thread = threading.Thread(target=proxy_vault.adjudicate, args=(proxy, results,))
    thread.start()
    threads.append(thread)
# Wait for all threads to finish
for thread in threads:
    thread.join()

active_proxies = [i for i in results if i['active']]
socks_proxies = [i for i in active_proxies if i['type'][0] != 'http']
# quick_proxies = [i for i in active_proxies if float(i['runtime']) < 0.1]

# for proxy in quick_proxies:
#     print(f'{proxy["type"][0]}\t{proxy["ip"]} {proxy["port"]}')


google_proxies = []
threads = []
for proxy in active_proxies:
    thread = threading.Thread(target=proxy_vault.google_verify, 
                              args=(proxy, google_proxies,))
    thread.start()
    threads.append(thread)
# Wait for all threads to finish
for thread in threads:
    thread.join()

content = []
for proxy in google_proxies:
    ip = proxy['ip']
    port = proxy['port']
    content.append(f'{ip}:{port}')

with open('google_proxies.txt', 'w') as w:
    w.write('\n'.join(content))