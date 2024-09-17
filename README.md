# ProxyScrape
## Overview
A web-scraping script that collects thousands of free proxies from multiple web pages, including:
- Free Proxy List
- VPNFail
- Proxyscrape
- Open Proxy List
- Spys One (with some javascript deobfuscation and reverse engineering)

## Takeaways
Most of this project is relatively simple webscraping and pandas data consolidation until I had to figure out how to bypass SpysOne's bot prevention mechanisms which was a fun intro-level web exploitation challenge. This was probably the project that first set me on my way to begin CTF challenges. It was also my first time getting hands-on with regular expressions.

I began this project in the hopes of proxychaining tor with a free proxy so I could access the clearnet without being blacklisted by websites, but at the time (early 2023) I didn't really understand networking. The free proxies are strongly not recommended for actual use as everyone and their mother already has them blacklisted, but there's some potentially fun statistical analysis that can be conducted with this database of free proxies. 
