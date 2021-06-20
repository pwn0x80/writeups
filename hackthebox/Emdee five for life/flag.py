import requests
from bs4 import BeautifulSoup
import hashlib
import re


url = 'http://138.68.158.87:30522/'

r = requests.session()
res = r.get(url)
soup = BeautifulSoup(res.text, 'lxml')
string = soup.select('h3', align='center')[0].text


send = r.post(url=url, data={'hash':  hashlib.md5(
    string.encode('utf-8')).hexdigest()})

send = send.text
clean = re.compile('<.*?>')
a = re.sub(clean, '', send)
a = a.split('string')[1].rstrip()

print(a[20:])
