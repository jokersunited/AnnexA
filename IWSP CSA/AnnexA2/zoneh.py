import requests
import base64

from webdriver_manager.chrome import ChromeDriverManager
from selenium import webdriver
import bs4

from PIL import Image
import io

import time

#Initialize the selenium instance of grab the initial anti-crawling ZHE cookie
base_url = "http://zone-h.org/"
options = webdriver.ChromeOptions()
user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.50 Safari/537.36'
options.add_argument(f'user-agent={user_agent}')
options.add_argument('--headless')
options.add_argument('ignore-certificate-errors')
driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)
driver.get(base_url)
zhe_cookie = driver.get_cookie("ZHE")['value']

class Zoneh:
    def __init__(self, mirror, sess):

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
            'Cookie': sess
            # This is another valid field
        }

        self.mirror = mirror
        self.soup = self.get_mirror()

        self.informer = self.get_data("informer")
        self.system = self.get_data("system")
        self.url = self.get_data("url")
        self.server = self.get_data("server")
        self.ip = self.get_data("ip")

        print(self.informer, self.system, self.url, self.server, self.ip)

    def get_mirror(self):
        resp = requests.get("http://zone-h.org" + self.mirror, headers=self.headers)
        mirror_soup = bs4.BeautifulSoup(resp.content, features='lxml')
        return mirror_soup

    def get_data(self, field_type):
        try:
            if field_type == "informer":
                return self.soup.find_all('li', class_="defacef")[0].text.split(":")[1][1:]
            elif field_type == "system":
                return self.soup.find_all('li', class_="defacef")[1].text.split(":")[1][1:]
            elif field_type == "url":
                return self.soup.find_all('li', class_="defaces")[0].text[8:]
            elif field_type == "server":
                return self.soup.find_all('li', class_="defaces")[1].text.split(":")[1][1:]
            elif field_type == "ip":
                return self.soup.find_all('li', class_="defacet")[0].text.split(":")[1][1:]
        except Exception as e:
            print(e)
            return False

def get_captcha():
    resp = requests.get("http://zone-h.org/captcha.py")

    cookie = resp.headers['Set-Cookie'].split(";")[0] + "; " + "ZHE=" + zhe_cookie + ";"
    b64_img = base64.b64encode(resp.content)

    png_captcha = "data:image/png;base64," + b64_img.decode()
    return png_captcha, cookie

def get_zoneh(captcha, cookie):

    data = {
        "defacer": "",
        "domain": ".sg",
        "filter_date_select": "week",
        "filter_date_y": "",
        "filter_date_m": "",
        "filter_date_d": "",
        "filter": "1",
        "fulltext": "on",
        "published": "",
        "archivecaptcha": captcha
    }

    output_list = []

    final_resp = requests.post("http://zone-h.org/archive", headers={"Cookie": cookie}, data=data)
    if b'name="archivecaptcha"' in final_resp.content:
        return False
    elif b'If you often get this captcha when gathering data' in final_resp.content:
        return -1
    zoneh_soup = bs4.BeautifulSoup(final_resp.content, features='lxml')
    for entry in zoneh_soup.find_all("tr")[1:-2]:
        output_list.append(Zoneh(entry.find_all("td")[-1].find('a').get('href'), cookie))

    print(output_list)
    return output_list

# print(get_zoneh())
# Zoneh("/mirror/id/34837906")







