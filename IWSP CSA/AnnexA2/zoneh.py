import requests
import base64
from random import randint

from webdriver_manager.chrome import ChromeDriverManager
from selenium import webdriver
import bs4
from urllib.parse import urlparse

from urlclass import LiveUrl
from datetime import datetime

from PIL import Image
import io

import time

# Initialize the selenium instance of grab the initial anti-crawling ZHE cookie
# base_url = "http://zone-h.org/"
# options = webdriver.ChromeOptions()
# user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.50 Safari/537.36'
# options.add_argument(f'user-agent={user_agent}')
# options.add_argument('--headless')
# options.add_argument('ignore-certificate-errors')
# driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)
# driver.get(base_url)
#
#
# def get_session():
#     resp = requests.get("http://zone-h.org/captcha.py")
#
#     sess = resp.headers['Set-Cookie'].split(";")[0]
#     return sess
#
#
# sess = get_session()
# zhe_cookie = driver.get_cookie("ZHE")['value']
#
# cookie = sess + "; " + "ZHE=" + zhe_cookie
# print(zhe_cookie)
# print(sess)
# print(cookie)


class Zoneh:
    def __init__(self, mirror, sess):

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
            'Cookie': sess
        }

        self.mirror = "http://zone-h.org" + mirror
        self.soup = self.get_mirror()

        if self.soup is not False:
            self.url = self.get_data("url")

            self.live = LiveUrl(self.url.split(":")[0] + "://" + urlparse(self.url).netloc)

            self.processed = False
            self.discard = False

            self.informer = self.get_data("informer")
            self.system = self.get_data("system")
            self.server = self.get_data("server")
            self.ip = self.get_data("ip")

            if self.live.dns is False or self.live.access is False:
                self.org = ""
                self.screenshot = False
            else:
                self.org = self.live.title
                self.screenshot = self.live.screenshot

            self.sec = ""

        print(self.informer, self.system, self.url, self.server, self.ip)

    def output(self):
        cn = ["Date", "Notifier", "Domain", "OS", "IndustrySector", "Organisation", "Mirror", "Platform"]

        case_id = "SingCERT_" + datetime.today().strftime('%Y%m%d') + "-A" + str(randint(100000, 999999))

        out_dict = {}
        out_dict.update({cn[0]: datetime.today().strftime('%d-%m-%Y')})
        out_dict.update({cn[1]: self.informer})
        out_dict.update({cn[2]: self.url})
        out_dict.update({cn[3]: self.system})
        out_dict.update({cn[4]: self.sec})
        out_dict.update({cn[5]: self.org})
        out_dict.update({cn[6]: self.mirror})
        out_dict.update({cn[7]: self.server})

        return out_dict

    def get_mirror(self):
        resp = requests.get(self.mirror, headers=self.headers)
        if b'If you often get this captcha when gathering data' in resp.content:
            return False
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
    resp = requests.get("http://zone-h.org/captcha.py", headers={"Cookie": None})

    b64_img = base64.b64encode(resp.content)

    png_captcha = "data:image/png;base64," + b64_img.decode()
    return png_captcha


def get_zoneh(cookie):

    print(cookie)

    data = {
        "notifier": "",
        "domain": ".sg",
        "filter_date_select": "week",
        "filter": "1",
        "fulltext": "on",
    }

    headers = {
        # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
        "Host": "zone-h.org",
        "Origin": "http://zone-h.org",
        "Referer": "http://zone-h.org/archive",
        "Cookie": cookie,

    }

    output_list = []

    final_resp = requests.post("http://zone-h.org/archive", headers=headers, data=data)
    if b'name="archivecaptcha"' in final_resp.content:
        return False
    elif b'If you often get this captcha when gathering data' in final_resp.content:
        return -1
    zoneh_soup = bs4.BeautifulSoup(final_resp.content, features='lxml')
    for entry in zoneh_soup.find_all("tr")[1:-2]:
        output_list.append(Zoneh(entry.find_all("td")[-1].find('a').get('href'), cookie))

    return output_list




# print(get_zoneh())
# Zoneh("/mirror/id/34837906")
