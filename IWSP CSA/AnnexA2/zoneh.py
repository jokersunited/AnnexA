import requests
import base64

from webdriver_manager.chrome import ChromeDriverManager
from selenium import webdriver
import bs4

from PIL import Image
import io

import time

def get_zoneh():
    base_url = "http://zone-h.org/"

    options = webdriver.ChromeOptions()
    user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.50 Safari/537.36'
    options.add_argument(f'user-agent={user_agent}')
    options.add_argument('--headless')
    options.add_argument('ignore-certificate-errors')
    driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)

    driver.get(base_url)
    cookie = driver.get_cookie("ZHE")['value']

    resp = requests.get("http://zone-h.org/captcha.py")

    image = Image.open(io.BytesIO(resp.content))
    image.show()

    cookie = resp.headers['Set-Cookie'].split(";")[0] + "; " + "ZHE=" + cookie + ";"
    b64_img = base64.b64encode(resp.content)

    png_captcha = "data:image/png;base64," + b64_img.decode()
    print(png_captcha)

    captcha = input("type captcha: ")

    data = {
        "defacer": "",
        "domain": ".sg",
        "filter_date_select": "today",
        "filter_date_y": "",
        "filter_date_m": "",
        "filter_date_d": "",
        "filter": "1",
        "fulltext": "on",
        "published": "0",
        "archivecaptcha": captcha
    }

    output_list = []

    final_resp = requests.post("http://zone-h.org/archive", headers={"Cookie": cookie}, data=data)
    zoneh_soup = bs4.BeautifulSoup(final_resp.content, features='lxml')
    for entry in zoneh_soup.find_all("tr")[1:-2]:
        output_list.append(entry.find_all("td")[7].text.replace("\n","").replace("\t", ""))

    return output_list

print(get_zoneh())


