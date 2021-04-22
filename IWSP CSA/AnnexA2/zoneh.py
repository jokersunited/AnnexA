import requests
from random import randint

import bs4
from urllib.parse import urlparse

from threading import Thread, Lock

from urlclass import LiveUrl
from datetime import datetime

#Class to handle ZoneH crawling
class Zoneh:
    def __init__(self, mirror, sess):

        '''
        ZoneH class that contains information of each zoneh mirror
        :param mirror: the mirror <a> link extracted from the zoneh page
        :param sess:  the session cookie taken from the zoneh page
        '''
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
            'Cookie': sess
        }

        #Get the page source content
        self.mirror = "http://zone-h.org" + mirror
        self.soup = self.get_mirror()

        #If page is live, follow up and extract and save data into object variables
        if self.soup is not False:
            self.url = self.get_data("url")

            self.live = LiveUrl(self.url.split(":")[0] + "://" + urlparse(self.url).netloc)
            self.defacelive = LiveUrl(self.url)

            self.processed = False
            self.discard = False

            self.informer = self.get_data("informer")
            self.system = self.get_data("system")
            self.server = self.get_data("server")
            self.ip = self.get_data("ip")
            self.abuse = self.live.first_email()

            if self.defacelive.dns is False or self.defacelive.access is False:
                self.defacescreenshot = False
            else:
                self.defacescreenshot = self.defacelive.screenshot

            if self.live.dns is False or self.live.access is False:
                self.org = ""
                self.screenshot = False
            else:
                self.org = self.live.title
                self.screenshot = self.live.screenshot

            self.sec = ""

        print(self.informer, self.system, self.url, self.server, self.ip)

    #Consolidate class information into a dict object to append to dataframe
    def output(self):
        cn = ["CaseID", "Date", "Notifier", "Domain", "OS", "IndustrySector", "Organisation", "Mirror", "Platform", "AbuseEmail"]

        case_id = "SingCERT_" + datetime.today().strftime('%Y%m%d') + "-D" + str(randint(100000, 999999))

        out_dict = {}
        out_dict.update({cn[0]: case_id})
        out_dict.update({cn[1]: datetime.today().strftime('%d-%m-%Y')})
        out_dict.update({cn[2]: self.informer})
        out_dict.update({cn[3]: self.url})
        out_dict.update({cn[4]: self.system})
        out_dict.update({cn[5]: self.sec})
        out_dict.update({cn[6]: self.org})
        out_dict.update({cn[7]: self.mirror})
        out_dict.update({cn[8]: self.server})
        out_dict.update({cn[9]: self.abuse})

        return out_dict

    #Get the HTML source of the mirror page
    def get_mirror(self):
        resp = requests.get(self.mirror, headers=self.headers)
        if b'If you often get this captcha when gathering data' in resp.content:
            return False
        mirror_soup = bs4.BeautifulSoup(resp.content, features='lxml')
        return mirror_soup

    #Extract fields from the mirror page HTML source code
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

lock = Lock()
def zonehthread(output_list, entry, cookie):
    zone_h_entry = Zoneh(entry.find_all("td")[-1].find('a').get('href'), cookie)
    lock.acquire()
    output_list.append(zone_h_entry)
    lock.release()

#Function to get zoneh content for today using the cookies sent by the user
def get_zoneh(cookie):
    #Post request parameters to send to zoneh
    data = {
        "notifier": "",
        "domain": ".sg",
        "filter_date_select": "today",
        "filter": "1",
        "fulltext": "on",
    }

    #Initialise headers to send to zoneh along with session cookie
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
        "Host": "zone-h.org",
        "Origin": "http://zone-h.org",
        "Referer": "http://zone-h.org/archive",
        "Cookie": cookie,

    }

    output_list = []

    #
    final_resp = requests.post("http://zone-h.org/archive", headers=headers, data=data)
    print(final_resp.text)
    if b'name="archivecaptcha"' in final_resp.content:
        return False
    elif b'If you often get this captcha when gathering data' in final_resp.content:
        return False
    zoneh_soup = bs4.BeautifulSoup(final_resp.content, features='lxml')

    thread_list = []
    #For each entry, extract mirror link and create zoneh object saved into a list
    for entry in zoneh_soup.find_all("tr")[1:-2]:
        t1 = Thread(target=zonehthread, args=(output_list, entry, cookie))
        thread_list.append(t1)
        t1.start()
        # output_list.append(Zoneh(entry.find_all("td")[-1].find('a').get('href'), cookie))

    for t in thread_list:
        t.join()

    return output_list
