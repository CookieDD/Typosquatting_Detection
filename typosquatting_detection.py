#!/usr/bin/env python3
import queue
import re
import shutil
import traceback

import IndicatorTypes
import boto3
import botocore
import whois
import threading
import os
import psutil
import yaml
import logging
import pytz
import socket
import json
import requests
import vt

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.timeouts import Timeouts
from whois.parser import PywhoisError
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from OTXv2 import OTXv2

CUR_TIME_ZONE = "nz"
VERSION_ALERT = "Discrepancy!"
NUM_OF_THREAD = 20  # thread number for scanners and scrapers
VALID_DAYS = 31
new_black_count = 0

common_word_file = ""  # words that can be inserted to domain names and cause confusion
tld_file_name = ""  # tlds that mutate the domain name

whois_servers = ['whois.NameBright.com', 'whois.godaddy.com', ]
abused_tlds = []
common_words = []
keywords = []  # words that are related to eroad/coretex products/projects
trusted_domains = []  # eroad/coretex's own domains

aws_config = {}
threat_view_ips = {}  # to resolve the 'same ip lookup in 15mins" error. Holds the first lookup result, if error triggers, retrieve the score.

white_list = {}
black_list = {}
abuseIPDB_record = {}
unable_to_open_record = {}

existing_domain_status = dict()  # records each domain's malicious status, the ones with False status would not go to whitelist in the end.

scanner_queueLock = threading.Lock()  # locks threads to get domain from work_queue
scarper_queueLock = threading.Lock()  # locks scrapers
counter_lock = threading.Lock()  # locks threads to increment the counter for the detected domains

work_queue = queue.Queue()  # queue that contains domain permutations
webcontent_queue = queue.Queue()  # queue that contains domains to scrape
suspicious_queue = queue.Queue()  # queue that contains domains detected suspicious, later for screen capture

scanner_threads = []  # scanner objects to run
scraper_threads = []  # scraper objects to run

vt_key = ""
abuIPDB_key = ""
alienVault_key = ""
count = 0


# Line 68 updated for test12


def main():
    global aws_config
    global tld_file_name, common_word_file
    global keywords
    global vt_key, abuIPDB_key, alienVault_key
    global existing_domain_status
    global white_list, black_list
    global trusted_domains
    global unable_to_open_record
    global abuseIPDB_record
    global VALID_DAYS
    global new_black_count

    config_file_name_s3 = "config.yaml"

    with open('aws_config.yaml', 'r') as aws_config_stream:
        try:
            aws_config = yaml.safe_load(aws_config_stream)
            config_file = read_3s_bucket_objs(config_file_name_s3)
            configurations = yaml.safe_load(config_file)

            trusted_domains = configurations['eroad_domains']
            tld_file_name = configurations['tld_file']
            common_word_file = configurations['common_word']
            keywords = configurations['key_words']
            vt_key = configurations['vt_key']
            abuIPDB_key = configurations['abuseipdb_key']
            threat_view_files = configurations["threat_view"]

            white_list_file = configurations["white_list"]
            black_list_file = configurations["black_list"]

            load_tlds(tld_file_name)
            load_common_words(common_word_file)

            load_white_list(white_list_file)
            load_black_list(black_list_file)

            if white_black_versions_consistency(white_list['version'], black_list['version']):

                check_lived_days()

                read_threatView_ips(threat_view_files)

                audit_log("Configurations loaded")

                for domain in trusted_domains:
                    run_multi_scanners(domain)
                audit_log(f"Whois lookup completes, obtained {len(existing_domain_status)} records for further lookup")

                check_domain_record_with_apis(existing_domain_status)
                load_non_suspicious_to_web_q()

                run_multi_scrapper()

                if suspicious_queue.qsize() > 0:
                    zip_file_name = browser_make_captures(suspicious_queue)
                    upload_file_to_s3(zip_file_name)
                else:
                    audit_log(f"No website to be captured.")

                write_to_list(white_list_file, black_list_file)
                upload_file_to_s3(white_list_file)
                upload_file_to_s3(black_list_file)
                log_file_name = audit_log("Uploade log to s3")
                upload_file_to_s3(log_file_name)

                audit_log(
                    f"Scanning and scrapping finish. Please check the screenshot folder and "
                    f"the white/black lists for details.")

        except Exception as e:
            print("Main Exception " + str(e) + " --> \n" + traceback.format_exc())

    aws_config_stream.close()


# <- General config loadings ->

def upload_file_to_s3(file_name):
    # uses for blacklist, whitelist, screenshots
    s3 = boto3.session.Session(region_name=aws_config['aws_credentials']['region_name']).resource("s3")
    file = s3.Object(aws_config['s3_bucket_name'], file_name)
    file.put(Body=open(os.path.basename(file_name), 'rb'))
    if os.path.isdir(file_name) is True:
        shutil.rmtree(os.path.basename(file_name))
    os.remove(file_name)


def read_3s_bucket_objs(obj_name):
    s3 = boto3.session.Session(region_name=aws_config['aws_credentials']['region_name']).resource("s3")
    obj = s3.Object(aws_config['s3_bucket_name'], obj_name)  # bucket name, object name
    try:
        file_content = obj.get()['Body'].read().decode('utf-8')
        return file_content
    except s3.meta.client.exceptions.NoSuchKey:
        return False
    except botocore.exceptions.ClientError:
        return False


def white_black_versions_consistency(white_version, black_version):
    if black_version == white_version:
        return True
    else:
        audit_log(
            f"<-WARNING->Version discrepancy between white and black lists.\n<-WARNING->Check if data has compromised")
        audit_log(f"<-ALERT-> Program stops due to version discrepancy.")
        return False


def check_lived_days():
    global white_list, black_list
    global VALID_DAYS

    day_lived = check_days(white_list['version'], white_list['days'])
    if day_lived > VALID_DAYS:
        white_list['domains'] = {}
        white_list['version'] = get_tz_current_date().strftime("%Y-%m-%d")
        white_list['days'] = 0
        black_list['domains'] = {}
        black_list['version'] = get_tz_current_date().strftime("%Y-%m-%d")
        black_list['days'] = 0
        audit_log(
            f'<-Attention->{day_lived - VALID_DAYS} days overdue, white list and black list domains will be '
            f'wiped and overwritten')
    else:
        audit_log(f'Lists lived {day_lived} days. Last version of white list and black list will be used.')


def check_days(last_list_date, last_lived_days):
    cur_date = get_tz_current_date()
    last_date = datetime.strptime(last_list_date, "%Y-%m-%d").date()
    days_lived = (cur_date - last_date).days
    return days_lived + last_lived_days


def load_non_suspicious_to_web_q():
    for domain in existing_domain_status:
        if existing_domain_status[domain]["reliable"]:
            audit_log(f"Putting {domain} to web scrapping queue.")
            webcontent_queue.put(domain)
    audit_log(f"{webcontent_queue.qsize()} domains will be further scrapped.")


def load_tlds(tld_file=tld_file_name):
    global abused_tlds
    with open(tld_file) as file:
        for tld in file.read().splitlines():
            if re.match(r'^[a-z0-9-]{2,63}(\.[a-z0-9-]{2,63}){0,1}$', tld) and tld not in abused_tlds:
                abused_tlds.append(tld)
    audit_log(f"Loaded abused_tld names from file {tld_file}")
    file.close()


def load_common_words(word_file=common_word_file):
    global common_words
    with open(word_file) as file:
        for word in file.read().splitlines():
            if word.isalnum() and word not in common_words:
                common_words.append(word)
    audit_log(f"Loaded common_tld names from file {word_file}")
    file.close()


def load_white_list(white_list_name):
    global white_list

    white_list_content = read_3s_bucket_objs(white_list_name)
    if white_list_content:
        audit_log(f"White list exists in s3 bucket, load to local list dictionary.")
        white_list = yaml.safe_load(white_list_content)
    else:
        audit_log(f"White list does not exist in s3 bucket, will initialize a local dicionary.")
        white_list = {"ips": {}, "domains": {}, "version": get_tz_current_date().strftime("%Y-%m-%d"), "days": 0}


def load_black_list(black_list_name):
    global black_list

    black_list_content = read_3s_bucket_objs(black_list_name)
    if black_list_content:
        audit_log(f"Black list exists in s3 bucket, load to local list dictionary.")
        black_list = yaml.safe_load(black_list_content)
    else:
        audit_log(f"Black list does not exist in s3 bucket, will initialize a local dicionary.")
        black_list = {"ips": {}, "domains": {}, "version": get_tz_current_date().strftime("%Y-%m-%d"), "days": 0}


# <- Write to lists ->

def write_to_list(white_list_path, black_list_path):
    global white_list, black_list, existing_domain_status, new_black_count

    new_record_white = False
    new_white_count = 0
    new_record_black = False
    new_black_count = 0

    for record in existing_domain_status:
        if record not in white_list["domains"] and existing_domain_status[record]["reliable"]:
            white_list["domains"][record] = existing_domain_status[record]
            new_record_white = True
            new_white_count += 1
            audit_log(f"New Whitelist record added {record}")
        if record not in black_list['domains'] and not existing_domain_status[record]['reliable']:
            black_list['domains'][record] = existing_domain_status[record]
            new_record_black = True
            new_black_count += 1
            audit_log(f"New blacklist record added {record}")
    audit_log(f"{len(white_list['domains'])} domains in WHITE list. {new_white_count} records added.")
    audit_log(f"{len(black_list['domains'])} domains in BLACK list. {new_black_count} records added.")

    with open(white_list_path, "w") as white_list_stream:
        new_version = get_tz_current_date().strftime("%Y-%m-%d")
        cur_version = datetime.strptime(white_list['version'], "%Y-%m-%d").date()
        new_day_to_live = (get_tz_current_date() - cur_version).days + white_list['days']
        white_list["version"] = new_version
        white_list['days'] = new_day_to_live
        yaml.dump(white_list, white_list_stream)
        if new_record_white:
            audit_log(f"New Record updated in White List")
        else:
            audit_log(f"No updates made to white list")
    white_list_stream.close()

    with open(black_list_path, "w") as black_list_stream:
        new_version = get_tz_current_date().strftime("%Y-%m-%d")
        cur_version = datetime.strptime(black_list['version'], "%Y-%m-%d").date()
        new_day_to_live = (get_tz_current_date() - cur_version).days + black_list['days']
        black_list["version"] = new_version
        black_list['days'] = new_day_to_live
        yaml.dump(black_list, black_list_stream)
        if new_record_black:
            audit_log(f"New Record updated in Black List")
        else:
            audit_log(f"No updates made to black list")
    black_list_stream.close()

    return new_black_count


# <- Threat view look ups ->

def get_req_header_for_threat_view(file_url):
    req = Request(
        url=file_url,
        headers={'User-Agent': 'Mozilla/5.0'}
    )
    return req


def read_threat_view_file(file_url):
    req_header = get_req_header_for_threat_view(file_url)
    return urlopen(req_header).readlines()


def read_threatView_ips(threat_view_files):
    global threat_view_ips

    C2_file = threat_view_files[0]["C2_feed"]
    webpage_C2 = read_threat_view_file(C2_file)
    for line in webpage_C2:
        try:
            ip_recorded = line.decode('utf-8').split()[0].split(",")[0]
            threat_view_ips[ip_recorded] = "C2_file"
        except Exception:
            pass

    IOC_file = threat_view_files[1]["IOC_feed"]
    webpage_IOC = read_threat_view_file(IOC_file)
    for line in webpage_IOC:
        try:
            # ip_recorded = line.decode('utf-8').split()[0].split(",")[0]
            ip_recorded = line.decode('utf-8')
            if len(ip_recorded.split(".")[0]) <= 3:
                threat_view_ips[ip_recorded.split("\n")[0]] = "IOC_file"
        except Exception:
            pass

    IP_file = threat_view_files[2]["IP_feed"]  # ip
    webpage_IOC = read_threat_view_file(IP_file)
    for line in webpage_IOC:
        try:
            ip_recorded = line.decode('utf-8')
            threat_view_ips[ip_recorded.split("\n")[0]] = "IP_file"
        except Exception:
            pass


# <- API lookups ->

def check_domain_record_with_apis(record_repo):
    global suspicious_queue
    for domain in record_repo:
        virus_total_check = check_with_virustotal(domain)
        if virus_total_check:
            audit_log(
                f"-- WARNING! {domain} reported suspicious by virustotal with confidence score {virus_total_check}. --")
            suspicious_queue.put(domain)
            existing_domain_status[domain]["reliable"] = False
            existing_domain_status[domain]['status'] = "Virus_total reported malicious"


        else:
            domain_ip = existing_domain_status[domain]["ip"]
            abuseipdb_result = check_with_abuseipdb(domain, domain_ip)
            if abuseipdb_result is not None:
                abuse_check = (float(abuseipdb_result) >= 50.0)
                if abuse_check:
                    audit_log(f"-- WARNING! {domain} reported suspicious by IPDB with score {abuseipdb_result}. --")

                    suspicious_queue.put(domain)
                    existing_domain_status[domain]["reliable"] = False
                    existing_domain_status[domain][
                        'status'] = f"AbuseIPDB reported malicious with score {abuseipdb_result}"

            else:
                server = "https://otx.alienvault.com/"
                alienvault_check = check_with_alienVault(domain, server)
                if alienvault_check > 0.5:
                    audit_log(
                        f"<- WARNING! -> {domain} reported suspicious by AlienVault with confident score {alienvault_check}.")

                    suspicious_queue.put(domain)
                    existing_domain_status[domain]['reliable'] = False
                    existing_domain_status[domain][
                        'status'] = f"Alien vault reported malicious with score {alienvault_check}"

                else:
                    existing_domain_status[domain]['status'] += ' , and passed all three api lookups.'
                    audit_log(f"All three API checks passed {domain} )")


def check_with_alienVault(domain_name, otx_server):
    global alienVault_key
    API_KEY = alienVault_key
    OTX_SERVER = otx_server
    otx = OTXv2(API_KEY, server=OTX_SERVER)

    otx_look_up_result = otx.get_indicator_details_full(IndicatorTypes.HOSTNAME, domain_name)
    look_up_source = otx_look_up_result['malware']

    av_result = get_alien_vault_malicious_detection(look_up_source)
    return av_result


def get_alien_vault_malicious_detection(source):
    malware_count = source['count']
    malware_size = source['size']
    if malware_count > 0:
        return 0.6
    if malware_size > 0:
        return malware_count / malware_count


def check_with_virustotal(url_to_check):
    global vt_key
    try:
        api_key = vt_key
        audit_log(f"checking {url_to_check} with virustotal")
        vt_client = vt.Client(api_key)
        url_id = vt.url_id(url_to_check)  # generate an appropriate identifier
        url_analysis = vt_client.get_object(f"/urls/{url_id}")
        if url_analysis.last_analysis_stats["malicious"] > 5:
            return url_analysis.last_analysis_stats["malicious"]
        if url_analysis.last_analysis_stats["suspicious"] > 5:
            return url_analysis.last_analysis_stats["suspicious"]
        else:
            audit_log(f"Virustotal passed {url_to_check} ")
            return False
    except vt.APIError:
        return False


def check_with_abuseipdb(domain_name, ip_to_check):
    global abuIPDB_key
    global abuseIPDB_record

    audit_log(f"Checking {domain_name} with AbuseIPDB")
    API_URL = "https://api.abuseipdb.com/api/v2/report"
    api_key = abuIPDB_key

    try:
        params = {
            'ip': ip_to_check,
            'categories': '18,20',
            'comment': 'SSH login attempts with user root.'
        }

        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }

        response = requests.request(method='POST', url=API_URL, headers=headers, params=params)

        # Formatted output
        result = json.loads(response.text)
        audit_log(f"AbuseIPDB result -> {result}")

        # check if lookup returns with useful result or errors
        data_in_result = "data" in result
        error_in_result = "errors" in result

        if data_in_result:
            confidence_score = result['data']['abuseConfidenceScore']
            abuseIPDB_record[ip_to_check] = {"domain": [domain_name], "score": confidence_score}
            audit_log(f"AbuseIPDB confidence score for {domain_name} is {confidence_score}")
            return confidence_score

        if error_in_result:
            if result["errors"][0]["detail"].find("same IP address"):
                print(f"<- LINE 332 -> {result['errors'][0]['detail']}")
                if ip_to_check in abuseIPDB_record:
                    abuseIPDB_record[ip_to_check]['domain'].append(domain_name)
                    audit_log(
                        f"Same ip lookup already executed, score for {domain_name} is {abuseIPDB_record[ip_to_check]['score']}. "
                        f"Domains -> {abuseIPDB_record[ip_to_check]}")
                    return abuseIPDB_record[ip_to_check]['score']
                else:
                    return 0
            else:
                return 0
        # avoid returning None to compare with an integer later.
        return 0

    except Exception as e:
        if ip_to_check in abuseIPDB_record:
            abuseIPDB_record[ip_to_check]['domain'].append(domain_name)
            audit_log(
                f"Same ip lookup already executed, score for {domain_name} is {abuseIPDB_record[ip_to_check]['score']}. "
                f"Domains -> {abuseIPDB_record[ip_to_check]}")
            return abuseIPDB_record[ip_to_check]['score']
        else:
            return 0


# <- Audit functionality ->

def audit_log(message):
    current_date_time = get_tz_current_datetime()
    current_date = get_tz_current_date()
    new_file_name = current_date.strftime("%m-%d") + "_activity.log"
    try:
        cur_date_str = current_date_time.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        time_message = "{} - {}".format(cur_date_str, message)
        print(message)  # print the message as well as logging to the file, that way console gets it too
        logging.basicConfig(format='%(message)s', filename=new_file_name, filemode='w', level=logging.INFO)
        logging.info(time_message)

    except Exception as e:
        done = True
    return new_file_name


def get_tz_current_date():
    return get_tz_current_datetime().date()


def get_tz_current_datetime():
    time_zone = CUR_TIME_ZONE
    utc = pytz.utc
    utc_now = utc.localize(datetime.utcnow())
    tz = pytz.timezone(pytz.country_timezones[time_zone][0])
    return utc_now.astimezone(tz)


# <- CAPTURE ->

def browser_make_captures(domains):
    browser = generate_headless_browser()
    while domains.qsize():
        domain = domains.get()

        domain_to_pass = "http://" + domain
        try:
            browser.get(domain_to_pass)

            screenshot_name = domain

            cur_workdir = os.getcwd()
            if not os.path.exists(f"{cur_workdir}/Screenshots"):
                os.makedirs(f"{cur_workdir}/Screenshots")

            capture_dir = f"{cur_workdir}/Screenshots"
            browser.save_screenshot(f"{capture_dir}/{screenshot_name}.png")
            save_html_text(domain, capture_dir)

            audit_log(f"Captured screen of {domain}")

        except Exception:
            pass
    browser.quit()

    screenshot_file = process_screenshots()
    return screenshot_file


# save the webpage html to txt file
def save_html_text(domain_name, path):
    req = Request(
        url="http://" + domain_name,
        headers={'User-Agent': "Mozilla/5.0"}
    )
    response = urlopen(req, timeout=10)
    try:
        html_content = response.read().decode("utf-8")
        print(html_content)
        print(type(html_content))
        file_name = domain_name + ".txt"
        file_path = path + "/" + file_name
        file = open(f"{file_path}", 'w')
        file.write(html_content)
        file.close()
    except ConnectionError:
        print(f"Was not able to obtain html source code of {domain_name}")


def process_screenshots():
    cur_date_str = get_tz_current_date().strftime("%m%d")
    new_file_name_screenshots = cur_date_str + "_screenshots"
    shutil.make_archive(new_file_name_screenshots, 'zip', "Screenshots")
    shutil.rmtree(os.path.basename("Screenshots"))
    new_file_name = new_file_name_screenshots + ".zip"
    return new_file_name


# selenium firefox options setting
def generate_headless_browser():
    options = Options()
    options.add_argument("--headless=new")

    my_timeouts = Timeouts()
    my_timeouts.page_load = 40
    browser = webdriver.Firefox(options=options)
    browser.timeouts = my_timeouts
    return browser


# <- FUZZERS ->

# to parse the domain into subdomain, domain, and tld
def domain_tld(domain):
    try:
        from tld import parse_tld
    except ImportError:
        ctld = ['org', 'com', 'net', 'gov', 'edu', 'co', 'mil', 'nom', 'ac', 'info', 'biz']
        d = domain.rsplit('.', 3)
        if len(d) < 2:
            return '', d[0], ''
        if len(d) == 2:
            return '', d[0], d[1]
        if len(d) > 2:
            if d[-2] in ctld:
                return '.'.join(d[:-3]), d[-3], '.'.join(d[-2:])
            else:
                return '.'.join(d[:-2]), d[-2], d[-1]
    else:
        d = parse_tld(domain, fix_protocol=True)[::-1]
        if d[1:] == d[:-1] and None in d:
            d = tuple(domain.rsplit('.', 2))
            d = ('',) * (3 - len(d)) + d
        return d


# Generate possible permutations of similar sounding domains
class Fuzzer():
    global white_list, trusted_domains

    def __init__(self, domain, dictionary=common_words, tld_dictionary=abused_tlds):
        self.subdomain, self.domain, self.tld = domain_tld(domain)
        self.dictionary = list(dictionary)
        self.tld_dictionary = list(tld_dictionary)
        self.domains = set()
        self.qwerty = {
            '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7',
            '9': '0oi8', '0': 'po9',
            'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7',
            'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
            'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu',
            'k': 'olmji', 'l': 'kop',
            'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
        self.qwertz = {
            '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7',
            '9': '0oi8', '0': 'po9',
            'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7',
            'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
            'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu',
            'k': 'olmji', 'l': 'kop',
            'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
        self.azerty = {
            '1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7',
            '9': '0oi8', '0': 'po9',
            'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7',
            'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
            'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu',
            'k': 'olji', 'l': 'kopm', 'm': 'lp',
            'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
        }
        self.keyboards = [self.qwerty, self.qwertz, self.azerty]
        self.glyphs = {
            '0': ['o'],
            '1': ['l', 'i'],
            '2': ['ƻ'],
            '3': ['8'],
            '5': ['ƽ'],
            '6': ['9'],
            '8': ['3'],
            '9': ['6'],
            'a': ['à', 'á', 'à', 'â', 'ã', 'ä', 'å', 'ɑ', 'ạ', 'ǎ', 'ă', 'ȧ', 'ą', 'ə'],
            'b': ['d', 'lb', 'ʙ', 'ɓ', 'ḃ', 'ḅ', 'ḇ', 'ƅ'],
            'c': ['e', 'ƈ', 'ċ', 'ć', 'ç', 'č', 'ĉ', 'ᴄ'],
            'd': ['b', 'cl', 'dl', 'ɗ', 'đ', 'ď', 'ɖ', 'ḑ', 'ḋ', 'ḍ', 'ḏ', 'ḓ'],
            'e': ['c', 'é', 'è', 'ê', 'ë', 'ē', 'ĕ', 'ě', 'ė', 'ẹ', 'ę', 'ȩ', 'ɇ', 'ḛ'],
            'f': ['ƒ', 'ḟ'],
            'g': ['q', 'ɢ', 'ɡ', 'ġ', 'ğ', 'ǵ', 'ģ', 'ĝ', 'ǧ', 'ǥ'],
            'h': ['lh', 'ĥ', 'ȟ', 'ħ', 'ɦ', 'ḧ', 'ḩ', 'ⱨ', 'ḣ', 'ḥ', 'ḫ', 'ẖ'],
            'i': ['1', 'l', 'í', 'ì', 'ï', 'ı', 'ɩ', 'ǐ', 'ĭ', 'ỉ', 'ị', 'ɨ', 'ȋ', 'ī', 'ɪ'],
            'j': ['ʝ', 'ǰ', 'ɉ', 'ĵ'],
            'k': ['lk', 'ik', 'lc', 'ḳ', 'ḵ', 'ⱪ', 'ķ', 'ᴋ'],
            'l': ['1', 'i', 'ɫ', 'ł'],
            'm': ['n', 'nn', 'rn', 'rr', 'ṁ', 'ṃ', 'ᴍ', 'ɱ', 'ḿ'],
            'n': ['m', 'r', 'ń', 'ṅ', 'ṇ', 'ṉ', 'ñ', 'ņ', 'ǹ', 'ň', 'ꞑ'],
            'o': ['0', 'ȯ', 'ọ', 'ỏ', 'ơ', 'ó', 'ö', 'ᴏ'],
            'p': ['ƿ', 'ƥ', 'ṕ', 'ṗ'],
            'q': ['g', 'ʠ'],
            'r': ['ʀ', 'ɼ', 'ɽ', 'ŕ', 'ŗ', 'ř', 'ɍ', 'ɾ', 'ȓ', 'ȑ', 'ṙ', 'ṛ', 'ṟ'],
            's': ['ʂ', 'ś', 'ṣ', 'ṡ', 'ș', 'ŝ', 'š', 'ꜱ'],
            't': ['ţ', 'ŧ', 'ṫ', 'ṭ', 'ț', 'ƫ'],
            'u': ['ᴜ', 'ǔ', 'ŭ', 'ü', 'ʉ', 'ù', 'ú', 'û', 'ũ', 'ū', 'ų', 'ư', 'ů', 'ű', 'ȕ', 'ȗ', 'ụ'],
            'v': ['ṿ', 'ⱱ', 'ᶌ', 'ṽ', 'ⱴ', 'ᴠ'],
            'w': ['vv', 'ŵ', 'ẁ', 'ẃ', 'ẅ', 'ⱳ', 'ẇ', 'ẉ', 'ẘ', 'ᴡ'],
            'x': ['ẋ', 'ẍ'],
            'y': ['ʏ', 'ý', 'ÿ', 'ŷ', 'ƴ', 'ȳ', 'ɏ', 'ỿ', 'ẏ', 'ỵ'],
            'z': ['ʐ', 'ż', 'ź', 'ᴢ', 'ƶ', 'ẓ', 'ẕ', 'ⱬ']
        }

    def _bitsquatting(self):
        masks = [1, 2, 4, 8, 16, 32, 64, 128]
        chars = set('abcdefghijklmnopqrstuvwxyz0123456789-')
        for index, char in enumerate(self.domain):
            for mask in masks:
                b = chr(ord(char) ^ mask)
                if b in chars:
                    yield self.domain[:index] + b + self.domain[index + 1:]

    def _homoglyph(self):
        def mix_glyph(domain):
            glyphs = self.glyphs
            for w in range(1, len(domain)):
                for i in range(len(domain) - w + 1):
                    pre = domain[:i]
                    win = domain[i:i + w]
                    suf = domain[i + w:]
                    for c in win:
                        for g in glyphs.get(c, []):
                            yield pre + win.replace(c, g) + suf

        result1 = set(mix_glyph(self.domain))
        result2 = set()
        for r in result1:
            result2.update(set(mix_glyph(r)))
        # Generate glyphs with up to 2 mutations
        return result1 | result2

    # self-explanatory
    def _hyphenation(self):
        return {self.domain[:i] + '-' + self.domain[i:] for i in range(1, len(self.domain))}

    def _insertion(self):
        result = set()
        for index in range(1, len(self.domain) - 1):
            prefix, orig_char, suffix = self.domain[:index], self.domain[index], self.domain[index + 1:]
            for keys in self.keyboards:
                for char in keys.get(orig_char, []):
                    result.update({
                        prefix + char + orig_char + suffix,
                        prefix + orig_char + char + suffix
                    })
        return result

    def _omission(self):
        omission_results = set()
        for index in range(len(self.domain)):
            omission_results.add(self.domain[:index] + self.domain[index + 1:])
        return omission_results

    def _repetition(self):
        result = set()
        for index, char in enumerate(self.domain):
            result.add(self.domain[:index] + char + self.domain[index:])
        return result

    def _replacement(self):
        for index, char in enumerate(self.domain):
            pre = self.domain[:index]
            suf = self.domain[index + 1:]
            for layout in self.keyboards:
                for r in layout.get(char, ''):
                    yield pre + r + suf

    def _subdomain(self):
        for index in range(1, len(self.domain) - 1):
            if self.domain[index] not in ['-', '.'] and self.domain[index - 1] not in ['-', '.']:
                yield self.domain[:index] + '.' + self.domain[index:]

    def _transposition(self):
        transposition_result = set()
        for index in range(len(self.domain) - 1):
            transposition_result.add(
                self.domain[:index] + self.domain[index + 1] + self.domain[index] + self.domain[index + 2:])
        return transposition_result

    def _vowel_swap(self):
        vowels = 'aeiou'
        for i in range(0, len(self.domain)):
            for vowel in vowels:
                if self.domain[i] in vowels:
                    yield self.domain[:i] + vowel + self.domain[i + 1:]

    def _addition(self):
        addition_result = set()
        for index in (*range(48, 58), *range(97, 123)):
            addition_result.add(self.domain + chr(index))
        return addition_result

    #  generates permutations with given domain name & commonly used in targets ie. myeroad -> myeroadportal
    def _dictionary(self):
        result = set()
        for word in self.dictionary:
            if not (self.domain.startswith(word) and self.domain.endswith(word)):
                result.update({
                    self.domain + '-' + word,
                    self.domain + word,
                    word + '-' + self.domain,
                    word + self.domain
                })
        if '-' in self.domain:
            parts = self.domain.split('-')
            for word in self.dictionary:
                result.update({
                    '-'.join(parts[:-1]) + '-' + word,
                    word + '-' + '-'.join(parts[1:])
                })
        return result

    def _tld(self):
        if self.tld in self.tld_dictionary:
            self.tld_dictionary.remove(self.tld)
        return set(self.tld_dictionary)

    # Generate all possible permutations from the above
    def generate(self):
        # self.domains.add(".".join(filter(None, [self.subdomain, self.domain, self.tld])))

        for func_name in ['addition', 'bitsquatting', 'hyphenation',
                          'insertion', 'omission', 'repetition', 'replacement',
                          'subdomain', 'transposition', 'vowel_swap', 'dictionary', 'homoglyph', ]:

            f = getattr(self, "_" + func_name)
            for domain in f():
                possible_domain = ".".join(filter(None, [self.subdomain, domain, self.tld]))
                if possible_domain not in white_list['domains'] and possible_domain not in black_list['domains']:
                    self.domains.add(possible_domain)
                else:
                    if possible_domain in white_list['domains']:
                        audit_log(f"{possible_domain} in white list already")
                    if possible_domain in black_list['domains']:
                        audit_log(f"{possible_domain} in black list already")
                    pass

            for tld in self._tld():
                possible_domain = ".".join(filter(None, [self.subdomain, self.domain, tld]))
                if possible_domain not in white_list['domains'] and possible_domain not in black_list['domains']:
                    self.domains.add(possible_domain)
                else:
                    if possible_domain in white_list['domains']:
                        audit_log(f"{possible_domain} in white list already")
                    if possible_domain in black_list['domains']:
                        audit_log(f"{possible_domain} in black list already")
                    pass
            '''
                also consider if "." in self.tld, depends on the given domain names.
                reserve this for further use if required.
            '''
        audit_log(f"generated the permutations from domain {self.domain}")


def generate_domain_obj(domain, ip, reliable_fact, status_msg, server_name, date_discovered):
    # Generate a domain record obj
    return {domain: {"ip": ip, "reliable": reliable_fact, "status": status_msg, "server": server_name,
                     "discovered date": date_discovered}}


def check_white_black_threatview_lists(domain_name, domain_ip, server_name):
    global white_list, black_list, existing_domain_status, count, suspicious_queue

    cur_date = get_tz_current_date().strftime("%Y-%m-%d")

    if domain_ip in white_list['ips']:
        msg = f"1) {domain_name} white listed, passed threat view checks."
        non_suspicious_obj_from_scanner = generate_domain_obj(domain_name, domain_ip,
                                                              True, msg, server_name, cur_date)
        existing_domain_status[domain_name] = non_suspicious_obj_from_scanner[
            domain_name]

        counter_lock.acquire()
        count += 1
        counter_lock.release()

        audit_log(f"In whitelist already, pass to next checks.")
        print(existing_domain_status)
    elif domain_ip in black_list['ips']:
        print(f"{domain_name} in black list with ip {domain_ip}")
        msg = f"Ip {domain_ip} is recorded in black list already"
        suspicious_obj = generate_domain_obj(domain_name, domain_ip,
                                             False, msg, server_name, cur_date)

        suspicious_queue.put(domain_name)
        existing_domain_status[domain_name] = suspicious_obj[domain_name]
        print(existing_domain_status)
        audit_log(f"{msg}")
    else:

        print(f"{domain_name} not in black list or white list")
        # check with threat view
        if domain_ip not in threat_view_ips:
            print(f"{domain_name} ip not in threat_view ips")
            msg = "1) Passed from threat_view_ips"
            non_suspicious_obj_from_scanner = generate_domain_obj(domain_name, domain_ip,
                                                                  True, msg, server_name, cur_date)
            existing_domain_status[domain_name] = non_suspicious_obj_from_scanner[
                domain_name]

            counter_lock.acquire()
            count += 1
            counter_lock.release()

            audit_log(f"{domain_name} passed threat_view ip checks")
        else:
            print(f"{domain_name} in threatview ips")

            msg = f"Detected in threat_view_ips from {threat_view_ips[domain_ip]}!"
            suspicious_obj = generate_domain_obj(domain_name, domain_ip,
                                                 False, msg, server_name, cur_date)
            suspicious_queue.put(domain_name)
            existing_domain_status[domain_name] = suspicious_obj[domain_name]
            print(suspicious_obj)
            audit_log(
                f" <-- WARNING! --> {domain_name} is detected in threat_view db with ip {domain_ip}. "
                f"Will make capture later.")


# Scans domains to check the existence
class Scanner(threading.Thread):
    global vt_key
    global existing_domain_status
    global white_list, black_list

    def __init__(self, q, name):
        threading.Thread.__init__(self)
        self._stop_event = threading.Event()
        self.tName = name
        self.queue = q

    def run(self):
        while self.queue.qsize():
            try:
                scanner_queueLock.acquire()
                if not work_queue.empty():
                    domain_to_check = self.queue.get()
                    scanner_queueLock.release()
                    try:
                        global count
                        lookup_result = whois.whois(domain_to_check)
                        whois_server = lookup_result['whois_server']
                        # if the domain exists
                        if whois_server:
                            audit_log(f"{domain_to_check} registered with {lookup_result['whois_server']}")
                            ip_of_domain = socket.gethostbyname(domain_to_check)

                            check_white_black_threatview_lists(domain_to_check, ip_of_domain, whois_server)

                    except PywhoisError:
                        pass

                else:
                    scanner_queueLock.release()
                    self.stop()
                    return

            except Exception:
                self.stop()
                return

    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()


def run_multi_scanners(url, thread_numer=NUM_OF_THREAD):
    global work_queue
    global exitFlag
    global trusted_domains

    audit_log(f"Scanning {url}")

    fuzzer = Fuzzer(url)
    fuzzer.generate()

    # To read the permutations
    domains = fuzzer.domains

    start_time_obj = datetime.now()

    for d in domains:
        if d in trusted_domains:
            pass
        else:
            work_queue.put(d)

    # check the existence of the permutations
    for i in range(NUM_OF_THREAD):
        scanner = Scanner(work_queue, "Scanner-" + str(i))
        scanner.start()
        scanner_threads.append(scanner)

    for thread in scanner_threads:
        thread.stop()

    exitFlag = 1
    try:
        for thread in scanner_threads:
            thread.join()

        end_time_obj = datetime.now()
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        audit_log(
            f"{url} lookup finish {end_time}. Total time = {end_time_obj - start_time_obj}, total permutations: {count}")

    except KeyboardInterrupt:
        audit_log("Program terminates due to keyboard interruption")
        current_sys_pid = os.getpid()
        cur_sys = psutil.Process(current_sys_pid)
        cur_sys.terminate()


# <- Scrappers ->

def scrape_web_content(domain_name):
    global keywords
    global unable_to_open_record
    global whois_servers
    global existing_domain_status
    sale_key_words = ['for sale', 'buy for']
    tags = ["title", "p", "a", "h1", "h2", "h3", "h4", "h5", "h6"]
    audit_log(f"Scraping {domain_name} content now")

    req = Request(
        url="http://" + domain_name,
        headers={'User-Agent': "Mozilla/5.0"}
    )
    response = urlopen(req, timeout=10)
    try:
        html = response.read()
        soup = BeautifulSoup(html, 'html.parser')

        for_sale_check = check_for_sale(soup.findAll('p'), sale_key_words)
        # whois_server_check = existing_domain_status[domain_name]['server'] in whois_servers

        for keyword in keywords:
            try:
                for tag in tags:
                    tag_group = soup.findAll(tag)
                    tag_check_result = check_by_tag(tag_group, keyword)
                    if tag_check_result:
                        # if tag contains keywords to look up
                        if for_sale_check:
                            # if the website is for sale and whois server is a commonly seen server,
                            # then the website can be passed
                            audit_log(f"{domain_name} {tag} tag contains key word {keyword}")
                            return False
                        else:
                            audit_log(f"{domain_name} {tag} tag contains key word but not for sale")
                            return f"{domain_name} {tag} tag contains key word but not for sale"
                else:
                    return False

            except Exception as e:
                audit_log(f"<- LINE 919 -> Scrape web content error: {e} with {domain_name}")
                pass
            return False
    except ConnectionError:
        unable_to_open_record[domain_name] = f"Unable to open with error {ConnectionError}"
        audit_log(f"Unable to open {domain_name} due to {ConnectionError}")


def check_by_tag(soup_result, keyword):
    for tag in soup_result:
        tag_seek_result = tag.text.lower().find(keyword)
        if type(tag_seek_result) == int and tag_seek_result > -1:
            return tag
    return False


def check_for_sale(tag_elements, sale_key_word):
    for word in sale_key_word:
        for tag in tag_elements:
            sale_key_word_search = tag.text.lower().find(word)
            if type(sale_key_word_search) == int and sale_key_word_search > -1:
                return tag
    return False


class Scrapper(threading.Thread):
    def __init__(self, job_q, name):
        threading.Thread.__init__(self)
        self._stop_event = threading.Event()
        self.tName = name
        self.queue = job_q
        audit_log(f"Scraper {name} initiated")

    def run(self):
        global trusted_domains
        while webcontent_queue.qsize():
            try:
                scarper_queueLock.acquire()
                domain_name = webcontent_queue.get()

                scarper_queueLock.release()

                scrap_result = scrape_web_content(domain_name)
                if scrap_result:

                    audit_log(f"<- WARNING! -> {domain_name} put to suspicious Q because {scrap_result}. : (")
                    suspicious_queue.put(domain_name)
                    existing_domain_status[domain_name]['reliable'] = False
                    existing_domain_status[domain_name]['status'] = f"{scrap_result}"

                else:
                    existing_domain_status[domain_name]['status'] += f" , and passed content scrapping."
                    audit_log(f"Safe to release {domain_name}")

            except HTTPError as error:
                pass
            except Exception as e:
                self.stop()
                return

    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()


def run_multi_scrapper():
    global webcontent_queue
    for i in range(NUM_OF_THREAD):
        scraper = Scrapper(webcontent_queue, "Scraper-" + str(i))
        scraper.start()
        scraper_threads.append(scraper)

    audit_log(f"Number of scrapers in array: {len(scraper_threads)}")

    for thread in scraper_threads:
        thread.stop()

    for thread in scraper_threads:
        thread.join()


if __name__ == '__main__':
    main()
