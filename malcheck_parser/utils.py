import os
import re
import time
import json
import string
import zipfile
import pandas as pd

from malcheck_parser.config import BASE_DIR, UPLOAD_DIR, EXTRACT_DIR, REPORT_DIR, REPORT_NAME
from malcheck_parser.config import REPORT_SPLUNK, REPORT_HASHES, REPORT_GENERAL, REPORT_CSV


def initial_dirs():
    try:
        dirs = [BASE_DIR, UPLOAD_DIR, EXTRACT_DIR, REPORT_DIR]
        for item in dirs:
            if not os.path.exists(item):
                os.mkdir(item)
        sub_dirs = [REPORT_GENERAL, REPORT_CSV, REPORT_SPLUNK, REPORT_HASHES]
        for item in sub_dirs:
            if not os.path.exists(item):
                os.mkdir(item)
    except Exception as ex:
        print(f"initial_dirs - {ex}")


def unzip_one_file(source_file, dest_folder):
    try:
        with zipfile.ZipFile(source_file, 'r') as zip_ref:
            zip_ref.extractall(dest_folder)
    except Exception as ex:
        print(f"unzip_file - {ex}")


def unzip_multi_file(zip_list):
    try:
        for zip_name in zip_list:
            source_file = os.path.join(UPLOAD_DIR, zip_name)
            dest_folder = os.path.join(EXTRACT_DIR, zip_name.replace(".zip", ""))
            unzip_one_file(source_file, dest_folder)
            time.sleep(0.5)
    except Exception as ex:
        print(f"unzip_multi_file - {ex}")


def load_json_file(file_path):
    try:
        buff = {}
        with open(file_path, encoding="utf-8-sig") as f:
            buff = json.load(f)
    except Exception as ex:
        print(f"load_json_file - {ex}")
    return buff


def get_list_dir(path):
    try:
        zip_files = os.listdir(path)
        return zip_files
    except Exception as ex:
        print(f"get_list_dir - {ex}")


def save_general_report(dict_data, file_name):
    try:
        file_path = os.path.join(REPORT_GENERAL, file_name)
        with open(file_path, "w", encoding="utf-8") as fs:
            json.dump(dict_data, fs)
    except Exception as ex:
        print(f"save_general_report - {ex}")


def save_splunk_report(dict_data, file_name):
    try:
        file_path = os.path.join(REPORT_SPLUNK, file_name)
        with open(file_path, "w", encoding="utf-8") as fs:
            for line in dict_data:
                fs.write(f"{line}\n")
    except Exception as ex:
        print(f"save_splunk_report - {ex}")


def convert_json_to_csv():
    try:
        json_files = os.listdir(REPORT_GENERAL)
        for json_file in json_files:
            try:
                json_path = os.path.join(REPORT_GENERAL, json_file)
                with open(json_path) as fs:
                    df = pd.read_json(fs)
                csv_file = os.path.join(REPORT_CSV, json_file.replace(".json", ".csv"))
                df.to_csv(csv_file, encoding="utf-8", index=False)
            except Exception as ex:
                print(f"convert_json_to_csv - {json_file} - {ex}")
    except Exception as ex:
        print(f"convert_json_to_csv - {ex}")


def standardized_keys(data: dict):
    return {k.replace(' ', '_').replace('-', '').lower(): v for k, v in data.items()}


def mac_address_extract(dir_name):
    macs = ""
    try:
        mac_address = os.path.join(EXTRACT_DIR, dir_name, REPORT_NAME["mac_address"])
        if os.path.exists(mac_address):
            mac_data = load_json_file(mac_address)
            if type(mac_data) is list:
                macs = "; ".join([x["MacAddress"] for x in mac_data])
            else:
                macs = mac_data["MacAddress"]
    except Exception as ex:
        print(f"mac_address_extract - {dir_name} - {ex}")
    finally:
        return macs


def ip_address_extract(dir_name):
    ips = ""
    try:
        sysinfo_file = os.path.join(EXTRACT_DIR, dir_name, REPORT_NAME["sysinfo"])
        if os.path.exists(sysinfo_file):
            sysinfo_data = load_json_file(sysinfo_file)
            ips = "; ".join(re.findall(r'[0-9]+(?:\.[0-9]+){3}', sysinfo_data['Network Card(s)']))
    except Exception as ex:
        print(f"ip_address_extract - {dir_name} - {ex}")
    finally:
        return ips


def hash_validator(value):
    try:
        if value is None:
            return False
        if len(value) not in [32, 40, 64]:
            return False
        for chr_ in list(value):
            if chr_ not in string.hexdigits:
                return False
    except Exception as ex:
        print(f"hash_validator - {ex}")
        return False
    return True
