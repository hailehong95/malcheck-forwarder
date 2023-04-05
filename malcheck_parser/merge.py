import os
import re
from datetime import datetime, timedelta

from malcheck_parser.utils import load_json_file, standardized_keys, hash_validator
from malcheck_parser.utils import mac_address_extract, ip_address_extract
from malcheck_parser.config import EXTRACT_DIR, REPORT_NAME, REPORT_HASHES, REPORT_GENERAL
from malcheck_parser.config import GENERAL_PROCESS_REPORT, GENERAL_AUTORUN_REPORT, GENERAL_FILE_REPORT


def sysinfo_task(dirs):
    total_sysinfo_data = []
    for dir_name in dirs:
        try:
            sysinfo_file = os.path.join(EXTRACT_DIR, dir_name, REPORT_NAME["sysinfo"])
            if os.path.exists(sysinfo_file):
                sysinfo_data = load_json_file(sysinfo_file)
            else:
                continue
            sysinfo_data[0]["employee_id"] = dir_name.split("_")[1]
            sysinfo_data[0]["employee_name"] = dir_name.split("_")[2]
            total_sysinfo_data.append(sysinfo_data[0])
        except Exception as ex:
            print(f"sysinfo_task - {dir_name} - {ex}")
    return total_sysinfo_data


def autorun_task(dirs):
    total_autorun_data = []
    for dir_name in dirs:
        try:
            autorun_file = os.path.join(EXTRACT_DIR, dir_name, REPORT_NAME["autorun"])
            if os.path.exists(autorun_file):
                autorun_data = load_json_file(autorun_file)
            else:
                continue
            for item in autorun_data:
                item["employee_id"] = dir_name.split("_")[1]
                item["employee_name"] = dir_name.split("_")[2]
                total_autorun_data.append(item)
        except Exception as ex:
            print(f"autorun_task - {dir_name} - {ex}")
    return total_autorun_data


def file_task(dirs):
    total_file_data = []
    for dir_name in dirs:
        try:
            files_path = os.path.join(EXTRACT_DIR, dir_name, REPORT_NAME["files"])
            if os.path.exists(files_path):
                files_data = load_json_file(files_path)
            else:
                continue
            for item in files_data:
                item["employee_id"] = dir_name.split("_")[1]
                item["employee_name"] = dir_name.split("_")[2]
                total_file_data.append(item)
        except Exception as ex:
            print(f"file_task - {dir_name} - {ex}")
    return total_file_data


def process_task(dirs):
    total_process_data = []
    for dir_name in dirs:
        try:
            process_file = os.path.join(EXTRACT_DIR, dir_name, REPORT_NAME["process"])
            if os.path.exists(process_file):
                process_data = load_json_file(process_file)
            else:
                continue
            for item in process_data:
                item["employee_id"] = dir_name.split("_")[1]
                item["employee_name"] = dir_name.split("_")[2]
                total_process_data.append(item)
        except Exception as ex:
            print(f"process_task - {dir_name} - {ex}")
    return total_process_data


def network_task(dirs):
    total_network_data = []
    for dir_name in dirs:
        try:
            network_file = os.path.join(EXTRACT_DIR, dir_name, REPORT_NAME["network"])
            if os.path.exists(network_file):
                network_data = load_json_file(network_file)
            else:
                continue
            for item in network_data:
                item["employee_id"] = dir_name.split("_")[1]
                item["employee_name"] = dir_name.split("_")[2]
                total_network_data.append(item)
        except Exception as ex:
            print(f"network_task - {dir_name} - {ex}")
    return total_network_data


def powershell_task(dirs):
    total_ps_log_data = []
    for dir_name in dirs:
        try:
            ps_log_file = os.path.join(EXTRACT_DIR, dir_name, REPORT_NAME["powershell_log"])
            if os.path.exists(ps_log_file):
                ps_log_data = load_json_file(ps_log_file)
            else:
                continue
            for item in ps_log_data:
                item["employee_id"] = dir_name.split("_")[1]
                item["employee_name"] = dir_name.split("_")[2]
                total_ps_log_data.append(item)
        except Exception as ex:
            print(f"powershell_task - {dir_name} - {ex}")
    return total_ps_log_data


def last_activity_task(dirs):
    total_last_activity_data = []
    for dir_name in dirs:
        try:
            last_activity_file = os.path.join(EXTRACT_DIR, dir_name, REPORT_NAME["last_activity"])
            if os.path.exists(last_activity_file):
                last_activity_data = load_json_file(last_activity_file)
            else:
                continue
            for item in last_activity_data:
                item["employee_id"] = dir_name.split("_")[1]
                item["employee_name"] = dir_name.split("_")[2]
                total_last_activity_data.append(item)
        except Exception as ex:
            print(f"last_activity_task - {dir_name} - {ex}")
    return total_last_activity_data


def addons_task(dirs):
    total_addons_data = []
    for dir_name in dirs:
        try:
            addon_file = os.path.join(EXTRACT_DIR, dir_name, REPORT_NAME["browser_addons"])
            if os.path.exists(addon_file):
                addons_data = load_json_file(addon_file)
            else:
                continue
            for item in addons_data:
                item["employee_id"] = dir_name.split("_")[1]
                item["employee_name"] = dir_name.split("_")[2]
                total_addons_data.append(item)
        except Exception as ex:
            print(f"addons_task - {dir_name} - {ex}")
    return total_addons_data


def hashes_extract():
    try:
        md5_hashes = []
        sha1_hashes = []
        sha256_hashes = []
        file_data = list()
        file_data.append(GENERAL_FILE_REPORT + "-general.json")
        file_data.append(GENERAL_AUTORUN_REPORT + "-general.json")
        file_data.append(GENERAL_PROCESS_REPORT + "-general.json")

        for fn in file_data:
            temp = load_json_file(os.path.join(REPORT_GENERAL, fn))
            for hs in temp:
                if hash_validator(hs.get("md5")):
                    md5_hashes.append(hs.get("md5"))
                if hash_validator(hs.get("sha1")):
                    sha1_hashes.append(hs.get("sha1"))
                if hash_validator(hs.get("sha256")):
                    sha256_hashes.append(hs.get("sha256"))
        md5_hashes = list(set(md5_hashes))
        sha1_hashes = list(set(sha1_hashes))
        sha256_hashes = list(set(sha256_hashes))
        return md5_hashes, sha1_hashes, sha256_hashes
    except Exception as ex:
        print(f"hashes_extract - {ex}")


def save_hashes_task():
    try:
        md5_hashes, sha1_hashes, sha256_hashes = hashes_extract()

        md5_file = os.path.join(REPORT_HASHES, "md5.txt")
        with open(md5_file, mode="w", encoding="utf-8") as fs:
            for item in md5_hashes:
                fs.write(f"{item}\n")

        sha1_file = os.path.join(REPORT_HASHES, "sha1.txt")
        with open(sha1_file, mode="w", encoding="utf-8") as fs:
            for item in sha1_hashes:
                fs.write(f"{item}\n")

        sha256_file = os.path.join(REPORT_HASHES, "sha256.txt")
        with open(sha256_file, mode="w", encoding="utf-8") as fs:
            for item in sha256_hashes:
                fs.write(f"{item}\n")
    except Exception as ex:
        print(f"save_hashes_task - {ex}")
