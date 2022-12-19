import os
from dotenv import load_dotenv

load_dotenv()
base = os.path.dirname(os.path.abspath(__file__))

BASE_DIR = os.getenv("BASE_DIR")
if BASE_DIR is None:
    BASE_DIR = base
elif BASE_DIR == "." or BASE_DIR == "":
    BASE_DIR = base

REPORT_DIR = os.path.join(BASE_DIR, "report")
REPORT_GENERAL = os.path.join(REPORT_DIR, "general")

SPLUNK_PORT = os.getenv("SPLUNK_PORT")
SPLUNK_ENDPOINT = os.getenv("SPLUNK_ENDPOINT")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX")
SPLUNK_HOSTNAME = os.getenv("SPLUNK_HOSTNAME")

GENERAL_PS_REPORT = "total-ps"
GENERAL_FILE_REPORT = "total-file"
GENERAL_ADDON_REPORT = "total-addon"
GENERAL_PROCESS_REPORT = "total-process"
GENERAL_AUTORUN_REPORT = "total-autorun"
GENERAL_NETWORK_REPORT = "total-network"
GENERAL_SYSINFO_REPORT = "total-sysinfo"
GENERAL_LAST_ACTIVITY_REPORT = "total-last-activity"
