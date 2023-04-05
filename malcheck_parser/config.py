import os
from dotenv import load_dotenv

load_dotenv()
base = os.path.dirname(os.path.abspath(__file__))

BASE_DIR = os.getenv("BASE_DIR")
if BASE_DIR is None:
    BASE_DIR = base
elif BASE_DIR == "." or BASE_DIR == "":
    BASE_DIR = base

UPLOAD_DIR = os.path.join(BASE_DIR, "upload")
EXTRACT_DIR = os.path.join(BASE_DIR, "extract")
REPORT_DIR = os.path.join(BASE_DIR, "report")
REPORT_CSV = os.path.join(REPORT_DIR, "csv")
REPORT_HASHES = os.path.join(REPORT_DIR, "hashes")
REPORT_SPLUNK = os.path.join(REPORT_DIR, "splunk")
REPORT_GENERAL = os.path.join(REPORT_DIR, "general")

GENERAL_PS_REPORT = "total-ps"
GENERAL_FILE_REPORT = "total-file"
GENERAL_ADDON_REPORT = "total-addon"
GENERAL_PROCESS_REPORT = "total-process"
GENERAL_AUTORUN_REPORT = "total-autorun"
GENERAL_NETWORK_REPORT = "total-network"
GENERAL_SYSINFO_REPORT = "total-sysinfo"
GENERAL_LAST_ACTIVITY_REPORT = "total-last-activity"

BATCH_SIZE = 100000

REPORT_NAME = {
    'last_activity': 'activity.json',
    'browser_addons': 'addon.json',
    'autorun': 'autorun.json',
    'files': 'files.json',
    'network': 'network.json',
    'powershell_log': 'powershell.json',
    'process': 'process.json',
    'sysinfo': 'sysinfo.json'

}
