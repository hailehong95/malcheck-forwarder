#!/usr/bin/env python

import os
from malcheck_forwarder.utils import load_json_report
from malcheck_forwarder.config import SPLUNK_ENDPOINT, SPLUNK_PORT, SPLUNK_TOKEN
from malcheck_forwarder.config import REPORT_GENERAL, SPLUNK_HOSTNAME, SPLUNK_INDEX, GENERAL_SYSINFO_REPORT
from malcheck_forwarder.config import GENERAL_PS_REPORT, GENERAL_FILE_REPORT, GENERAL_PROCESS_REPORT
from malcheck_forwarder.config import GENERAL_AUTORUN_REPORT, GENERAL_NETWORK_REPORT, GENERAL_ADDON_REPORT
from malcheck_forwarder import SplunkSender

splunk_conf = {
    "endpoint": SPLUNK_ENDPOINT,
    "port": SPLUNK_PORT,
    "token": SPLUNK_TOKEN,
    "index": SPLUNK_INDEX,
    "channel": "16c70678-e516-44a9-854d-d139929e6869",  # GUID
    "api_version": "1.0",
    "source_type": "_json",
    "allow_overrides": True,  # Whether to look for one of the Splunk built-in parameters(index, host, ecc)
    "verify": False,  # turn SSL verification on or off, defaults to True
    "enable_debug": False,  # turn on debug mode; prints module activity to stdout, defaults to False
    "hostname": SPLUNK_HOSTNAME,  # manually set a hostname parameter, defaults to socket.gethostname()
    # 'source': 'source',  # manually set a source, defaults to the log record.pathname
    # 'timeout': 60,  # timeout for waiting on a 200 OK from Splunk server, defaults to 60s
    # 'retry_count': 5,  # Number of retry attempts on a failed/erroring connection, defaults to 5
    # 'retry_backoff': 2.0,  # Backoff factor, default options will retry for 1 min, defaults to 2.0

}


def forward_sysinfo_logs():
    try:
        print("Info: Sending sysinfo logs")
        splunk_conf["source"] = "sysinfo"
        splunk_fwd = SplunkSender(**splunk_conf)
        json_path = os.path.join(REPORT_GENERAL, GENERAL_SYSINFO_REPORT + "-general.json")
        payloads = load_json_report(json_path)
        splunk_res = splunk_fwd.send_data(payloads)
    except Exception as ex:
        print(f"forward_sysinfo_logs - {ex}")


def forward_addon_logs():
    try:
        print("Info: Sending addon logs")
        splunk_conf["source"] = "addon"
        splunk_fwd = SplunkSender(**splunk_conf)
        json_path = os.path.join(REPORT_GENERAL, GENERAL_ADDON_REPORT + "-general.json")
        payloads = load_json_report(json_path)
        splunk_res = splunk_fwd.send_data(payloads)
    except Exception as ex:
        print(f"forward_sysinfo_logs - {ex}")


def forward_network_logs():
    try:
        print("Info: Sending network logs")
        splunk_conf["source"] = "network"
        splunk_fwd = SplunkSender(**splunk_conf)
        json_path = os.path.join(REPORT_GENERAL, GENERAL_NETWORK_REPORT + "-general.json")
        payloads = load_json_report(json_path)
        splunk_res = splunk_fwd.send_data(payloads)
    except Exception as ex:
        print(f"forward_sysinfo_logs - {ex}")


def forward_autorun_logs():
    try:
        print("Info: Sending autorun logs")
        splunk_conf["source"] = "autorun"
        splunk_fwd = SplunkSender(**splunk_conf)
        json_path = os.path.join(REPORT_GENERAL, GENERAL_AUTORUN_REPORT + "-general.json")
        payloads = load_json_report(json_path)
        splunk_res = splunk_fwd.send_data(payloads)
    except Exception as ex:
        print(f"forward_sysinfo_logs - {ex}")


def forward_process_logs():
    try:
        print("Info: Sending process logs")
        splunk_conf["source"] = "process"
        splunk_fwd = SplunkSender(**splunk_conf)
        json_path = os.path.join(REPORT_GENERAL, GENERAL_PROCESS_REPORT + "-general.json")
        payloads = load_json_report(json_path)
        splunk_res = splunk_fwd.send_data(payloads)
    except Exception as ex:
        print(f"forward_sysinfo_logs - {ex}")


def forward_powershell_logs():
    try:
        print("Info: Sending powershell logs")
        splunk_conf["source"] = "powershell"
        splunk_fwd = SplunkSender(**splunk_conf)
        json_path = os.path.join(REPORT_GENERAL, GENERAL_PS_REPORT + "-general.json")
        payloads = load_json_report(json_path)
        splunk_res = splunk_fwd.send_data(payloads)
    except Exception as ex:
        print(f"forward_sysinfo_logs - {ex}")


def forward_files_logs():
    try:
        print("Info: Sending files logs")
        splunk_conf["source"] = "files"
        splunk_fwd = SplunkSender(**splunk_conf)
        json_path = os.path.join(REPORT_GENERAL, GENERAL_FILE_REPORT + "-general.json")
        payloads = load_json_report(json_path)
        splunk_res = splunk_fwd.send_data(payloads)
    except Exception as ex:
        print(f"forward_sysinfo_logs - {ex}")


def main():
    forward_sysinfo_logs()
    forward_addon_logs()
    forward_network_logs()
    forward_autorun_logs()
    forward_process_logs()
    forward_powershell_logs()
    forward_files_logs()


if __name__ == "__main__":
    main()
