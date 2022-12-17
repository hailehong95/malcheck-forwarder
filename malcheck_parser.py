#!/usr/bin/env python

from malcheck_parser.utils import convert_json_to_csv, unzip_multi_file
from malcheck_parser.utils import initial_dirs, get_list_dir, save_general_report, save_splunk_report
from malcheck_parser.config import EXTRACT_DIR, GENERAL_ADDON_REPORT, GENERAL_LAST_ACTIVITY_REPORT
from malcheck_parser.config import GENERAL_PROCESS_REPORT, GENERAL_AUTORUN_REPORT, GENERAL_FILE_REPORT
from malcheck_parser.config import GENERAL_PS_REPORT, GENERAL_NETWORK_REPORT, GENERAL_SYSINFO_REPORT, UPLOAD_DIR
from malcheck_parser.merge import sysinfo_task, autorun_task, file_task, process_task, network_task
from malcheck_parser.merge import addons_task, last_activity_task, powershell_task, save_hashes_task


def main():
    initial_dirs()
    unzip_multi_file(get_list_dir(UPLOAD_DIR))
    dirs = get_list_dir(EXTRACT_DIR)

    total_sysinfo_data = sysinfo_task(dirs)
    save_general_report(total_sysinfo_data, GENERAL_SYSINFO_REPORT + "-general.json")
    save_splunk_report(total_sysinfo_data, GENERAL_SYSINFO_REPORT + "-splunk.json")

    total_autorun_data = autorun_task(dirs)
    save_general_report(total_autorun_data, GENERAL_AUTORUN_REPORT + "-general.json")
    save_splunk_report(total_autorun_data, GENERAL_AUTORUN_REPORT + "-splunk.json")

    total_file_data = file_task(dirs)
    save_general_report(total_file_data, GENERAL_FILE_REPORT + "-general.json")
    save_splunk_report(total_file_data, GENERAL_FILE_REPORT + "-splunk.json")

    total_process_data = process_task(dirs)
    save_general_report(total_process_data, GENERAL_PROCESS_REPORT + "-general.json")
    save_splunk_report(total_process_data, GENERAL_PROCESS_REPORT + "-splunk.json")

    total_network_data = network_task(dirs)
    save_general_report(total_network_data, GENERAL_NETWORK_REPORT + "-general.json")
    save_splunk_report(total_network_data, GENERAL_NETWORK_REPORT + "-splunk.json")

    total_ps_log_data = powershell_task(dirs)
    save_general_report(total_ps_log_data, GENERAL_PS_REPORT + "-general.json")
    save_splunk_report(total_ps_log_data, GENERAL_PS_REPORT + "-splunk.json")

    total_last_activity_data = last_activity_task(dirs)
    save_general_report(total_last_activity_data, GENERAL_LAST_ACTIVITY_REPORT + "-general.json")
    save_splunk_report(total_last_activity_data, GENERAL_LAST_ACTIVITY_REPORT + "-splunk.json")

    total_addons_data = addons_task(dirs)
    save_general_report(total_addons_data, GENERAL_ADDON_REPORT + "-general.json")
    save_splunk_report(total_addons_data, GENERAL_ADDON_REPORT + "-splunk.json")

    convert_json_to_csv()
    save_hashes_task()


if __name__ == "__main__":
    main()
