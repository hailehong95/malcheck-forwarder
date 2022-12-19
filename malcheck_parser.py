#!/usr/bin/env python

from malcheck_parser.utils import convert_json_to_csv, unzip_multi_file
from malcheck_parser.utils import initial_dirs, get_list_dir, save_general_report
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
    print(f"[*] Total sysinfo data = {str(len(total_sysinfo_data))}")
    save_general_report(total_sysinfo_data, GENERAL_SYSINFO_REPORT)

    total_autorun_data = autorun_task(dirs)
    print(f"[*] Total autorun data = {str(len(total_autorun_data))}")
    save_general_report(total_autorun_data, GENERAL_AUTORUN_REPORT)

    total_file_data = file_task(dirs)
    print(f"[*] Total files data = {str(len(total_file_data))}")
    save_general_report(total_file_data, GENERAL_FILE_REPORT)

    total_process_data = process_task(dirs)
    print(f"[*] Total process data = {str(len(total_process_data))}")
    save_general_report(total_process_data, GENERAL_PROCESS_REPORT)

    total_network_data = network_task(dirs)
    print(f"[*] Total network data = {str(len(total_network_data))}")
    save_general_report(total_network_data, GENERAL_NETWORK_REPORT)

    total_ps_log_data = powershell_task(dirs)
    print(f"[*] Total powershell data = {str(len(total_ps_log_data))}")
    save_general_report(total_ps_log_data, GENERAL_PS_REPORT)

    total_last_activity_data = last_activity_task(dirs)
    print(f"[*] Total last activity data = {str(len(total_last_activity_data))}")
    save_general_report(total_last_activity_data, GENERAL_LAST_ACTIVITY_REPORT)

    total_addons_data = addons_task(dirs)
    print(f"[*] Total addon data = {str(len(total_addons_data))}")
    save_general_report(total_addons_data, GENERAL_ADDON_REPORT)

    convert_json_to_csv()
    save_hashes_task()


if __name__ == "__main__":
    main()
