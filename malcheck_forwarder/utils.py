import os
import json


def load_json_report(file_path):
    buff = list()
    try:
        with open(file=file_path, mode="r", encoding="utf-8") as fs:
            buff = json.load(fs)
    except Exception as ex:
        print(f"load_json_report - {ex}")
    return buff
