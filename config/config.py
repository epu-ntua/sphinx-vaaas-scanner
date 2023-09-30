import os
import json

config = None

# def read_config():
#     global config
#     script_path = os.path.abspath(__file__)
#     script_dir = os.path.split(script_path)[0]
#
#     with open(str(os.path.join(script_dir, 'default.json'))) as default_data:
#         config = json.load(default_data)
#
#     with open(str(os.path.join(script_dir, 'config.json'))) as config_data:
#         config.update(json.load(config_data))


# def get_config():
#     global config
#     if not config:
#         read_config()
#     return config


import argparse

settings = {
    "DEV": {
        "redis_url": "10.0.1.220",
        "redis_port": 6379,
        "logger_url": "10.0.1.220",
        "logger_port": 12201,
        "logger_protocol": "http",
        "cve_db_protocol": "http",
        "cve_db_url": "127.0.0.10",
        "cve_db_port": 8001
    },
    "PROD": {
        "redis_url": "127.0.0.1",
        "redis_port": 6379,
        "logger_url": "127.0.0.1",
        "logger_port": 12201,
        "logger_protocol": "http",
        "cve_db_protocol": "http",
        "cve_db_url": "127.0.0.10",
        "cve_db_port": 8001
    }
}


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--mode', dest='mode', help='Set the running mode (dev/prod/test)')
    options = parser.parse_args()

    # Check for errors i.e if the user does not specify the target IP Address
    # Quit the program if the argument is missing
    # While quitting also display an error message
    # if not options.mode:
    # Code to handle if interface is not specified
    # parser.error("[-] Please specify the running mode (dev/prod), use --help for more info.")
    # logging.error("[-] Please specify the running mode (dev/prod), use --help for more info.")
    # else:
    #     pass
    return options


def get_mode():
    options = get_args()
    if options and options.mode:
        if options.mode.upper() == 'DEV':
            MODE = 'DEV'
        elif options.mode.upper() == 'PROD':
            MODE = 'PROD'
        elif options.mode.upper() == 'TEST':
            MODE = 'TEST'
        else:
            MODE = 'DEV'
    else:
        MODE = 'DEV'
    return MODE


def get_config():
    return settings[get_mode()]
