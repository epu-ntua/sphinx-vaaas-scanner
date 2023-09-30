import json

import requests
from config.config import get_config

conf: dict = get_config()


def get_cves_by_cpe(cpe: str):
    base_url = f"{conf.get('cve_db_protocol')}://{conf.get('cve_db_url')}:{conf.get('cve_db_port')}/cves/cpes"
    result = requests.post(url=base_url, data=json.dumps({'cpe': cpe}))
    while not result:
        pass
    return result.json().get('items')
