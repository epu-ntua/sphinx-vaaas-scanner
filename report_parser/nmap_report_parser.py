import json
import re

from stix2 import CustomObservable, properties, utils
from stix2 import Bundle, IPv4Address, MACAddress, Relationship
from utils.utils import get_main_logger, json_crawler
from utils.uuid_generator import generate_uuid

log = get_main_logger()


@CustomObservable('x-discovered-service', [
    ('created', properties.TimestampProperty(
        default=lambda: utils.NOW, precision='millisecond',
        precision_constraint='min'
    )),
    ('modified', properties.TimestampProperty(
        default=lambda: utils.NOW, precision='millisecond',
        precision_constraint='min'
    )),
    ('port', properties.StringProperty(required=True)),
    ('protocol', properties.StringProperty()),
    ('state', properties.StringProperty()),
    ('service_name', properties.StringProperty()),
    ('service_product', properties.StringProperty()),
    ('service_product_version', properties.StringProperty()),
    ('service_cpe_list', properties.ListProperty(properties.StringProperty())),
    ('scripts_list', properties.ListProperty(properties.DictionaryProperty())),
    ('service_vulnerabilities', properties.ListProperty(properties.DictionaryProperty())),

])
class DiscoveredService:
    pass


@CustomObservable('x-host-script', [
    ('created', properties.TimestampProperty(
        default=lambda: utils.NOW, precision='millisecond',
        precision_constraint='min'
    )),
    ('modified', properties.TimestampProperty(
        default=lambda: utils.NOW, precision='millisecond',
        precision_constraint='min'
    )),
    ('id', properties.StringProperty()),
    ('output', properties.StringProperty()),
    ('elements', properties.DictionaryProperty()),

])
class HostScript:
    pass


class ReportParser:
    def __init__(self, _json_report: dict):
        # self.discovered_services = []
        # try:
        # print(_json_report)
        assert isinstance(_json_report, dict), 'Report should be of type dict!'
        # self.report_json = list(_json_report.values())[0].get('__NmapReport__')
        self.report_json = _json_report.get('__NmapReport__') if _json_report.get('__NmapReport__') else {}
        self.cvss_scores = list(json_crawler(self.report_json, 'cvss'))
        self.cvss_score = max(self.cvss_scores) if len(self.cvss_scores) > 0 else 4.5
        self.assessment_date = self.report_json.get('_nmaprun').get('startstr') if self.report_json else ''
        self.hosts = self.report_json.get('_hosts')
        self.start = self.hosts[0].get('__NmapHost__').get('_endtime') if self.hosts else ''
        self.stop = self.hosts[0].get('__NmapHost__').get('_starttime') if self.hosts else ''
        self.IPV4s = [IPv4Address(value=h.get('__NmapHost__').get('_ipv4_addr')) for h in self.hosts if
                      (h.get('__NmapHost__') and h.get('__NmapHost__').get('_ipv4_addr'))] if self.hosts else []
        self.MACs = [MACAddress(value=h.get('__NmapHost__').get('_mac_addr')) for h in self.hosts if (h.get('__NmapHost__') and h.get('__NmapHost__').get('_mac_addr'))] if self.hosts else []
        self.relationships = [Relationship(relationship_type='has', source_ref=self.IPV4s[i], target_ref=self.MACs[i]) for i in range(len(self.IPV4s)) if
                              ((len(self.IPV4s) > 0) and (len(self.MACs) > 0))]
        self.discovered_services = [
            DiscoveredService(
                port=self.__get_port(s),
                protocol=self.__get_protocol(s),
                state=self.__get_state(s),
                service_name=self.__get_service_name(s),
                service_product=self.__get_service_product(s),
                service_product_version=self.__get_service_product_version(s),
                service_cpe_list=self.__get_cpe_list(s),
                scripts_list=self.__get_script_list(s),
                service_vulnerabilities=self.get_service_cves(s)
            ) for h in self.hosts for s in h.get('__NmapHost__').get('_services') if len(s) > 0
        ]
        self.host_extras = next(iter(self.hosts), []).get('__NmapHost__').get('_extras') if next(iter(self.hosts), []) else {}
        # print(self.host_extras.get('hostscript')) if self.host_extras else []
        # print(self.host_extras)
        self.host_scripts = [HostScript(id=hs.get('id') if hs.get('id') else 'null',
                                        output=hs.get('output') if hs.get('output') else 'null',
                                        elements=hs.get('elements') if hs.get('elements') else {"value": "null"}) for hs in
                             self.host_extras.get('hostscript')] if (self.host_extras and self.host_extras.get('hostscript')) else []
        self.total_services = len(self.discovered_services)
        self.bundle_objects = self.IPV4s + self.MACs + self.relationships + self.discovered_services + self.host_scripts

        self.report_stix = json.loads(Bundle(
            id='bundle--' + generate_uuid(),
            assessment_date=self.assessment_date,
            start=self.start,
            stop=self.stop,
            task_name=self.IPV4s[0].value,
            objects=self.bundle_objects,
            cvss_score=float(self.cvss_score),
            total_services=self.total_services,
            allow_custom=True
        ).serialize())
        # print(self.discovered_services[0])
        # print(self.report_stix)
        # except Exception as e:
        #     log.exception(e.__str__())

    @staticmethod
    def __get_cpe_list(_services):
        return [cpe.get('__CPE__').get('_cpestring') for cpe in _services.get('__NmapService__').get('_cpelist') if _services.get('__NmapService__').get('_cpelist')]

    @staticmethod
    def get_service_cves(_service):
        _cves = []
        _scripts = _service.get('__NmapService__').get('_service_extras').get('scripts')
        for _script in _scripts:
            _elements: dict = _script.get('elements')
            # print(_elements)
            for _key, _val in _elements.items():
                # print(_key, _val)
                _cves.append({re.sub('[^A-Za-z0-9]+', '', _key): _val})
        return _cves

    @staticmethod
    def __get_service_product_version(_services):
        return _services.get('__NmapService__').get('_service').get('version')

    @staticmethod
    def __get_service_product(_services):
        return _services.get('__NmapService__').get('_service').get('product')

    @staticmethod
    def __get_service_name(_services):
        return _services.get('__NmapService__').get('_service').get('name')

    @staticmethod
    def __get_state(_services):
        return _services.get('__NmapService__').get('_state').get('state')

    @staticmethod
    def __get_port(_services):
        return _services.get('__NmapService__').get('_portid')

    @staticmethod
    def __get_protocol(_services):
        return _services.get('__NmapService__').get('_protocol')

    def __get_script_list(self, _services):
        # _list = [sc for sc in _services.get('__NmapService__').get('_service_extras').get('scripts') if
        #          len(_services.get('__NmapService__').get('_service_extras').get('scripts')) > 0]
        out = []
        scripts = []
        for sc in _services.get('__NmapService__').get('_service_extras').get('scripts'):
            if len(_services.get('__NmapService__').get('_service_extras').get('scripts')) > 0:
                out = [o for o in sc.get('output').split('\n') if o]
                sc['output'] = out
                scripts.append(sc)
        return scripts

    def __get_host_scripts(self):
        pass

    def get_stix_report(self):
        return self.report_stix

    def get_json_report(self):
        return self.report_json

    def iterdict(self, d):
        for k, v in d.items():
            if isinstance(v, dict):
                self.iterdict(v)
            else:
                print(k, ":", v)


#
# #
# if __name__ == '__main__':
#     #     cves = []
#     report_filename = '2021-12-01_15-27.json'
#     with open(report_filename) as js:
#         #         # print(json.load(js))
#         report_json = json.load(js)
#         rp = ReportParser(report_json)
#         print(rp.get_stix_report())

#         print(rp.get_stix_report())
#         hosts = report_json.get('__NmapReport__').get('_hosts')
#         for host in hosts:
#             services = host.get('__NmapHost__').get('_services')
#             for service in services:
#                 scripts = service.get('__NmapService__').get('_service_extras').get('scripts')
#                 for script in scripts:
#                     elements: dict = script.get('elements')
#                     for key, val in elements.items():
#                         cves.append({key: val})
#
#                         # print(json.dumps(el, indent=3))
