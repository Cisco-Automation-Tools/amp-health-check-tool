import json
import os
import pathlib as p
import platform
import re
from copy import deepcopy

from schema import SchemaError

from config_schema import config_schema

https_re = re.compile(r"^(http(?:s)?://)", flags=re.I)


class Config(dict):
    def __init__(self, data, mode):
        self.mode = mode
        data = config_schema.validate(data)
        super(Config, self).__init__(data)

    @property
    def endpoints(self):
        return self["currentlist"]

    @property
    def resources(self):
        return self["resources"]

    @property
    def amp_console_hostname(self):
        return ""

    def save(self, values, endpoints):
        self.pre_save(values, endpoints)
        # public configs should not be changeable
        pass

    def pre_save(self, values, endpoints):
        pass


class PrivateConfig(Config):
    @property
    def amp_console_hostname(self):
        isolation_str = self.resources["isolation_code"]
        schema = https_re.search(isolation_str)
        ret = https_re.sub("", isolation_str).split("/")[0]
        if schema:
            ret = schema.group(1) + ret
        return ret

    def save(self, values, endpoints):
        self.pre_save(values, endpoints)
        self["resources"]["isolation_code"] = values["-ISOLATION_CODE-"]
        self["resources"]["policy_serial_compare"] = values["-POLICY SERIAL COMPARE-"]
        self["resources"]["tetra_def_compare_32"] = values["-TETRA_32_COMPARE-"]
        self["resources"]["tetra_def_compare_64"] = values["-TETRA_64_COMPARE-"]
        self["resources"]["verify_api_creds"] = values["-VERIFY_API_CREDS-"]
        self["currentlist"] = endpoints
        self["MODE"] = "PRIVATE"

    def pre_save(self, values, endpoints):
        copy = dict(self)
        copy["resources"]["isolation_code"] = values["-ISOLATION_CODE-"]
        copy["resources"]["policy_serial_compare"] = values["-POLICY SERIAL COMPARE-"]
        copy["resources"]["tetra_def_compare_32"] = values["-TETRA_32_COMPARE-"]
        copy["resources"]["tetra_def_compare_64"] = values["-TETRA_64_COMPARE-"]
        copy["resources"]["verify_api_creds"] = values["-VERIFY_API_CREDS-"]
        copy["currentlist"] = endpoints
        copy["MODE"] = "PRIVATE"
        config_schema.validate(copy)


nam = Config({
    "MODE": "PUBLIC [NAM]",
    "currentlist": [
        "cloud-ec.amp.cisco.com",
        "cloud-ec-asn.amp.cisco.com",
        "cloud-ec-est.amp.cisco.com",
        "enrolment.amp.cisco.com",
        "console.amp.cisco.com",
        "mgmt.amp.cisco.com",
        "intake.amp.cisco.com",
        "policy.amp.cisco.com",
        "upgrades.amp.cisco.com",
        "crash.amp.cisco.com",
        "ioc.amp.cisco.com",
        "tetra-defs.amp.cisco.com",
        "clam-defs.amp.cisco.com",
        "custom-signatures.amp.cisco.com",
        "rff.amp.cisco.com",
        "orbital.amp.cisco.com",
        "ncp.orbital.amp.cisco.com"
    ],
    "resources": {
        "isolation_code": "https://api.amp.cisco.com/v1/computers/{}/isolation",
        "policy_serial_compare": "http://api.amp.cisco.com/v1/policies/{}",
        "tetra_def_compare_32": "http://update.amp.cisco.com/av32bit/versions.id",
        "tetra_def_compare_64": "http://update.amp.cisco.com/av64bit/versions.id",
        "verify_api_creds": "https://api.amp.cisco.com/v1/version",
    }
}, "PUBLIC [NAM]")
eu = Config({
    "MODE": "PUBLIC [EU]",
    "currentlist": [
        "cloud-ec.eu.amp.cisco.com",
        "cloud-ec-asn.eu.amp.cisco.com",
        "cloud-ec-est.eu.amp.cisco.com",
        "enrolment.eu.amp.cisco.com",
        "console.eu.amp.cisco.com",
        "mgmt.eu.amp.cisco.com",
        "intake.eu.amp.cisco.com",
        "policy.eu.amp.cisco.com",
        "upgrades.eu.amp.cisco.com",
        "crash.eu.amp.cisco.com",
        "ioc.eu.amp.cisco.com",
        "tetra-defs.eu.amp.cisco.com",
        "clam-defs.eu.amp.cisco.com",
        "custom-signatures.eu.amp.cisco.com",
        "rff.eu.amp.cisco.com",
        "orbital.eu.amp.cisco.com",
        "ncp.orbital.eu.amp.cisco.com"
    ],
    "resources": {
        "isolation_code": "https://api.eu.amp.cisco.com/v1/computers/{}/isolation",
        "policy_serial_compare": "http://api.eu.amp.cisco.com/v1/policies/{}",
        "tetra_def_compare_32": "http://update.amp.cisco.com/av32bit/versions.id",
        "tetra_def_compare_64": "http://update.amp.cisco.com/av64bit/versions.id",
        "verify_api_creds": "https://api.eu.amp.cisco.com/v1/version",
    }
}, "PUBLIC [EU]")
apjc = Config({
    "MODE": "PUBLIC [APJC]",
    "currentlist": [
        "cloud-ec.apjc.amp.cisco.com",
        "cloud-ec-asn.apjc.amp.cisco.com",
        "cloud-ec-est.apjc.amp.cisco.com",
        "enrolment.apjc.amp.cisco.com",
        "console.apjc.amp.cisco.com",
        "mgmt.apjc.amp.cisco.com",
        "intake.apjc.amp.cisco.com",
        "policy.apjc.amp.cisco.com",
        "upgrades.apjc.amp.cisco.com",
        "crash.apjc.amp.cisco.com",
        "ioc.apjc.amp.cisco.com",
        "tetra-defs.apjc.amp.cisco.com",
        "clam-defs.apjc.amp.cisco.com",
        "custom-signatures.apjc.amp.cisco.com",
        "rff.apjc.amp.cisco.com",
    ],
    "resources": {
        "isolation_code": "https://api.apjc.amp.cisco.com/v1/computers/{}/isolation",
        "policy_serial_compare": "http://api.apjc.amp.cisco.com/v1/policies/{}",
        "tetra_def_compare_32": "http://update.amp.cisco.com/av32bit/versions.id",
        "tetra_def_compare_64": "http://update.amp.cisco.com/av64bit/versions.id",
        "verify_api_creds": "https://api.apjc.amp.cisco.com/v1/version",
    }
}, "PUBLIC [APJC]")
empty_config_dict = {
    "MODE": "PRIVATE",
    "currentlist": [],
    "resources": {
        "isolation_code": "placeholder.com/v1/computers/{}/isolation",
        "policy_serial_compare": "placeholder.com/v1/policies/{}",
        "tetra_def_compare_64": "placeholder.com/av64bit/versions.id",
        "tetra_def_compare_32": "placeholder.com/av32bit/versions.id",
        "verify_api_creds": "placeholder.com/v1/version",
    }
}
private_config = PrivateConfig(deepcopy(empty_config_dict), "PRIVATE")


class SettingsManager:
    config_directory = p.Path.home().joinpath(".amp_health_check")
    config_file_name = "config.json"
    system = platform.system().lower()

    def __init__(self, current_config=None):
        self.configs = {
            "-NAM-": nam,
            "PUBLIC [NAM]": nam,
            "-EU-": eu,
            "PUBLIC [EU]": eu,
            "-APJC-": apjc,
            "PUBLIC [APJC]": apjc,
            "PRIVATE": private_config,
            "-PRIVATE-": private_config,
        }

        self.client_id = ""
        self.api_key = ""

        self.current: Config
        self.current = current_config

    @property
    def auth(self):
        return self.client_id, self.api_key

    def switch_config(self, config):
        self.current = config

    def load_from_disk(self):
        if "windows" not in SettingsManager.system:
            raise NotImplementedError("The AMP Healthcheck Tool only supports Windows platforms.")

        os.makedirs(SettingsManager.config_directory, exist_ok=True)
        config_file_path = SettingsManager.config_directory.joinpath(SettingsManager.config_file_name)

        if not os.path.isfile(config_file_path):
            self.current = self.configs["PUBLIC [NAM]"]
            self.save_to_disk({}, [])
            return
        with open(config_file_path, "r") as fp:
            config_data = json.load(fp)

        try:
            config_schema.validate(config_data)
        except SchemaError as e:
            print(f"Unable to load config.json: Bad Schema: {str(e)}")

        mode = config_data["MODE"]
        if mode == "PRIVATE":
            private_config = PrivateConfig(config_data, mode)
            self.configs["PRIVATE"] = private_config
            self.configs["-PRIVATE-"] = private_config
        self.current = self.configs[mode]

    def save_to_disk(self, values, endpoints):
        self.current.save(values, endpoints)
        os.makedirs(SettingsManager.config_directory, exist_ok=True)
        config_file_path = SettingsManager.config_directory.joinpath(SettingsManager.config_file_name)
        with open(config_file_path, "w") as fp:
            fp.write(json.dumps(self.current, indent=4, sort_keys=True))
