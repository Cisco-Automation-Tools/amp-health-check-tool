import re
from functools import partial

from schema import Schema, SchemaError


def _validate_mode(value):
    if value is None:
        raise SchemaError('Invalid configuration: \'MODE\' is not set')
    if not isinstance(value, str):
        raise SchemaError('Invalid configuration: \'MODE\' must be a string')
    allowed_modes = {"PRIVATE", "PUBLIC [EU]", "PUBLIC [NAM]", "PUBLIC [APJC]"}
    if value.upper() not in allowed_modes:
        raise SchemaError('Invalid configuration: \'MODE\' must be one of the following {}'.format(allowed_modes))
    return value.upper()


valid_url_re = re.compile(
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)', re.IGNORECASE)


def _validate_endpoint_list(value):
    if value is None:
        raise SchemaError('Invalid configuration: \'currentlist\' is not set')
    if not isinstance(value, list):
        raise SchemaError('Invalid configuration: \'currentlist\' is not a list of items')
    for item in value:
        _validate_valid_url(item, caller="'currentlist' items")
    return True


def _validate_valid_url(value, caller):
    if value is None:
        raise SchemaError('Invalid configuration: {} is not set'.format(caller))
    if not isinstance(value, str):
        raise SchemaError('Invalid configuration: {} must be strings'.format(caller))
    if not valid_url_re.search(value):
        raise SchemaError('Invalid configuration: {} must be a valid url'.format(caller))
    return value


config_schema = Schema({
    "MODE": _validate_mode,
    "currentlist": _validate_endpoint_list,
    "resources": {
        "isolation_code": partial(_validate_valid_url, caller="'isolation_code'"),
        "policy_serial_compare": partial(_validate_valid_url, caller="'policy_serial_compare'"),
        "tetra_def_compare_64": partial(_validate_valid_url, caller="'tetra_def_compare_64'"),
        "tetra_def_compare_32": partial(_validate_valid_url, caller="'tetra_def_compare_32'"),
        "verify_api_creds": partial(_validate_valid_url, caller="'verify_api_creds'"),
    }
})
