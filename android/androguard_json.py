import argparse
import os
import sys
import re
import json
import hashlib
import ssdeep
from androguard.misc import AnalyzeAPK
from androguard.core import androconf


FUNC_FILTERS = [
    ('->sendTextMessage', 'SMS'),
    ('->getRuntime', 'runbinary'),
    ('->registerReceiver', 'dynamicbroadcastreceiver'),
    ('->send(', 'socket'),
    ('->digest(', 'crypto'),
    ('->startPreview(', 'camera'),
    ('->getLine1Number(', 'phonenumber'),
    ('->getDeviceId(', 'imei'),
    ('->getAccounts()', 'accounts'),
    ('->getInstalledApplications(', 'installedapplications'),
    ('->getNetworkOperator()', 'mcc'),
]


def get_urls(apk):
    """
    Extract urls from data
    """
    res = []
    for dex in apk.get_all_dex():
        res += re.findall(b'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', dex)
    return [s.decode('utf-8') for s in res]


def get_intent_filers(apk):
    """
    Extract all intent filters from the Manifest
    """
    # FIXME : not sure this fully reproduce Koodous filters
    res = []
    filters = apk.xml['AndroidManifest.xml'].findall(".//intent-filter")
    for f in filters:
        for ff in f.findall('.//action'):
            filt = ff.get('{http://schemas.android.com/apk/res/android}name')
            if filt:
                res.append(filt)
    return res


def extract_new_permissions(permissions):
    """
    Extract permissions that are not default in Android
    """
    res = []
    for p in permissions:
        if not p.startswith('android.permission') and not p.startswith('com.google') and not p.startswith('com.android'):
            res.append(p)
    return res


def convert_x509_name(name):
    """
    Convert x509 name to a string
    """
    types = {
        'country_name': 'C',
        'state_or_province_name': 'ST',
        'locality_name': 'L',
        'organization_name': 'O',
        'organizational_unit_name': 'OU',
        'common_name': 'CN',
        'email_address': 'emailAddress'
    }

    return '/'.join(['{}={}'.format(types[attr], name.native[attr]) for attr in name.native])


def find_functionalities(dx):
    """
    Identify functionalities
    """
    func = {}
    for cl in dx.get_classes():
        for method in cl.get_methods():
            if not method.is_external():
                for i in method.get_method().get_instructions():
                    if i.get_name().startswith('invoke-'):
                        for f in FUNC_FILTERS:
                            if f[0] in i.get_output():
                                if f[1] not in func:
                                    func[f[1]] = []
                                func[f[1]].append({
                                    'code': '{} {}'.format(i.get_name(), i.get_output()),
                                    'class': cl.name,
                                    'method': method.get_method().name
                                })

    return func


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate a JSON summary of an APK using androguard')
    parser.add_argument('APK', help='An APK file')
    args = parser.parse_args()

    if not os.path.isfile(args.APK):
        print("Invalid file path")
        sys.exit(1)

    ret_type = androconf.is_android(args.APK)
    if ret_type != "APK":
        print("Not an APK file")
        sys.exit(1)

    apk, dex, dexes = AnalyzeAPK(args.APK)

    res = {
        'app_name': apk.get_app_name(),
        'package_name': apk.get_package(),
        'providers': apk.get_providers(),
        'new_permissions': extract_new_permissions(apk.get_permissions()),
        'filters': get_intent_filers(apk),
        'certificate': {},
        'wearable': apk.is_wearable(),
        'max_sdk_version': (apk.get_max_sdk_version()),
        'min_sdk_version': int(apk.get_min_sdk_version()),
        'version_code': apk.xml['AndroidManifest.xml'].get('{http://schemas.android.com/apk/res/android}versionCode'),
        'libraries': list(apk.get_libraries()),
        'androidtv': apk.is_androidtv(),
        'target_sdk_version': apk.get_target_sdk_version(),
        'api_keys': {}, # TODO
        'activities': apk.get_activities(),
        'main_activity': apk.get_main_activity(),
        'receivers': apk.get_receivers(),
        'signature_name': apk.get_signature_name(),
        'dexes': {},
        'displayed_version': apk.xml['AndroidManifest.xml'].get('{http://schemas.android.com/apk/res/android}versionName'),
        'services': apk.get_services(),
        'permissions': apk.get_permissions(),
        'cordova': None, #What is this ?
        'functionalities': {},
        'urls': get_urls(apk),
    }

    # Certificate
    if len(apk.get_certificates()) > 0:
        cert = apk.get_certificates()[0]
        res['certificate']['sha1'] = cert.sha1_fingerprint.replace(' ', '')
        res['certificate']['serial'] = '{:X}'.format(cert.serial_number)
        res['certificate']['issuerDN'] = convert_x509_name(cert.issuer)
        res['certificate']['subjectDN'] = convert_x509_name(cert.subject)
        res['certificate']['not_before'] = cert['tbs_certificate']['validity']['not_before'].native.strftime('%b %-d %X %Y %Z')
        res['certificate']['not_after'] = cert['tbs_certificate']['validity']['not_after'].native.strftime('%b %-d %X %Y %Z')

    # Dexes
    dex_names = list(apk.get_dex_names())
    dex_values = list(apk.get_all_dex())
    for dex in range(len(dex_names)):
        m = hashlib.sha256()
        m.update(dex_values[dex])
        res['dexes'][dex_names[dex][:-4]] = {
            'sha256': m.hexdigest(),
            'ssdeep': ssdeep.hash(dex_values[dex])
        }

    res['functionalities'] = find_functionalities(dexes)

    print(json.dumps(res, indent=4, sort_keys=True))


