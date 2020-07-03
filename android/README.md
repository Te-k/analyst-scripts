# Android

Scripts relying mostly on [androguard](https://github.com/androguard/androguard)

* `androguard_json.py` : generate a JSON with information about the APK like Koodous does
* `get_package_name.py` : extract package name
* `get_dex.py` : extrac classes.dex file from APKs
* `yaradex.py` : run a yara rule over the dex classes of an APK file
* `koodous_tag.py` : comment on some Koodous samples
* `koodous_search.py` : search in Koodous
* `download_androguard_report.py` : download androguard report from Koodous, copy of [this script](https://github.com/Koodous/androguard-yara/blob/master/download_androguard_report.py) updated for Python 3
* `extract_firebase.py` : check if firebase address in ressources
* `extract_rsrc_strings.py` : list all strings in resources
* `get_method_code.py` : extract code, byte code or hex code from a method
* `get_certificate.py` : extract certificate information
* `print_frosting.py` : check if an APK contains Google Play Metadata (also called frosting) ([ref](https://stackoverflow.com/questions/48090841/security-metadata-in-android-apk/51857027#51857027))
* `snoopdroid_vt_check.py` : check snoopdroid results on VT
* `is_obfuscated.py` : check if class names are obfuscated or not
