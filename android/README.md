# Android

Scripts relying mostly on [androguard](https://github.com/androguard/androguard)

* `get_package_name.py` : extract package name
* `get_dex.py` : extrac classes.dex file from APKs
* `yaradex.py` : run a yara rule over the dex classes of an APK file
* `koodous_tag.py` : comment on some Koodous samples
* `koodous_search.py` : search in Koodous
* `download_androguard_report.py` : download androguard report from Koodous, copy of [this script](https://github.com/Koodous/androguard-yara/blob/master/download_androguard_report.py) updated for Python 3
* `extract_rsrc_strings.py` : list all strings in resources
* `get_method_code.py` : extract code, byte code or hex code from a method
