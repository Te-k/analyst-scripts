# analyst-scripts

Random script I needed at least once for investigations or tests. Mostly python 3 compliant but maybe not. Old and new, useless and useful. If you like that, you may like [Harpoon](https://github.com/Te-k/harpoon) too.

## Main Folder
* `clamav_to_yara.py` : Convert ClamAV signature to Yara (from the Malware Analyst's Cookbook)
* `cloudcidrs.py` : check if an IP is part of a Cloud provider range (for now, only Google Cloud and Amazon AWS)
* `disassemble.py` : disassemble a binary file using [Capstone](http://www.capstone-engine.org/) (mostly for shellcode)
* `hostnametoips.py` : resolve a list of hostnames in a text files and return list of uniq IPs
* `infect.sh` : classic script to create an encrypted zip of a file with password infected (password used to share malware)
* `mqtt-get.py` : basic script to do get requests to an [MQTT](https://fr.wikipedia.org/wiki/MQTT) service
* `parsepng.py` : Analyze a PNG file looking for weird things
* `scrdec18.c` : An old code still useful to decode .jse files (MS Jscript encoded), by MrBrownStone ([website archive](https://web.archive.org/web/20131208110057/http://virtualconspiracy.com/content/articles/breaking-screnc), [source code](https://gist.github.com/bcse/1834878))

## Subfolder

* bitly : bit.ly tools
    * `bitly.py` : basic tool to request the bit.ly API
* censys : scripts using the censys.io API
    * `censyscerts.py` : Search for certificates
    * `censysip.py` : Search in censys IP database
    * `censysipentries.py` : Display information on an IPv4
    * `censyslib.py`  a file to reuse the function to get the API key from `~/.censys`
* certs : scripts to deal with certificates and CT dbs
    * `listcerts.py` list certificates from a domain in crt.sh using [pycrtsh](https://github.com/Te-k/pycrtsh)
* forensic : forensic related scripts
    * `filetimeline.py` : get a list of files in a folder with their change time, modification time and birth time using stat (which does not give the creation time even if the file system has it)
    * `mactime.py` : convert this list of files into a csv timeline
* format : convert files in different formats
    * `csv2md.py` : convert a csv file to a markdown table
    * `extract_ttld.py` : extract the TLDs from a list of domains
    * `punycode.py` : convert [a punycode domain](https://en.wikipedia.org/wiki/Punycode) to its encoded form
* goo.gl : playing with the now deprecated goo.gl API
    * `api.py` : API and CLI tool to query Google URL shortener goo.gl (soon deprecated by Google)
* http : HTTP stuff
* misp : some scripts for using MISP servers
* ooni : https://ooni.torproject.org/ API scripts
* osint : open source intelligence scripts
* pe : PE scripts
* resources : interesting infosec resources
* shodan : shodan.io scripts
* twitter : Twitter stuff
* visualization : nice graphs everywhere
