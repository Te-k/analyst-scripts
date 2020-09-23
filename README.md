# analyst-scripts

Random script I needed at least once for investigations or tests. Mostly python 3 compliant but maybe not. Old and new, useless and useful. If you like that, you may like [Harpoon](https://github.com/Te-k/harpoon) or [pe](https://github.com/Te-k/pe).

Feel free to open [issues](https://github.com/Te-k/analyst-scripts/issues) if you have any question.

## Main Folder

* `clamav_to_yara.py` : Convert ClamAV signature to Yara (from the [Malware Analyst's Cookbook](https://www.wiley.com/en-us/Malware+Analyst%27s+Cookbook+and+DVD%3A+Tools+and+Techniques+for+Fighting+Malicious+Code-p-9780470613030))
* `cloudcidrs.py` : check if an IP is part of a Cloud provider range (for now, only Google Cloud and Amazon AWS, inspired from [cloudcidrs](https://cloudyr.github.io/cloudcidrs/))
* `disassemble.py` : disassemble a binary file using [Capstone](http://www.capstone-engine.org/) (mostly for shellcode)
* `csv_extract.py` : extract a column from a csv file
* `hostnametoips.py` : resolve a list of hostnames in a text files and return list of uniq IPs
* `infect.sh` : classic script to create an encrypted zip of a file with password infected (password used to share malware)
* `mqtt-get.py` : basic script to do get requests to an [MQTT](https://fr.wikipedia.org/wiki/MQTT) service
* `parsejpeg.py` : Analyze JPEG headers of a file
* `parsepng.py` : Analyze a PNG file looking for weird things
* `scrdec18.c` : An old code still useful to decode .jse files (MS Jscript encoded), by MrBrownStone ([website archive](https://web.archive.org/web/20131208110057/http://virtualconspiracy.com/content/articles/breaking-screnc), [source code](https://gist.github.com/bcse/1834878))

## Subfolder

* [android](android/) : Android stuff (surprising !)
* [bitly](bitly/) : bit.ly tools
    * `bitly.py` : basic tool to request the bit.ly API
* [censys](censys/) : scripts using the censys.io API
    * `censyscerts.py` : Search for certificates
    * `censysip.py` : Search in censys IP database
    * `censysipentries.py` : Display information on an IPv4
    * `censyslib.py`  a file to reuse the function to get the API key from `~/.censys`
* [certs](certs/) : scripts to deal with certificates and CT dbs
    * `listcerts.py` list certificates from a domain in crt.sh using [pycrtsh](https://github.com/Te-k/pycrtsh)
* [email](email/) : scripts to handle emails
* [forensic](forensic) : forensic related scripts
    * `filetimeline.py` : get a list of files in a folder with their change time, modification time and birth time using stat (which does not give the creation time even if the file system has it)
    * `mactime.py` : convert this list of files into a csv timeline
* [format](format/) : convert files in different formats
    * `csv2md.py` : convert a csv file to a markdown table
    * `extract_ttld.py` : extract the TLDs from a list of domains
    * `punycode.py` : convert [a punycode domain](https://en.wikipedia.org/wiki/Punycode) to its encoded form
* [ghidra_scripts](ghidra_scripts/) : scripts for ghidra
* [goo.gl](goo.gl/) : playing with the now deprecated goo.gl API
    * `api.py` : API and CLI tool to query Google URL shortener goo.gl (soon deprecated by Google)
* [harpoon-extra](harpoon-extra/) : some scripts expanding [Harpoon](https://github.com/Te-k/harpoon) features
* [web](web/) : Web stuff (mostly outdated)
* [macos](macos/) : Mac OSX related scripts
* [misp](misp/) : some scripts helping using [MISP servers](https://www.misp-project.org/)
* [network](network/) : network related scripts
* [ooni](ooni/) : [OONI](https://ooni.torproject.org/) API scripts
* [osint](osint/) : open source intelligence scripts
* [pe](pe/) : PE scripts (most of them moved to [PE](https://github.com/Te-k/pe))
* [pt](pt/) : scripts using [Passive Total](https://community.riskiq.com/home) API
* [resources](resources/) : interesting infosec resources
* [shodan](shodan/) : [shodan.io](https://www.shodan.io/) scripts
* [threats](threats/) : threat intelligence scripts
* [twilio](twilio/) : scripts related to [Twilio](https://www.twilio.com/)
* [twitter](twitter/) : Twitter stuff
* [visualization](visualization/) : nice graphs everywhere
* [vt](vt/) : scripts related to Virus Total
