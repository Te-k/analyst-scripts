# PE

* build_shellcode_pe.py : build a PE file from a shellcode
* checkpesize.py : Check that the size of a PE file is correct
* common_strings.py : identify strings in common between several files
* disitool.py : python program to extract PE signatures by [Didier Stevens](https://blog.didierstevens.com/programs/disitool/)
* extract_sig.py : extract the digital signature from a PE file
* getnetguids.py : Script from [Cylance](https://github.com/cylance/GetNETGUIDs/blob/master/getnetguids.py), see [this blog post](https://medium.com/@seifreed/hunting-net-malware-40235e11dc05), updated for python 3
* get_imphash.py : extract imp hash of PE files
* get_richheaderhash.py ; Extract RichPE hash of PE files
* pecheck.py : pecheck developed by [Didier Stevens](https://blog.didierstevens.com/)
* pe.py : display information about a PE file (python2)
* pescanner.py : display information about PE files, script by Michael Ligh and published in the [Malware Analysts Cookbook](https://www.amazon.fr/Malware-Analysts-Cookbook-DVD-Techniques/dp/0470613033) (python 2)
* pesearch.py : search for a string in a PE file
* petimeline.py : Create a timeline of PE/DLL timestamp
* print_signature.py : check if PE files are signed
* py2exe_unpack.py : extract and decompyle py2exe payloads (mostly copied from [unpy2exe](https://github.com/matiasb/unpy2exe))
* pyinstxtractor.py : extract the contents of a PyInstaller generated Windows executable file by Extreme Coders ([source](https://sourceforge.net/projects/pyinstallerextractor/))
* unxor.py : Check if the file is a xored PE file and if yes unxor it (single byte key only)
