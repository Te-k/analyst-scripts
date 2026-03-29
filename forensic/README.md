# Forensic scripts

Two scripts here to help creating timeline on Linux live systems :
* `filetimeline.py` : get a list of files in a folder with their change time, modification time and birth time using stat (which does not give the creation time even if the file system has it)
* `mactime.py` : convert this list of files into a csv timeline

Misc :
* `DeXRAY.pl` is an archive of the fascinating [Dexray](https://www.hexacorn.com/blog/2023/10/13/dexray-v2-33/) from Hexacorn in case it disappears.
* `defender_mac_unquarantine.py`: decrypt a filed quarantined by Defender for Mac OS.
* `extract_chrome_history.py`: extract history from a Chrome History Sqlite file

    * On Windows, stored in `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default`
    * On Mac OS, stored in `/Users/<username>/Library/Application Support/Google/Chrome/Default`
    * On Linux, stored in `/home/<username>/.config/google-chrome/Default`
* `ios_unpack.py` : unpack iOS backup folder from iTunes or [libimobiledevice](https://www.libimobiledevice.org/)

