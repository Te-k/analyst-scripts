name=`md5sum $1 | cut -d ' ' -f 1`
7z a $name.zip $1 -pinfected
