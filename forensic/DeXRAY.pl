#!/usr/bin/perl
#
# dexray v2.36, copyright by Hexacorn.com, 2010-2025
#
# This is a simple script that attempts to decrypt:
# - Quarantine files from various AV / security products
# - Log and metadata encrypted files from various AV companies/products
# - Portable Executable files embedded in an encrypted form within
#   other files (using encryption relying on a one-byte xor key).
#   The decryption is generic and is based on the X-RAY algorithm.
#
# Note: the tool scans directories recursively
#
# File types that dexray attempts to handle:
#     * AhnLab (V3B)
#     * Amiti (IFC)
#     * ASquared (EQF)
#     * Avast/AVG (Magic@0='-chest- ')
#     * Avira (QUA)
#     * Baidu (QV)
#     * BitDefender (BDQ)
#     * BullGuard (Q)
#     * Cisco AMP
#     * CMC Antivirus (CMC)
#     * Comodo <GUID> (not really; Quarantined files are not encrypted :)
#     * ESafe (VIR)
#     * ESET (NQF)
#     * F-Prot (TMP) (Magic@0='KSS')
#     * G-Data (Q) (Magic@0=0xCAFEBABE)
#     * K7 Antivirus (<md5>.QNT)
#     * Kaspersky (KLQ, System Watcher's <md5>.bin)
#     * Lavasoft AdAware (BDQ) /BitDefender files really/
#     * Lumension LEMSS (lqf)
#     * MalwareBytes Data files (DATA) - 2 versions
#     * MalwareBytes Quarantine files (QUAR) - 2 versions
#     * McAfee Quarantine files (BUP) /full support for OLE format/
#     * Microsoft Antimalware / Microsoft Security Essentials
#     * Microsoft Defender PC (Magic@0=0B AD|D3 45) - D3 45 C5 99 metadata + 0B AD malicious content
#     * Microsoft Defender Mac (Magic@0=75 6E)
#     * Panda <GUID> Zip files
#     * Sentinel One (MAL)
#     * Spybot - Search & Destroy 2 'recovery'
#     * SUPERAntiSpyware (SDB)
#     * Symantec ccSubSdk files: {GUID} files and submissions.idx
#     * Symantec Quarantine Data files (QBD)
#     * Symantec Quarantine files (VBN), including from SEP on Linux
#     * Symantec Quarantine Index files (QBI)
#     * Symantec Quarantine files on MAC (quarantine.qtn)
#     * Total AV ({GUID}.dat) 'infected'
#     * Total Defense (BDQ) /BitDefender files really/
#     * TrendMicro (Magic@0=A9 AC BD A7 which is a 'VSBX' string ^ 0xFF)
#     * QuickHeal <hash> files
#     * Vipre (<GUID>_ENC2)
#     * Zemana <hash> files+quarantine.db
#     * Any binary file (using X-RAY scanning)
#
# Usage:
#      perl DeXRAY.pl <filename or directory>
#
#  History
#     2025-12-03 - Brian added yet another fix, this time for Windows Defender files. thx!
#     2025-02-24 - Added Fortinet (thx to TheMythologist who implemented it based on https://github.com/NUKIB/maldump)
#     2024-09-11 - Fixed some architecture-related bugs (hopefully!)
#     2023-10-13 - Kaspersky Security for Windows Server Fixed -> 2.33; thx RevD17!
#     2022-01-21 - Fixed support for Defender for Mac (thx to Oskar)
#     2021-11-10 - Added support for Defender for Mac (thx to Jordan Meurer)
#     2021-04-12 - Tony pointed out bug/feature with recursive directory scan and offered a fix (thx!)
#     2020-11-23 - Brian added yet another type of symantec files on Linux (different offset)
#     2020-11-18 - Added Total Defence AV (
#     2020-11-17 - Added Total AV {GUID}.dat 'infected'
#     2020-11-16 - Added K7 QNT files (<md5>.QNT)
#     2020-11-10 - Added G-Data Q files (Magic@0=0xCAFEBABE)
#     2020-10-17 - Added Amiti IFC files
#     2020-09-18 - Thanks to @r0ns3n added Cisco AMP decryption & updated X-Ray detection
#     2020-09-16 - Brian did it again -- lots of new code to handle all known variants of VBNs
#     2020-01-03 - Brian revisited the VBN routine and rewritten big part of it
#     2019-11-09 - added a quick hack to always extract 2 alternative versions of VBN Quarantine files
#                  one of them should be always right; not sure what causes it, needs further research
#     2019-07-18 - added full support for Windows Defender (now handles both malicious code & meta)
#     2018-05-12 - added Microsoft Antimalware / Microsoft Security Essentials (thx Corey Forman /fetchered/).
#     2018-04-24 - added decryption for MAL files from Sentinel One (thx @MrAdz350)
#     2018-04-23 - Brian added extraction of metadata for Linux VBN files (thx @bmmaloney97!)
#     2018-04-21 - yet another fix for VBN files (thx @bmmaloney97 & @shotgunner101)
#     2018-03-26 - better fix for VBN files (thx @bmmaloney97)
#     2018-03-08 - temp. fix for SEP decryption to handle some corner cases (needs more research)
#     2018-03-01 - Brian Maloney did an incredible work adding a much better support for VBN files (thx @bmmaloney97)
#     2018-01-26 - added Kaspersky System Watcher (thx @countuponsec)
#     2017-11-09 - added new MBAM
#     2017-10-07 - added Symantec for MAC
#     2017-09-29 - added Zemana
#     2017-09-23 - added BullGuard
#     2017-03-09 - added generic carving routine to allow extraction of troublesome files
#     2017-03-06 - added better code to handle McAfee BUP files (thx @bmmaloney97) /v1.9 not published/
#     2017-01-28 - added Lumension LEMSS (thx @JamesHabben) /v1.8 not published/
#     2016-09-18 - added a buggy routine that attempts to interpret ccSubSdk files; it does work relatively well on some files,
#                  and on others it fails miserably; pure static file-format based analysis, that's why :)
#     2016-09-15 - added Symantec ccSubSdk files: {GUID} files and submissions.idx
#     2016-06-25 - added Microsoft Defender (D3 45 C5 99 header)
#     2016-05-20 - added ESafe VIR
#     2016-05-20 - added Spybot - Search & Destroy 2 'recovery'
#     2016-04-06 - confirmed Comodo stores Quarantine files w/o encryption :)
#     2016-04-05 - added CMC Antivirus
#     2016-04-04 - added Baidu Antivirus
#     2016-04-04 - confirmed Lavasoft AdAware to be identical with BitDefender
#     2016-04-03 - added F-Prot
#     2016-04-01 - added QuickHeal
#     2016-03-31 - added Panda
#     2016-03-29 - added AhnLab
#     2016-03-28 - added Vipre
#     2016-03-26 - added Bitdefender & Avira
#     2016-03-20 - added Avast/AVG
#     2012-2016  - added ESET, ASquared, Symantec QBD/QBI, Trend, etc.
#     2012-09-22 - added support for new VBN files (xor A5 + F6 xx xx FF FF chunks)
#     2012-01-23 - fixed minor bug in X-RAY loop
#     2012-01-05 - first public release
#     2010-2012  - private version handling a couple of formats, including
#                  QUAR/DATA, VBN, BUP, X-RAY
#
# References:
#    Trend Micro decrypter
#       https://docs.trendmicro.com/all/ent/iwsva/v5.5/en-us/iwsva_5.5_olh/decrypt_encrypted_quarantine_files.htm
#       http://solutionfile.trendmicro.com/SolutionFile/11435/en/vsencode.zip
#       http://docs.trendmicro.com/all/ent/tmcm/v3.5/en-us/tmcm_3.5_olh/Template_Files/decrypt_encrypted_quarantine_files.htm
#    Symantec VBN extractor
#       https://github.com/conix-security/VBNExtract/blob/master/extractVBN.c
#    BUP extractor
#       https://github.com/herrcore/punbup/blob/master/punbup.py
#    Various Quarantine formats
#       https://github.com/brad-accuvant/cuckoo-modified/blob/master/lib/cuckoo/common/quarantine.py

use strict;
use warnings;
use Crypt::RC4;
use Digest::CRC qw(crc32);
use Digest::MD5 qw (md5 );
use Crypt::Blowfish;
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
use Compress::Raw::Zlib;
use MIME::Base64;
use OLE::Storage_Lite;
use Encode qw(decode);

$| = 1;
my %output_files;

print STDERR "
=================================================================
 dexray v2.37, copyright by Hexacorn.com, 2010-2025
 Trend&Kaspersky decryption based on code by Optiv
 McAfee BUP decryption code by Brian Maloney
 Much better Symantec VBN support code by Brian Maloney
 Kaspersky System Watcher decryption by Luis Rocha&Antonio Monaca
 Sentinel One decryption research by MrAdz350
 Microsoft AV/Security Essentials by Corey Forman /fetchered/
 Cisco AMP research by \@r0ns3n
 Fortinet code by TheMythologist
 Thx to Brian Baskin, James Habben, Brian Maloney, Luis Rocha,
 Antonio Monaca, MrAdz350, Corey Forman /fetchered/, \@r0ns3n
 Tony, Jordan Meurer, Oskar, RevD17, Roman D., TheMythologist,
 Maldump team
=================================================================
";

    my $target = shift or die "\n\nError: Gimme a filename or dir (use '.' for a current directory)\n";

       if (-d $target)
       {
          scan ($target);
       }
    elsif (-f $target)
       {
          processonefile ($target);
       }
    else
       {
          print "\n\nError: Don't know what to do with '$target'\n";
       }

    exit(0);

######################
sub scan
    {
        my $subdir = shift;

        $subdir =~ s/^\.\///;

        print   STDERR "Processing  directory: '$subdir'\n";

        opendir(DIR, $subdir);
        my @sorted_subdir = sort readdir DIR;
        closedir DIR;

        foreach my $filename (@sorted_subdir)
           {
                next if $filename =~ /^\.{1,2}$/;

                my $fullpath = $subdir.'/'.$filename;

                if (-d $fullpath)
                   {
                       scan ($fullpath);
                       next;
                   }

                processonefile ($fullpath);
           }
    }

######################
sub processonefile
    {
        my $file = shift;
        $file =~ s/^\.\///;
        return if defined $output_files{$file};
        return if $file=~/out_[0-9a-f]{8}_[0-9a-f]{8}/i;

        # Filter .rpt, .log and .db files
        return if $file=~/\.(log|rpt|db|db-wal)$/;

        print   STDERR "Processing file: '$file'\n";

        if (! -f $file)
            {
                print STDERR " -> Can't be found! (check attributes/access rights)\n";
                return;
            }

        my $filesize = -s $file;

        if ($filesize == 0)
            {
                print STDERR " -> Skipping cuz it's empty \n";
                return;
            }

        my $data = readfile ($file, 0, $filesize);

        my $datalen = length($data);
        if ($filesize != $datalen)
            {
                print STDERR " -> Skipping cuz something funny happened during data reading (investigate)\n";
                return;
            }

        ## --> AhnLab V3B files
        if ($file =~ /\.v3b$/i || substr($data,0,16) eq 'AhnLab Inc. 2006')
            {
                extract_ahnlab ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> ASquared EQF Files
        if ($file =~ /\.eqf$/i)
            {
                extract_asquared ($file, $data, 0x0000000, $filesize);
                goto skipxray;
            }

        ## --> Avast/AVG chest files
        if (substr($data,0,8) eq '-chest- ')
            {
                extract_avast_avg ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Avira QUA Files
        if ($file =~ /\.qua$/i || substr($data,0,11) eq 'AntiVir Qua')
            {
                extract_avira ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Baidu QV Files
        if ($file =~ /\.qv$/i)
            {
                extract_baidu ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> BitDefender, Lavasoft AdAware, Total Defence BDQ Files
        if ($file =~ /\.bdq$/i)
            {
                extract_bitdefender ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        if ($file =~ /\.q$/i)
            {
              ## --> G-Data Q Files
              if ($data=~/\xCA\xFE\xBA\xBE/)
               {
                  extract_gdata ($file, $data, 0x00000000, $filesize);
                  goto skipxray;
               }

               ## --> BullGuard Q Files
               extract_bullguard ($file, $data, 0x00000000, $filesize);
               goto skipxray;
            }

        ## --> Cisco AMP
        if ($file =~ /(^|[\/\\])qrt[a-z0-9]{16}\.[0-9]{3}/i)
            {
                extract_cisco_amp ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> CMC Antivirus CMC Files
        if ($file =~ /\.cmc$/i && substr($data,0,23) eq 'CMC Quarantined Malware')
            {
                extract_cmc ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> ESafe VIR Files
        if ($file =~ /\.vir$/i)
            {
                extract_esafe ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Amiti IFC Files
        if ($file =~ /\.ifc$/i)
            {
                extract_amiti ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> ESET NQF Files
        if ($file =~ /\.nqf$/i)
            {
                extract_eset ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> F-Prot TMP Files
        if ($file =~ /\.tmp$/i||$data=~/^KSS/)
            {
                extract_fprot ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Kaspersky KLQ files
        if ($file =~ /\.klq$/i || (substr($data,0,4)) eq 'KLQB')
            {
                extract_kaspersky ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> K7 QNT files
        if ($file =~ /(^|[\/\\])[0-9a-f]{32}\.QNT$/i)
            {
                extract_k7 ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Kaspersky System Watcher files
        if ($file =~ /(^|[\/\\])[0-9a-f]{32}\.bin$/i)
            {
                extract_kaspersky_system_watcher ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Kaspersky Security for Windows Server files
        if ($file =~ /{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}}$/i && $data =~ /^\xAF\x1F/)
            {
                extract_kaspersky_security_for_windows_server ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Lumension LEMSS
        if ($file =~ /\.lqf$/i)
            {
                extract_lumension ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> MalwareBytes DATA and QUAR Files
        if ($file =~ /\.(quar|data)$/i)
            {
                extract_malwarebytes ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> McAfee BUP Files
        if ($file =~ /\.bup$/i&&$data=~/^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1/)
            {
                extract_mcafee ($file);
                goto skipxray;
            }

        ## --> Microsoft Antimalware / Microsoft Security Essentials
        if ($file=~/\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}-.{1,}/i)
            {
                extract_ma_mse ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Microsoft Defender MAC
        if ($file=~/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i)
            {
                extract_defender_mac ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }


        ## --> Microsoft Defender PC - partially supported (D3 45 C5 99 header);
        if ($data=~/^(\xD3\x45|\x0B\xAD)/)
            {
                extract_defender ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Panda <GUID> Zip Files
        if ($file =~ /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i && $data=~/^PK/)
            {
                extract_panda ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Sentinel One MAL files
        if ($file =~ /\.mal$/i)
            {
                extract_sentinelone ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        if ($file =~ /-\d+/i && $data=~/^PK/)
            {
                ## --> Total AV {GUID}.dat
                if ($file =~ /(^|[\/\\])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.dat$/i && $data=~/^PK/)
                    {
                        extract_zip ($file, $data, 0x00000000, $filesize, 'Total AV', 'infected');
                        goto skipxray;
                    }

                ## --> Spybot - Search & Destroy 2 Zip Files
                extract_zip ($file, $data, 0x00000000, $filesize, 'Search & Destroy 2', 'recovery');
                goto skipxray;
            }

        ## --> SUPERAntiSpyware (SDB)
        if ($file =~ /\.sdb$/i)
            {
                extractdata ($file, $data, 0x00000000, $filesize, 0xED, 1);
                goto skipxray;
            }

        ## --> Symantec QBD and QBI Files
        ##     Note: I don't know what data is stored inside QBI files
        if ($file =~ /\.qb[di]$/i)
            {
                extractdata ($file, $data, 0x00000000, $filesize, 0xB3, 1);
                goto skipxray;
            }

        ## --> Symantec ccSubSDK {GUID} Files
        if ($file =~ /\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$/i)
            {
                extract_sym_ccSubSDK ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Symantec ccSubSDK submissions.idx Files
        if ($file =~ /submissions\.idx$/i)
            {
                extract_sym_submissionsidx ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Symantec quarantine.qtn
        if ($file =~ /quarantine\.qtn/i && $data=~/^PK/)
            {
                extract_sym_qtn ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> Symantec VBN Files
        if ($file =~ /\.vbn$/i)
            {
                extract_sep ($file, $data, $filesize);
                goto skipxray;
            }

        ## --> TrendMicro VSBX files
        if ((unpack("I",substr($data,0,4))^0xFFFFFFFF) == 0x58425356) # VSBX
            {
                extract_trend ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> QuickHeal <hash> Files
        ## --> Zemana    <hash> Files
        if ($file =~ /(^|[\/\\])[0-9a-f]{32}$/i)
            {
                if (-f 'quarantine.db')
                {
                  extract_zemana    ($file, $data, 0x00000000, $filesize);
                }
                else
                {
                  extract_quickheal ($file, $data, 0x00000000, $filesize);
                }
                goto skipxray;
            }

        ## --> Vipre <GUID>_ENC2 Files
        if ($file =~ /\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}_ENC2$/i)
            {
                extract_vipre ($file, $data, 0x00000000, $filesize);
                goto skipxray;
            }

        ## --> FortiClient files
        if ($data =~ /^\x51\x55\x41\x52\x46\x00\x00\x00/)
            {
                extract_forticlient ($file, $data, 0x00000000, $filesize);
                goto skipxray
            }

        if ($file =~ /[0-9a-f]{2,}.*?\.out$/i)
        {
          goto skipxray;
        }

        ## --> X-RAY scan
        my $progress_delta = 100/$datalen; # $datalen is never 0
        my $progress = 0;
        my $lastprogress = 0;

        my $cnt = 0;
        print   STDERR "    Attempting x-ray scan ($datalen bytes)\n";
        print   STDERR "    (may take quite some time !!!)\n" if $datalen>2000000;
        if ($data !~ /^MZ/)
        {
           for (my $ofs=0; $ofs<$datalen; $ofs++)
               {
                  print STDERR int($progress)."%\r" if $progress != $lastprogress;

                   if ( (ord(substr($data, $ofs, 1)) ^ ord(substr($data, $ofs+1, 1))) == 0x17)
                   {
                     my $key = ord(substr($data, $ofs, 1)) ^ 0x4D;
                     next if ( ord(substr($data, $ofs+1, 1)) ^ $key ) != 0x5A;

                     my $MZPE = dexor(substr($data,$ofs,16384),$key);
                     if ($MZPE =~ /^MZ.+PE\x00\x00/s)
                        {
                           $cnt+=extractdata ($file, $data, $ofs,$filesize-$ofs, $key, 0);
                        }
                   }
                   $lastprogress = $progress;
                   $progress+=$progress_delta;
               }
        }

        print   STDERR " -> Nothing found via X-RAY\n" if $cnt == 0;
        print   STDERR " -> $cnt potential file(s) found via X-RAY\n" if $cnt > 0;
     skipxray:
    }

sub extractdata
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;
        my $key  = shift;
        my $flag = shift;

        my $newfilename = sprintf($file.'.%08d.%02X.out',$ofs,$key);

        my $newdata = dexor(substr($data,$ofs,$size),$key);

        if ($newdata =~ /^MZ.+?PE\x00\x00/si)
           {
               print   STDERR " -> '$newfilename' - Possible PE\n -> ofs='$ofs' (".sprintf("%08lX",$ofs)."), key = 0x".sprintf("%02X",$key)." ($key)\n";
               writefile ($newfilename, substr($newdata,0,length($newdata)));
               return 1;
           }
        elsif ($newdata =~ /^(PK\x03\x04|Cr24|Rar!|\xCA\xFE\xBA\xBE|CAB|SZDD)/si)
           {
               print   STDERR " -> '$newfilename' - Possible Archive\n -> ofs='$ofs' (".sprintf("%08lX",$ofs)."), key = 0x".sprintf("%02X",$key)." ($key)\n";
               writefile ($newfilename, substr($newdata,0,length($newdata)));
               return 1;
           }
        elsif ($newdata =~ /^\%PDF/si)
           {
               print   STDERR " -> '$newfilename' - Possible PDF\n -> ofs='$ofs' (".sprintf("%08lX",$ofs)."), key = 0x".sprintf("%02X",$key)." ($key)\n";
               writefile ($newfilename, substr($newdata,0,length($newdata)));
               return 1;
           }

        elsif ($flag == 1)
           {
               print   STDERR " -> '$newfilename' - Decrypted data\n -> ofs='$ofs' (".sprintf("%08lX",$ofs)."), key = 0x".sprintf("%02X",$key)." ($key)\n";
               writefile ($newfilename, $newdata);
               return 1;
           }

      return 0;
    }

sub extract_sep
    {
        my $file = shift;
        my $data = shift;
        my $filesize = shift;
        my $ofs = unpack("I64", $data);
        my $recordtype;
        my $qdataheader;
        my $switch = ord(substr($data, $ofs, 1));
        my $qsize;

        #printf ("### DEBUG: The offset is @ %08lX (%d)\n",$ofs,$ofs);
        #printf ("### DEBUG: The qsize  is @ %08lX (%d)\n",$qsize,$qsize);
        #printf ("### DEBUG: The switch is %08lX (%d)\n",$switch,$switch);

        if ($ofs == 3676)
            {
                $recordtype = unpack("L",(substr($data,2656,4)));
                $qsize = unpack("L",(substr($data,2348, 4)));
            }
        if ($ofs == 4752)
            {
                $recordtype = unpack("L",(substr($data,3732,4)));
                $qsize = unpack("L",(substr($data,3412, 4)));
            }
        if ($ofs == 15100)
            {
                $recordtype = unpack("L",(substr($data,14080,4)));
                $qsize = unpack("L",(substr($data,9936, 4)));
            }
        if ($ofs == 15108)
            {
                $recordtype = unpack("L",(substr($data,14088,4)));
                $qsize = unpack("L",(substr($data,9940, 4)));
            }
        if ($recordtype == 0)
            {
                $qdataheader = unpack("L",(dexor(substr($data, $ofs+1, 8),0x5A)));
                if ($qdataheader == 0x06AAAA20)
                    {
                        $filesize = unpack("L",(dexor(substr($data, $ofs + 16, 8),0x5A)));
                        $filesize -= unpack("L",(dexor(substr($data, $ofs + 8, 8),0x5A)));
                        $ofs += unpack("L",(dexor(substr($data, $ofs + 8, 8),0x5A)));
                        sep_meta($file, $data, $ofs, 0xA5);
                        extractdata ($file, $data, $ofs, $filesize, 0x5A, 1);
                    }
                else
                    {
                        sep_meta($file, $data, $ofs, 0xA5);
                        extractdata ($file, $data, $ofs, $filesize-$ofs, 0x5A, 1);
                    }
            }
        if ($recordtype == 1)
            {
                print STDERR " -> Extracting metadata only. Does not contain quarantine file.\n";
                sep_meta($file, $data, $ofs, 0x5A);
            }
        if ($recordtype == 2)
            {
                sep_meta($file, $data, $ofs, 0xA5);
                extract_sept2($file, $data, $ofs,$filesize,$qsize);
            }
    }

sub extract_sept2
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $filesize = shift;
        my $qsize = shift;

        my $newfilename=sprintf($file.'.%08d.0xA5.out',$ofs);
        my $newdata;
        my $garbage =1;

        my $pos = $ofs + unpack("L",(dexor(substr($data,4776,4),0x5A))) + 117;
        my $qfs = unpack("L",(dexor(substr($data,$pos - 8,8),0x5A)));
        my $datatype = ord(dexor(substr($data,$pos,1),0x5A));
        if ($datatype == 0x8)
            {
                $garbage = 0;
                my $sdsize = unpack("L",(dexor(substr($data,$pos + 1,4),0x5A)));
                $pos = $pos + $sdsize + 19;
                $datatype = ord(dexor(substr($data,$pos,1),0x5A));
            }
        if ($datatype == 0x9)
            {
                my $junk = $qfs - $qsize;
                my $chunktype = ord(dexor(substr($data,$pos,1),0x5A));
                $ofs = $pos;
                while ($chunktype == 0x9)
                    {
                        my $chunksize = unpack("L",(dexor(substr($data,$pos + 1,4),0x5A)));
                        $newdata .= dexor(substr($data,$pos + 5,$chunksize),0xA5);
                        $pos = $pos + 5 + $chunksize;
                        $chunktype = ord(dexor(substr($data,$pos,1),0x5A));
                    }
                if ($newdata =~ /MZ.+?PE\x00\x00/si)
                    {
                        print   STDERR " -> '$newfilename' - Possible PE\n -> ofs='$ofs' (".sprintf("%08lX",$ofs+$-[0])."), key = 0xA5 (165)\n";
                        $ofs=$-[0];
                    }
                else
                    {
                        print   STDERR " -> '$newfilename' - Decrypted data\n -> ofs='$ofs' (".sprintf("%08lX",$ofs)."), key = 0xA5 (165)\n";
                    }
                if ($garbage == 1)
                    {
                        my $header = unpack("L",substr($newdata,8,8)) + 40;
                        writefile ($newfilename, substr($newdata,$header,$qsize));
                    }
                if ($garbage == 0)
                    {
                        writefile ($newfilename,$newdata);
                    }
            }
        else
            {
                print STDERR " -> Does not contain quarantine file.\n";
            }
    }


sub extract_mcafee
    {
        my  $file = shift;

        my  $oOl = OLE::Storage_Lite->new($file);
        my  $oPps = $oOl->getPpsTree(1);
        die ( $file. "Must be a OLE file") unless($oPps);
        my  $iTtl = 0;

        olestream ($oPps, 0, \$iTtl, 1, $file);
    }

sub extract_ma_mse
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_ma_mse.out',$ofs);

        my $newdata = dexor($data,255);
        print   STDERR " -> '$newfilename' - Microsoft Antimalware/Security Essentials File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);
    }

sub extract_defender_mac
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_defender_mac.out',$ofs);

        my $newdata = dexor($data,0x25);
        print   STDERR " -> '$newfilename' - Microsoft Defender for Mac File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);
    }

sub extract_defender
    {
        my $file = shift;
        my $data = shift;
        my $filesize = shift;
        my $ofs  = shift;
        my $size = shift;

        return if length($data)<0x3C;

        my $newfilename = sprintf($file.'.%08d_defender.out',$ofs);

        # this doesn't work for the samples I have atm
        #my $newdata = dexor(substr($data,$ofs,$size),0xFF);

        # this works for a subset of Windows Defender samples (D3 45 C5 99)
        # these files contain metadata
        my $hdrlen=0x3C;

        my $key ="\x1E\x87\x78\x1B\x8D\xBA\xA8\x44\xCE\x69\x70\x2C\x0C\x78\xB7\x86\xA3\xF6\x23\xB7\x38\xF5\xED\xF9\xAF\x83\x53\x0F\xB3\xFC\x54\xFA\xA2\x1E\xB9\xCF\x13\x31\xFD\x0F\x0D\xA9\x54\xF6\x87\xCB\x9E\x18\x27\x96\x97\x90\x0E\x53\xFB\x31\x7C\x9C\xBC\xE4\x8E\x23\xD0\x53\x71\xEC\xC1\x59\x51\xB8\xF3\x64\x9D\x7C\xA3\x3E\xD6\x8D\xC9\x04\x7E\x82\xC9\xBA\xAD\x97\x99\xD0\xD4\x58\xCB\x84\x7C\xA9\xFF\xBE\x3C\x8A\x77\x52\x33\x55\x7D\xDE\x13\xA8\xB1\x40\x87\xCC\x1B\xC8\xF1\x0F\x6E\xCD\xD0\x83\xA9\x59\xCF\xF8\x4A\x9D\x1D\x50\x75\x5E\x3E\x19\x18\x18\xAF\x23\xE2\x29\x35\x58\x76\x6D\x2C\x07\xE2\x57\x12\xB2\xCA\x0B\x53\x5E\xD8\xF6\xC5\x6C\xE7\x3D\x24\xBD\xD0\x29\x17\x71\x86\x1A\x54\xB4\xC2\x85\xA9\xA3\xDB\x7A\xCA\x6D\x22\x4A\xEA\xCD\x62\x1D\xB9\xF2\xA2\x2E\xD1\xE9\xE1\x1D\x75\xBE\xD7\xDC\x0E\xCB\x0A\x8E\x68\xA2\xFF\x12\x63\x40\x8D\xC8\x08\xDF\xFD\x16\x4B\x11\x67\x74\xCD\x0B\x9B\x8D\x05\x41\x1E\xD6\x26\x2E\x42\x9B\xA4\x95\x67\x6B\x83\x98\xDB\x2F\x35\xD3\xC1\xB9\xCE\xD5\x26\x36\xF2\x76\x5E\x1A\x95\xCB\x7C\xA4\xC3\xDD\xAB\xDD\xBF\xF3\x82\x53";
        my $rc4 = Crypt::RC4->new($key);
        my $hdr = $rc4->RC4(substr($data,0,$hdrlen));
        if (substr($hdr,0,4) eq "\xDB\xE8\xC5\x01")
        {
           $data=substr($data,$hdrlen,length($data)-$hdrlen);
           my $len1 = unpack("I",substr($hdr,0x28,4));
           my $len2 = unpack("I",substr($hdr,0x2C,4));
           $rc4 = Crypt::RC4->new($key);
           my $dec1=$rc4->RC4( substr($data,0,$len1) );
           $data=substr($data,$len1,length($data)-$len1);
           $rc4 = Crypt::RC4->new($key);
           my $dec2=$rc4->RC4( substr($data,0,$len2) );
           print   STDERR " -> '$newfilename' - Defender File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
           writefile ($newfilename, $hdr.$dec1.$dec2);
        }
        # and this works for a subset of Windows Defender samples (0B AD)
        # these files contain malicious code
        else
        {
           my $rc4 = Crypt::RC4->new($key);
           my $data = $rc4->RC4($data);
           my $ofs = 0x28 + unpack("I",substr($data,0x08,4));
           my $filesize = unpack("L",(substr($data,$ofs - 0xC,8)));
           $newfilename = sprintf($file.'.%08d_Defender.out',$ofs);
           print   STDERR " -> '$newfilename' - Defender File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
           writefile ($newfilename, substr($data,$ofs,$filesize));
        }
    }

sub extract_sym_submissionsidx
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        $data=substr($data,0x30,length($data)-0x30);
        my $cnt=0;
        while (substr($data,0,4) eq "\x40\x99\xC6\x89")
        {
          my $len1=unpack("I",substr($data,24,4));
          my $len2=unpack("I",substr($data,28,4));
          print STDERR "Submission [$cnt] len1=$len1 len2=$len2\n";
          my $newfilename = sprintf($file.'.%08d_Symantec_submission_[%04d]_idx.out',$ofs,$cnt);
          print   STDERR " -> '$newfilename' - Symantec submission_".sprintf("[%04d]",$cnt).".idx File\n";
          my $dec=blowfishit(substr($data,56,$len1),substr($data,40,16),1);
          writefile ($newfilename, $dec);
          $newfilename = sprintf($file.'.%08d_Symantec_submission_[%04d]_idx.met',$ofs,$cnt);
          my $dataout=parsesym($dec);
          writefile ($newfilename, $dataout);
          $data=substr($data,40+$len1);
          $cnt++;
        }

    }

# 8EF95B94E971E842BAC952B02E79FB74 AVModule.dll
# 2B5CA624B61E3F408B994BF679001DC2 BHSvcPlg.dll
# 6AB68FC93C09E744B828A598179EFC83
# 5E6E81A4A77338449805BB2B7AB12FB4
sub extract_sym_ccSubSDK
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_Symantec_ccSubSDK.out',$ofs);
        print   STDERR " -> '$newfilename' - Symantec_ccSubSDK File\n";
        print "GUID = ".hexdump (substr($data,0,16))."\n";
        my $dec=blowfishit(substr($data,32,length($data)-32),substr($data,16,16),1);
        writefile ($newfilename, $dec);
        carve     ($newfilename);

        $newfilename = sprintf($file.'.%08d_Symantec_ccSubSDK.met',$ofs);
        my $dataout=parsesym($dec);
        writefile ($newfilename, $dataout);
    }

sub parsesym
    {
      my $data  = shift;

      my $ret='';

      my $lasttoken=0;
      my $contlen=0;
      while (1)
      {
          my $token = ord(substr($data,0,1)) or last;

          $ret.=sprintf("%02X",$token)."\n";

          if    ($token==0x00) { $ret.=hexdump (substr($data,1,8))."\n"; $data=substr($data,1+8,length($data)-9); }
          elsif ($token==0x01) { $ret.=hexdump (substr($data,1,1))."\n"; $data=substr($data,1+1,length($data)-2); }
          elsif ($token==0x02) { $ret.=hexdump (substr($data,1,2))."\n"; $data=substr($data,1+2,length($data)-3); }
          elsif ($token==0x03) { $ret.=hexdump (substr($data,1,4))."\n"; $data=substr($data,1+4,length($data)-5); }
          elsif ($token==0x04) { $ret.=hexdump (substr($data,1,8))."\n"; $data=substr($data,1+8,length($data)-9); }
          elsif ($token==0x06) { $ret.=hexdump (substr($data,1,4))."\n"; $data=substr($data,1+4,length($data)-5); }
          elsif ($token==0x07) {
               $ret.=hexdump (substr($data,1,4))."\n";
               my $strlen=unpack("I",substr($data,1,4));
               my $string=substr($data,5,$strlen);
               $ret.=hexdump (substr($data,5,$strlen))."\n### STRING-A\n      $string\n\n";
               $data=substr($data,1+4+$strlen,length($data)-5-$strlen);
                               }
          elsif ($token==0x08) {
               $ret.=hexdump (substr($data,1,4))."\n";
               my $strlen=unpack("I",substr($data,1,4));
               my $string=substr($data,5,$strlen);
               $string =~ s/\x00//gs;
               $ret.=hexdump (substr($data,5,$strlen))."\n### STRING-W\n      $string\n\n";
               $data=substr($data,1+4+$strlen,length($data)-5-$strlen);
                               }
          elsif ($token==0x09) {
               $ret.=hexdump (substr($data,1,4))."\n";
               $contlen=unpack("I",substr($data,1,4));
               $data=substr($data,1+4,length($data)-5);
                               }
          elsif ($token==0x0A) { $ret.=hexdump (substr($data,1,1)) ."\n";$data=substr($data,1+1,length($data)-2); }
          elsif ($token==0x0F) {
               $ret.="\n### GUID\n".hexdump (substr($data,1,16))."\n";
               $data=substr($data,1+16,length($data)-17);
                               }
          elsif ($token==0x10) {
                 if ($lasttoken==9)
                 {
                  $ret.=hexdump(substr($data,1,16))."\n";
                  $data=substr($data,1+16,length($data)-17);
                 }
                 else
                 {
                  $data=substr($data,1+16,length($data)-17);
                 }
                               }
          else
          {
              if ($lasttoken!=9)
              {
                $ret.="### Error: $token [$lasttoken]!\n.[".hexdump(substr($data,0,16))."]\n";
                #### very stupid fix, but at least it produces some output
                #### when the routine gets stuck
                if ($data=~/(
                    \x01\x35\xDB\x62\x9E\xE4\x0A\x40\x80\x27\x90\xA6\x7C\x64\x9F\x2E|
                    \x12\x90\x16\x29\xB1\xB6\x28\x40\xA5\x4A\x81\xC9\x1E\x79\xFD\x8C|
                    \x20\xE4\x52\xD3\x86\x9E\x7F\x4A\x82\x6C\xA8\x78\x26\x62\xB2\x46|
                    \x21\xA3\x05\x3F\xB7\x43\x78\x45\x93\xC8\xCD\xC5\xF6\x4A\x14\x9A|
                    \x25\x7B\x09\x10\xB0\xB2\xD7\x42\xBF\x9F\xA8\xB7\x48\x86\x75\x72|
                    \x3B\x3F\xFF\x0B\x21\x8D\x56\x4E\x84\xFF\x8E\x1C\x6D\xCF\xD7\x45|
                    \x56\xA9\x7B\xD9\x75\x7A\x08\x41\x8D\xCB\xE1\xD3\xAD\x6B\x55\x08|
                    \x6B\xC4\x70\x6E\xD6\x7F\x71\x4D\xA2\x33\xB1\x01\xE9\xAD\x72\xF2|
                    \x84\x12\x69\x0E\x06\xF4\x81\x45\xBD\x8F\xC6\x66\xC9\xFD\xEC\x84|
                    \x91\xD2\x5F\x94\x65\xF5\x44\x4A\x88\xEB\x23\xB6\x5C\xBB\xF9\x6B|
                    \xBF\xCC\x5C\x4E\xCB\x10\xBC\x45\x84\xAE\x94\x00\x03\x4A\xF8\xC4|
                    \x21\xA3\x05\x3F\xB7\x43\x78\x45\x93\xC8\xCD\xC5\xF6\x4A\x14\x9A|
                    \x63\x47\x39\xF6\x0E\x6A\xCF\x05\xD0\x5F\x1D\xFF\xD9\xA4\xCB\x16|
                    \x64\x45\x32\x31\x13\x3B\x33\x45\x89\x99\x33\x99\x06\x88\xF5\xA9|
                    \x6A\xB6\x8F\xC9\x3C\x09\xE7\x44\xB8\x28\xA5\x98\x17\x9E\xFC\x83|
                    \x7C\x62\xD3\x37\x34\x34\x45\x32\x3C\x37\x43\x33\xCB\xCC\x32\x33|
                    \xBB\x81\x1A\x3A\x8F\xC1\xBE\x48\x82\x2C\x8B\x62\x63\xA5\x20\x4D
                )/sgx)
                {
                  $data=substr($data,(pos $data),length($data)-(pos $data));
                  $ret.="### Resuming search after the GUID!\n";
                }
                else
                {
                  last;
                }
              }
              else
              {
                 my $cont=substr($data,0,$contlen);
                 if (length($cont)==16)
                 {
                    $ret.="\n### GUID\n".hexdump($cont);
                 }
                 else
                 {
                    $ret.="\n### BLOB\n".hexdump($cont);
                 }
                 $contlen=length($data) if $contlen>length($data);

                 $data=substr($data,$contlen,length($data)-$contlen);
              }
          }

          $lasttoken=$token;
      }

      return $ret;
    }

sub extract_panda
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $zip = Archive::Zip->new();
        if ($zip->read( $file ) != AZ_OK)
        {
          print STDERR "Error reading zip file $file\n" ;
        }

        my @members = $zip->memberNames();
        foreach my $onefile (sort @members)
        {

          my $newfilename = '';
          if ($onefile =~ /QEINFO/i)
          {
           $newfilename = sprintf($file.'.%08d_Panda_'.$onefile.'.met',$ofs);
           print   STDERR " -> '$newfilename' - Panda File MetaData\n";
         }
          else
          {
           $newfilename = sprintf($file.'.%08d_Panda_'.$onefile.'.out',$ofs);
           print   STDERR " -> '$newfilename' - Panda File\n";
          }

          my $ddata = $zip->contents( $onefile);
          my $key ="\x3D\xD8\x22\x66\x65\x16\xE3\xB8\xC5\xD6\x18\x71\xE7\x19\xE0\x5A";
          my $dec=blowfishit($ddata,$key,0);
          my $gun = new Compress::Raw::Zlib::Inflate(WindowBits => WANT_GZIP);
          my $dec2;
          $gun->inflate($dec,$dec2);
          writefile ($newfilename, $dec2);
        }
    }

sub extract_lumension
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_Lumension_'.$file.'.out',$ofs);
        print   STDERR " -> '$newfilename' - Lumension File\n";

        my $gun = new Compress::Raw::Zlib::Inflate(WindowBits => WANT_GZIP);
        my $dec;
        $gun->inflate(substr($data,32,length($data)-32),$dec);
         writefile ($newfilename, $dec);
    }

sub extract_zip
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;
        my $prod = shift;
        my $pass = shift;

        my $zip = Archive::Zip->new();
        if ($zip->read( $file ) != AZ_OK)
        {
          print STDERR "Error reading zip file $file\n" ;
        }

        my @members = $zip->memberNames();
        foreach my $onefile (sort @members)
        {

          print   STDERR " -> '$file' - $prod File\n";
        }
        print   STDERR " To extract, use 7zip, Winrar, etc. - the password is '$pass'\n";
    }

sub extract_sym_qtn
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $zip = Archive::Zip->new();
        if ($zip->read( $file ) != AZ_OK)
        {
          print STDERR "Error reading zip file $file\n" ;
        }

        my @members = $zip->memberNames();
        foreach my $onefile (sort @members)
        {

          print   STDERR " -> '$onefile' - Symantec QTN File\n";
        }
        print   STDERR " To extract, use 7zip, Winrar, etc. - the password is ... the actual file name\n";
        print   STDERR " i.e. to extract 00000000-1111-2222-3333-444444444444.zip use\n";
        print   STDERR "       password: 00000000-1111-2222-3333-444444444444.zip\n";

    }

sub extract_bitdefender
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_BITDEFENDER.out',$ofs);

        my $dec='';
        my $cl=25;
        my $dl=43;
        for (my $i=0; $i<length($data); $i++)
        {
           $dec.=chr ( ((ord (substr($data,$i,1))-$dl) %256)^ $cl ) ;
           $cl=($cl+3)%256;
           $dl=($dl+20)%256;
        }

        print   STDERR " -> '$newfilename' - BitDefender File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $dec);
    }

sub extract_bullguard
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_BULLGUARD.out',$ofs);

        my $dec='';
        for (my $i=0; $i<length($data); $i++)
        {
           $dec.=chr ( ord (substr($data,$i,1)) ^ ((int($i%2)?0x00:0x3F)));
        }

        print   STDERR " -> '$newfilename' - BullGuard File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $dec);
    }

sub extract_avira
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_AVIRA.out',$ofs);

        my $o2d = unpack("I",substr($data,16,4));
        my $newdata = dexor(substr($data,$o2d,length($data)-$o2d),170);
        print   STDERR " -> '$newfilename' - Avira File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);
    }

sub extract_baidu
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename_out = sprintf($file.'.%08d_Baidu.out',$ofs);
        my $newfilename_met = sprintf($file.'.%08d_Baidu.met',$ofs);

        print   STDERR " -> '$newfilename_out' - Baidu File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        print   STDERR " -> '$newfilename_met' - Baidu File MetaData\n";

        my $magic   = unpack("I", substr($data,0x0,4));
        my $time1   = unpack("I", substr($data,0x4,4));
        my $task    = unpack("I", substr($data,0x8,4));
        my $scanstat= unpack("I", substr($data,0xC,4));
        my $md5     = substr($data,0x10,0x42);
           $md5=~s/\x00//g;

        $data=substr($data,0x52,length($data)-0x52);
        my $len=unpack("I", substr($data,0,4));
        my $path=substr($data,4,$len);
           $path =~s/\x00//g;

        $data=substr($data,4+$len,length($data)-$len-4);
        $len=unpack("I", substr($data,0,4));
        my $clientid=substr($data,4,$len);
           $clientid =~s/\x00//g;

        $data=substr($data,4+$len,length($data)-$len-4);
        my $st=unpack("I", substr($data,0,4));

        $data=substr($data,4,length($data)-4);
        $len=unpack("I", substr($data,0,4));
        my $threat=substr($data,4,$len);
           $threat =~s/\x00//g;

        $data=substr($data,4+$len,length($data)-$len-4);
        $len=unpack("I", substr($data,0,4));
        my $maltype=substr($data,4,$len);
           $maltype =~s/\x00//g;

        $data=substr($data,4+$len,length($data)-$len-4);
        $len=unpack("I", substr($data,0,4));
        my $packtype=substr($data,4,$len);
           $packtype =~s/\x00//g;

        $data=substr($data,4+$len,length($data)-$len-4);
        $len=unpack("I", substr($data,0,4));
        my $reserved=substr($data,4,$len);
           $reserved =~s/\x00//g;

        $data=substr($data,4+$len,length($data)-$len-4);
        my $crc32=unpack("I", substr($data,0,4));

        $data=substr($data,4,length($data)-4);

        my $meta = '';
        $meta.="    Magic        = $magic\n";
        $meta.=sprintf("    Time         = %s (%d)\n",epoch($time1),$time1);
        $meta.=sprintf("    Task         = %08lX\n",$task);
        $meta.="    Scan Status  = $scanstat\n";
        $meta.="    MD5          = $md5\n";
        $meta.="    Path         = $path\n";
        $meta.="    ClientID     = $clientid\n";
        $meta.="    Scanner Type = $st\n";
        $meta.="    Threat Name  = $threat\n";
        $meta.="    Malware Type = $maltype\n";
        $meta.="    Pack Type    = $packtype\n";
        $meta.="    Reserved     = $reserved\n";
        $meta.="    CRC32        = ".sprintf("%08lX",$crc32)."\n";

        my @key =(0xD9,0xA7,0xA3,0xBF,0x85,0xFF,0x43,0x77,0xAD,0x06,0xCF,0xFD,0x1F,0x94,0xE9,0xCC);

        my $dec='';
        while (length($data)>0)
        {
           my $lend=unpack("S", substr($data,0,2));
           $data=substr($data,2,length($data)-2);
           my $gun = new Compress::Raw::Zlib::Inflate();
           my $dec2;
           $gun->inflate($data,$dec2);
           my $b=ord(substr($dec2,0,1));
           for (my $i=0;$i<length($dec2);$i++)
           {
             $b=$b ^ $key[$i % ($#key+1)];
           }
           $data=substr($data,$lend,length($data)-$lend);
           $dec.=chr($b).substr($dec2,1,length($dec2)-1);
        }
        print   STDERR "$meta\n";
        writefile ($newfilename_met, $meta);
        writefile ($newfilename_out, $dec);
    }

sub extract_cisco_amp
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_CiscoAMP.out',$ofs);
        my $dec='';
        for (my $i=0; $i<length($data); $i++)
        {
           $dec.=chr ( (ord (substr($data,$i,1)) ^ (0x77)&0xFF));
        }
        print   STDERR " -> '$newfilename' - Cisco AMP File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $dec);
     }

sub extract_cmc
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename_out = sprintf($file.'.%08d_CMC 1.out',$ofs);
        my $newfilename_met = sprintf($file.'.%08d_CMC 1.met',$ofs);

        print   STDERR " -> '$newfilename_out' - CMC File 1\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        print   STDERR " -> '$newfilename_met' - CMC File 1 MetaData\n";

        my $magic   = substr($data,0x0,32);  $magic=~s/[\r\n]+//g;
        my $ffv     = unpack("I", substr($data,0x20,4));

        my $crc     = unpack("I", substr($data,0x28,4));
        my $adler   = unpack("I", substr($data,0x2C,4));
        my $ofn     = unpack("S", substr($data,0x50,2));
        my $us      = unpack("I", substr($data,0x54,4));
        my $qs      = unpack("I", substr($data,0x58,4));
        my $tnl     = unpack("S", substr($data,0x6C,2));

        my $fn=substr($data,0x200,$ofn);
        my $tn=substr($data,0x200+$ofn,$tnl);

        my $md5     = substr($data,0x30,16);
           $md5=~s/(.)/sprintf("%02X",ord($1))/ges;

        my $submitid     = substr($data,0x40,16);
           $submitid=~s/(.)/sprintf("%02X",ord($1))/ges;

        my $meta = '';
        $meta.="    Magic             = $magic\n";
        $meta.="    File version      = $ffv\n";
        $meta.="    CRC               = ".sprintf("%08lX",$crc)."\n";
        $meta.="    Adler             = ".sprintf("%08lX",$adler)."\n";
        $meta.="    Original Size     = $us\n";
        $meta.="    Quarantined Size  = $qs\n";
        $meta.="    Original FileName = $fn\n";
        $meta.="    MD5               = $md5\n";
        $meta.="    Threat Name       = $tn\n";
        $meta.="    SubmitID          = $submitid\n";

        $data=substr($data,0x200+$ofn+$tnl,length($data)-0x200-$ofn-$tnl);
        my $buflen=unpack("I", substr($data,0,4));
        $data=substr($data,4,$buflen);
        my $dec=dexor($data,30);

        print   STDERR "$meta\n";
        writefile ($newfilename_met, $meta);
        writefile ($newfilename_out, $dec);

        my $zip = Archive::Zip->new();
        if ($zip->read( $newfilename_out ) != AZ_OK)
        {
          print STDERR "Error reading zip file $newfilename_out\n" ;
        }

        my @members = $zip->memberNames();
        my $cnt=2;
        foreach my $onefile (sort @members)
        {
          $newfilename_out = sprintf($file.".%08d_CMC $cnt.out",$ofs);
          my $dec = $zip->contents( $onefile);
          print   STDERR " -> '$newfilename_out' - CMC File $cnt\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
          writefile ($newfilename_out, $dec);
          $cnt++;
        }

    }

sub extract_vipre
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_Vipre.out',$ofs);

        my $newdata = dexor($data,51);
        print   STDERR " -> '$newfilename' - Vipre File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);
    }

sub extract_forticlient
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename_out = sprintf($file.'.%08d_forticlient.out',$ofs);
        my $newfilename_met = sprintf($file.'.%08d_forticlient.met',$ofs);

        my $magic         = substr($data,0x0,8);
        my $unknown1      = unpack("I", substr($data,0x8,4));
        my $mal_offset    = unpack("I", substr($data,0xC,4));  # Inaccurate for some reason
        my $unknown2      = substr($data,0x10,2);
        my $sha256_hash   = unpack("H*", substr($data,0x12,32));
        my $unknown3      = substr($data,0x32,2);
        my $mal_len       = unpack("I", substr($data,0x34,4));
        my $raw_timestamp = substr($data,0x38,16);

        my $year        = unpack("s", substr($raw_timestamp,0x0,2));
        my $month       = unpack("s", substr($raw_timestamp,0x2,2));
        my $tz_offset   = unpack("s", substr($raw_timestamp,0x4,2));
        my $day         = unpack("s", substr($raw_timestamp,0x6,2));
        my $hour        = unpack("s", substr($raw_timestamp,0x8,2));
        my $minute      = unpack("s", substr($raw_timestamp,0xA,2));
        my $second      = unpack("s", substr($raw_timestamp,0xC,2));
        my $microsecond = unpack("s", substr($raw_timestamp,0xE,2));
        my $date = $month."/".$day."/".$year." ".$hour.":".$minute.":".$second.":".$microsecond." +".$tz_offset;

        my $unknown4      = substr($data,0x48,12);
        my $file_id       = unpack("I", substr($data,0x54,4));
        my $fn_len        = unpack("I", substr($data,0x58,4));
        my $tn_len        = unpack("I", substr($data,0x5C,4));
        my $fn            = decode("UTF16-LE", substr($data,0x60,$fn_len));
        my $tn            = decode("UTF16-LE", substr($data,0x60+$fn_len,$tn_len));
        my $data          = substr($data,0x60+$fn_len+$tn_len,$mal_len);

        my $dec=dexor($data,171);

        print   STDERR " -> '$newfilename_out' - Forticlient File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename_out, $dec);

        my $meta = '';
        $meta.="    Magic             = $magic\n";
        $meta.="    SHA256            = $sha256_hash\n";
        $meta.="    Quarantine Time   = $date\n";
        $meta.="    File ID           = $file_id\n";
        $meta.="    Original Filename = $fn\n";
        $meta.="    Threat Name       = $tn\n";
        print   STDERR " -> '$newfilename_met' - Forticlient Metadata\n";
        writefile ($newfilename_met, $meta);
    }

sub extract_quickheal
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_QuickHeal.out',$ofs);

        my $dec='';
        my $ki=0;
        for (my $i=0; $i<length($data); $i++)
           {
              my $b1=ord (substr($data,$i,1));
              my $b2=$b1;
              $dec.=chr (($b1>>4)|(($b2<<4)&0xFF));
           }

        print   STDERR " -> '$newfilename' - QuickHeal File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $dec);
    }

sub extract_zemana
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        if (!-f 'quarantine_db_Zemana.out')
        {
          my $data = readfile ('quarantine.db', 8, (-s 'quarantine.db')-8);
          my $rc4 = Crypt::RC4->new( 'AA33A87C484AF1107F1C381B10C63C1E1788A0FF6A1D95F0D95AA46D7FB6A161' );
          my $newdata = $rc4->RC4( $data );
          print   STDERR " -> 'quarantine_db_Zemana.out' - Zemana Quarantine file\n";
          writefile ('quarantine_db_Zemana.out', $newdata);
        }

        my $newfilename = sprintf($file.'.%08d_Zemana.out',$ofs);

        my $rc4 = Crypt::RC4->new( 'A8147B3ABF8533AB27FA9551B1FAA385' );
        my $newdata = $rc4->RC4( $data );

        print   STDERR " -> '$newfilename' - Zemana File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);

    }

sub extract_ahnlab
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_AhnLab.out',$ofs);

        my $o2d = unpack("I",substr($data,0x58,4))+0x58;
        $data = substr($data,$o2d,length($data)-$o2d);
        my @key =(~0x76,~0x33,~0x62,~0x61,~0x63,~0x6B,~0x75,~0x70,~0x21,~0x40,~0x23,~0x24,~0x25,~0x5E,~0x26,~0x29);

           my $dec='';
           my $ki=0;
           for (my $i=0; $i<length($data); $i++)
           {
              $dec.=chr ( (ord (substr($data,$i,1)) ^ ($key[$ki] &0xFF)));
              $ki++;
              if ($ki>($#key)) {$ki=0;}
           }

        print   STDERR " -> '$newfilename' - AhnLab File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $dec);
    }

sub extract_avast_avg
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_AVAST_AVG.out',$ofs);
        $data=substr($data,8,length($data)-8);

        my @key =(0x33,0xB6,0x59,0x83,0x8B,0x43,0x75,0xFB,0x35,0xB6,0x8A,0x37,0xAE,0x29,0x16,0x47,0xA2,0x51,0x41,0x4F,0x69,0x9A,0x07,0xF5,0xF1,0x69,0x80,0x89,0x60,0x15,0x8E,0xF6,0xB2,0x3B,0x89,0xC4,0x9F,0xFF,0x65,0x2E,0x36,0xD3,0xF2,0x10,0xEA,0x76,0x88,0xAD,0x19,0x39,0x44,0xEF,0x7E,0xBC,0xAF,0xA0,0x26,0x7D,0x83,0xC9,0x13,0xC7,0xBD,0xE1,0x16,0xEB,0x27,0x69,0x2C,0x17,0xE2,0xF9,0xF8,0x8A,0x7F,0x6E,0x6F,0xEB,0x16,0x16,0x60,0x48,0x86,0x12,0xC5,0x9A,0x91,0x6B,0xB3,0xA2,0x71,0x38,0xC6,0x2F,0x4E,0x05,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0x0F,0x08,0xE3,0x73,0xA6,0xA0,0x2E,0x02,0x76,0x7F,0x97,0x9F,0x8E,0x5D,0x80,0xDE,0x75,0xDB,0x41,0x31,0x62,0xCC,0x68,0x73,0x79,0x33,0x3F,0xE8,0xDC,0xCD,0xF5,0x9A,0x9E,0x1F,0x21,0xD7,0x97,0xDF,0x66,0xC8,0x50,0x0F,0xBD,0x2E,0x35,0x11,0x1D,0x77,0xE1,0x62,0xA1,0xCA,0x4C,0xC7,0x4C,0xE3,0xB5,0x5C,0x86,0xD5,0xE4,0xCE,0xF5,0xD3,0xCF,0xA5,0xE6,0x54,0xA7,0x2E,0x7B,0xA8,0xBA,0xA5,0x8B,0x02,0x15,0x4E,0xEE,0xD6,0xB1,0xE4,0xEB,0x46,0x9B,0x8B,0xB5,0x26,0xCA,0x88,0xAF,0xE6,0xF8,0x56,0xFA,0x6F,0x39,0x48,0x6B,0xFA,0xF0,0x7A,0x4F,0xC4,0xE3,0xA7,0x2C,0x62,0x44,0x84,0x39,0xE3,0xDD,0xED,0xA4,0xF6,0xFD,0x4E,0xB8,0x92,0x0C,0x1D,0x3A,0x78,0x7E,0xDD,0x03,0x3E,0xD1,0x7B,0xE6,0x2C,0xBE,0xD3,0x87,0x75,0xD5,0xE1,0x2F,0x07,0x19,0x37,0x01,0x40,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0x6F,0x43,0x73,0x1E,0x13,0x7D,0x30,0x3D,0xFA,0x30,0x5B,0x81,0x68,0x7C,0xF9,0xEA,0x52,0xA9,0xE3,0xF4,0x28,0x8C,0x01,0x38,0xAF,0xE9,0xD0,0xA8,0x2C,0xD4,0x62,0xE8,0x41,0xA5,0xB1,0x71,0xC1,0x2E,0x2B,0x79,0xE3,0xFF,0xA8,0x24,0x12,0xAF,0x89,0xA7,0x9A,0x6D,0x73,0xE6,0xCD,0xE8,0x11,0x75,0xFF,0xE6,0x70,0x8A,0x8A,0xE5,0x4F,0x08,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0x32,0x91,0x88,0xC4,0x01,0x19,0x08,0x2F,0x48,0x84,0xD2,0x30,0x5F,0x56,0xB7,0x15,0xAF,0x90,0x52,0x1A,0x1B,0x16,0xCD,0x84,0xEA,0x6E,0xE6,0x9A,0x89,0xC3,0x48,0xF0,0x9C,0xBD,0xC3,0x95,0x18,0xF9,0x30,0xC0,0xD2,0x50,0x21,0x66,0x41,0xA1,0x82,0xB6,0xA5,0x57,0x64,0x6A,0x96,0x96,0x8C,0x1D,0x94,0x74,0xD6,0x2F,0x77,0x12,0x4B,0x3F,0xF6,0x5C,0x33,0x8C,0xA1,0x21,0x7F,0x3C,0x5B,0x9D,0xCB,0x2C,0x1F,0x6E,0xA0,0xAA,0x8F,0xEA,0x09,0x90,0x4B,0x47,0xD0,0x27,0xA7,0x9A,0x89,0x78,0x9E,0x20,0xF2,0x8E,0x81,0x12,0xDD,0x09,0xDF,0x0D,0x7F,0x4B,0x76,0xB5,0x89,0xA7,0x69,0x7F,0x42,0x15,0x22,0x7F,0xE9,0x59,0xA6,0xFD,0x59,0x2A,0x8E,0x58,0x25,0xCC,0xFC,0x63,0x88,0xC5,0x64,0x22,0x71,0x48,0x2E,0xC9,0xC8,0xE3,0xAE,0xB4,0x94,0xBD,0x73,0x7A,0x11,0x04,0x37,0x0C,0xF0,0x04,0x1D,0x57,0x62,0x6F,0x65,0xFE,0x57,0x97,0xBA,0x44,0x81,0xA7,0x9D,0xB4,0xFC,0x16,0x3E,0xB5,0x05,0xED,0xD1,0x67,0xD5,0x2A,0xE7,0xCF,0xD5,0xD5,0xD4,0xC8,0x4A,0x1F,0x85,0x39,0x79,0xDF,0xB7,0x1E,0x79,0x75,0xC3,0xB3,0xB4,0xCA,0xA1,0x3D,0x38,0x54,0xC6,0x42,0x17,0x3B,0x57,0x02,0xB9,0xDC,0xDE,0xC8,0x1F,0x88,0x0A,0x9B,0xB7,0x4E,0x95,0x25,0xCE,0xC8,0x3F,0x02,0x74,0xFD,0xB8,0xA2,0x5C,0x12,0x1D,0xD6,0x25,0x37,0xE3,0xD3,0x6C,0x2A,0x9D,0x8F,0x93,0x26,0xE3,0x3F,0xC1,0xD6,0xBE,0x14,0x8E,0xEF,0x08,0xBC,0x4D,0xB4,0xDE,0xE9,0x05,0x14,0x29,0xA0,0x3A,0x57,0xEB,0x52,0x47,0xD7,0xDE,0x1D,0x42,0x97,0x51,0xD3,0x85,0x0D,0xA7,0xF0,0xF7,0xD3,0x30,0xFC,0x78,0xC3,0x77,0x73,0x8D,0x8E,0xF4,0x18,0x2D,0x33,0xC6,0xE9,0x9F,0xE3,0x1E,0x81,0x8A,0x99,0xDB,0x26,0x36,0x8D,0xC1,0x9D,0xC0,0x03,0xF2,0xB7,0xBC,0xA3,0xBD,0x22,0xA8,0xAF,0x5D,0x37,0x1A,0x3E,0x1D,0x9C,0x48,0xD6,0xA8,0x0D,0x21,0xA6,0x7A,0xC0,0x11,0x37,0xB3,0x97,0x5D,0x50,0x5A,0xE8,0xDC,0xC6,0x7F,0xF8,0x16,0x35,0xED,0x28,0xEF,0x51,0xEE,0x05,0x43,0x4F,0x62,0x15,0xBE,0x8B,0x88,0x0F,0x6C,0xB0,0x57,0x69,0x57,0xB1,0xFF,0x76,0x44,0x64,0x6C,0xA3,0x12,0x9C,0x54,0x5C,0x7B,0xA2,0xC3,0xAD,0x26,0x60,0xDE,0xF0,0x5D,0x23,0xA3,0x28,0xF5,0xAB,0x88,0x8B,0x61,0x85,0x02,0xC8,0xB3,0x1D,0x41,0xD2,0x30,0x0B,0x22,0x2C,0xEA,0xD3,0xC9,0xEB,0x3F,0x23,0x80,0xDA,0xC3,0x84,0x0F,0x6C,0xD4,0xCC,0x1E,0x5F,0x6D,0x22,0xAC,0x74,0x1D,0xD2,0x09,0x3A,0x1B,0x28,0x08,0xB6,0xED,0x92,0xE6,0xA5,0xAD,0x9B,0x84,0x09,0x40,0xA2,0x91,0x6C,0x1A,0x90,0x72,0x8E,0x54,0x63,0x16,0xA6,0xDD,0xFC,0xF3,0x23,0x3E,0x11,0xF0,0x0A,0x32,0x2C,0x7B,0x81,0x60,0xFF,0x61,0xF7,0x4A,0x7A,0x07,0x10,0x7B,0xEB,0x68,0x90,0x56,0xD9,0x6A,0x3D,0xDB,0x22,0x31,0x65,0xA2,0x2D,0xA4,0xB4,0x82,0xC3,0xEA,0x7C,0xF8,0x24,0x88,0x80,0x4A,0x2F,0xA9,0x56,0x55,0xBD,0x2E,0x88,0xF7,0x26,0x36,0x1D,0x18,0x65,0xF9,0xB7,0xB3,0x63,0xB2,0xE6,0x0F,0x76,0x5A,0xF4,0x3A,0x0A,0xB7,0x6C,0x11,0x1F,0x00,0xCC,0x31,0x16,0x5C,0x6F,0x51,0x2C,0xC4,0xD9,0xEE,0xF6,0xC4,0xF9,0x2D,0x81,0x6E,0xF1,0xCD,0x13,0x44,0x77,0x43,0x67,0xBD,0xB6,0x14,0x91,0xD9,0x32,0xB2,0xFF,0x96,0x46,0x26,0xC4,0x62,0x1E,0x6C,0xB4,0x3A,0xC5,0xBC,0xB8,0xEA,0x40,0x7B,0x72,0x7F,0xF8,0x82,0xDC,0x67,0x47,0xF2,0x38,0x66,0xC6,0x73,0xD5,0xA9,0x8F,0x48,0xE5,0x10,0x54,0x7B,0x43,0xFD,0xEE,0x9B,0x1C,0x12,0x55,0x15,0x20,0xF8,0x23,0x0F,0x95,0x85,0xCB,0x5F,0xF5,0x1B,0x57,0x4F,0x25,0x0B,0xCA,0xA1,0x6A,0x6D,0xF2,0x69,0xD8,0x8E,0x40,0xEC,0x64,0x60,0x93,0x43,0x3A,0x01,0x77,0xBC,0x4B,0x72,0x73,0x23,0xF5,0xD1,0x0C,0x70,0x1B,0x71,0xE3,0x95,0xF9,0x51,0x7D,0xAB,0x40,0x46,0xB3,0xEC,0x38,0x2A,0xFB,0x9C,0xB9,0xA2,0x69,0xE4,0x22,0xBD,0xB1,0x6B,0x08,0xA9,0xE0,0xE7,0x66,0x48,0xF1,0xB0,0x2D,0x6B,0x53,0x8B,0x62,0x54,0xD4,0xE8,0x48,0xDA,0xFB,0xE0,0x8C,0x0B,0x8A,0x9D,0xA4,0x46,0x88,0x5B,0x47,0xE5,0x2A,0xF6,0x84,0xB3,0xAE,0x31,0xF6,0xC5,0x3F,0x11,0x59,0x40,0x7C,0x66,0x74,0x8D,0xA3,0x1A,0x13,0x7E,0xD6,0x90,0xCD,0xC8,0x97,0xAF,0x33,0xBA,0xAD,0xF6,0xDE,0x64,0x41,0xD3,0xAE,0x08,0x00,0xF6,0x2F,0x73,0xD3,0x21,0x64,0x4E,0xC5,0x27,0xFA,0xB6,0x62,0x02,0xB9,0x37,0xD2,0x22,0x9D,0xE6,0x9F,0x08,0x47,0xFB,0x05,0x1E,0xB8,0x2C,0xE4,0xC5,0x92,0x91,0xAA,0x50,0xA3,0xE4,0x78,0x80,0xC5,0xB0,0x14,0x4F,0x90,0x11,0x4D,0x80,0xEB,0x20,0x25,0x3C,0x3F,0x03,0xF6,0xFC,0xFE,0xAE,0xCD,0x0F,0x48,0xF5,0x90,0xE2,0x9E,0xC1,0x6C,0xA3,0x33,0xEB,0xD9,0xA4,0xE9,0x33,0x0D,0xE2,0x5D,0x4A,0x48,0xC9,0xCE,0xF4,0xDF,0xE9,0xD2,0x8D,0xDB,0x3D,0x2E,0xE9,0x0C,0xBE,0x8D,0x36,0x4B,0xD3,0xA9,0xA7,0xC9,0xE5,0xB6,0xFB,0x83,0x37,0xD5,0x65,0x31,0x61,0x7F,0x30,0xDC,0x4B,0xB6,0x30,0xCD,0x44,0xE0,0x9B,0x07,0x4E,0x00,0x89,0x80,0xAC,0xC9,0xFB,0x86,0x4E,0x78,0xA2,0x48,0x17,0x34,0x67,0x94,0x11,0x60,0x67,0xFC,0x61,0x74,0xC1,0x6B,0x40,0x47,0xA1,0x22,0x75,0xCA,0x56,0x99,0x0B,0xBB,0x33,0x07,0xA2,0x88,0x78,0xAE,0xF6,0x1B,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0x59,0x40,0xBA,0x35,0x0A,0x34,0x21,0x3C,0x8D,0xDA,0x9B,0x9D,0x16,0xCB,0x22,0x63,0x27,0xA4,0x3A,0xD1,0x0E,0xCB,0x79,0x87,0x34,0x89,0xE9,0x8F,0x9B,0x0E,0xC8,0x05,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0xF4,0x03,0xFC,0xBE,0x12,0xEB,0xDA,0x57,0x28,0x28,0x26,0x43,0xCF,0xC4,0x71,0xBF,0x60,0x51,0x33,0xBF,0x3D,0xC1,0xB6,0xBB,0x18,0x39,0xCC,0xE0,0x8B,0x66,0x33,0xC2,0x82,0x79,0x3E,0xFC,0x73,0x7C,0xD2,0xD5,0xF9,0x7D,0x83,0xA6,0x2C,0x1B,0x0B,0x76,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0x2D,0x72,0x31,0x49,0xD9,0x9F,0xEB,0x32,0x72,0xDC,0xE0,0x59,0xF8,0xE2,0xAA,0xBB,0x94,0x48,0xE3,0x65,0x89,0x2B,0xB6,0xA4,0xCA,0x38,0x39,0x82,0x92,0x1D,0xED,0x9E,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0xE3,0xAB,0xE2,0x85,0x50,0x08,0xD1,0xA8,0x27,0x88,0x2D,0x92,0x65,0x5D,0x30,0xBF,0xA1,0x61,0x69,0xA1,0x32,0xAC,0xC0,0x68,0x55,0x5A,0x82,0x98,0x2C,0x2C,0x02,0x64,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0xAD,0xF6,0x5C,0x7E,0xC3,0x7B,0x8A,0x5C,0xC3,0xF6,0x40,0x28,0x0F,0x4E,0x30,0x0F,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0xFF,0x1D,0x50,0x0E,0xFE,0x67,0xF3,0x44,0x9C,0xDF,0xEE,0xC2,0x4A,0xFB,0xCA,0x04,0x96,0x16,0x10,0xF1,0x30,0x17,0x4E,0x7F,0x4C,0xF8,0x86,0x53,0x7C,0x73,0x15,0x0A,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0xF4,0xAD,0x23,0x55,0x42,0x96,0xED,0xC0,0x71,0x75,0x9B,0x1C,0x70,0x17,0x07,0x25,0x0A,0x83,0x42,0xEB,0x81,0xAB,0x4B,0x1B,0xE5,0x39,0xA0,0x9E,0x98,0xD7,0x33,0x67,0x3E,0xF0,0xFA,0xBB,0xB7,0xBD,0x71,0xD1,0x4D,0x11,0x52,0xC3,0x2B,0x9C,0xDA,0x43,0xA3,0x48,0xEB,0x27,0x04,0x0E,0x6E,0x0D,0xF6,0x42,0xA5,0xB7,0xB3,0xC5,0x78,0x45,0xD8,0x28,0xCE,0x52,0x22,0xC5,0x82,0x0F,0x1F,0xA9,0x0F,0xCE,0xD9,0xD2,0x1F,0xA5,0x8A,0xFE,0x93,0xBC,0x02,0x18,0x2F,0x7C,0x27,0x5C,0x67,0xC1,0xE0,0xF6,0xBD,0x94,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0x53,0xF1,0x82,0xF9,0xDF,0x59,0xF3,0x3C,0xA8,0xAF,0x18,0x68,0xFF,0xD8,0x1B,0x19,0x19,0xCF,0x42,0xEB,0xE2,0xC5,0x6B,0x22,0x90,0x4A,0x34,0xE3,0x36,0x8A,0x49,0xE1,0xEA,0x79,0xFA,0x1F,0x79,0x8A,0x3C,0xE3,0xC4,0x8C,0x46,0x49,0x56,0x7B,0x80,0x8F,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0xF9,0x85,0x6C,0xC3,0x6E,0x9A,0x3D,0x9C,0x3D,0xAC,0xD0,0x9C,0x11,0x8F,0x82,0x1C,0x45,0xC6,0xF3,0xE6,0xD6,0x12,0x6A,0xFC,0x3D,0x61,0x6C,0xED,0xBB,0x7A,0x08,0xB5,0x13,0x9D,0x43,0x91,0x75,0x69,0x20,0x4D,0xE2,0xBE,0xA7,0x30,0x93,0xF7,0xA7,0xC1,0x5A,0x6C,0x35,0x53,0x86,0x03,0x32,0x26,0x6B,0xD8,0xD8,0xA7,0xDC,0xE7,0xF3,0x42,0x8D,0x7E,0xE8,0x98,0x30,0xFF,0x6F,0xB2,0xBD,0x03,0x35,0x71,0xD3,0xF6,0x08,0x0F,0xBE,0x85,0x0C,0x45,0x9E,0x70,0xC6,0x84,0x15,0xA3,0xC4,0x2E,0x60,0xAD,0xC9,0xB9,0x99,0x95,0x4A,0xBD,0xD9,0x43,0xA5,0x56,0x28,0xE9,0xCF,0x96,0x8A,0x05,0x40,0xCF,0x34,0x64,0x71,0x69,0xCA,0x92,0x9F,0x1F,0x01,0x48,0xDB,0xFD,0x73,0x29,0x41,0x94,0x9A,0x92,0xEF,0x74,0x71,0xA5,0xE0,0xF9,0x7D,0x11,0xCF,0x6B,0x5A,0x81,0x74,0x77,0x1D,0x25,0xC1,0x18,0x9B,0xDE,0xF3,0x88,0x18,0x88,0x2B,0x3A,0xD7,0xD4,0xDA,0x57,0xF6,0xE0,0xE1,0xCC,0xD2,0x83,0x61,0xEA,0xDF,0xBE,0xC6,0xEE,0x82,0x29,0x31,0x03,0xC3,0xB7,0x44,0xD2,0x8A,0x00,0x1E,0x4F,0x40,0x74,0x56,0x72,0xCA,0x4F,0xAD,0x44,0x6C,0x20,0xD7,0xA3,0xA2,0xF4,0xDA,0x32,0x51,0xCE,0xAA,0x8D,0x7F,0xD1,0xD1,0xFB,0xC0,0xA3,0x3E,0xB9,0xB4,0x8E,0x54,0xDA,0xE9,0x7A,0xD6,0xBA,0xFD,0x54,0xB7,0x50,0x2D,0x02,0xA4,0xC9,0x8A,0x1E,0x82,0xB5,0x11,0x8E,0x38,0xAA,0xDE,0x2F,0x84,0x64,0x44,0x03,0xA6,0xF9,0x4C,0xD7,0x6A,0x8F,0x25,0x6F,0xD6,0x7B,0xF8,0x47,0x71,0x33,0x28,0x2A,0x25,0x01,0x1D,0xEA,0x8C,0xBA,0x62,0x65,0xE0,0x5B,0x5E,0xA8,0x6F,0x5F,0xEE,0xA9,0x09,0x6B,0xB2,0x35,0xBB,0x07,0x40,0x8A,0x99,0xB9,0xBB,0xDE,0xEB,0x7B,0x92,0x73,0xC5,0x7A,0x5E,0x71,0xA9,0x5A,0x3A,0xC1,0x76,0x74,0x4F,0x0C,0x37,0x9A,0x9C,0x66,0xDE,0x41,0x40,0xB3,0xBF,0x58,0x25,0x88,0x05,0x0B,0x3B,0x62,0x06,0x89,0x12,0x5E,0x2C,0x82,0x7E,0x18,0x93,0x60,0xAE,0x71,0x6A,0x79,0x1C,0x5F,0xB6,0x70,0x7C,0xEF,0x16,0x3E,0x6C,0x9F,0x88,0x0F,0x6C,0x39,0xE9,0xED,0xCB,0x01,0x3C,0x27,0x08,0x78,0xFA,0x60,0xB5,0xD4,0x14,0xAB,0x10,0xB0,0xE4,0xA2,0x8F,0x80,0x4F,0x6E,0xB7,0x45,0xCB,0x81,0x84,0x86,0x83,0xFE,0x15,0x8B,0x21,0x59,0xD7,0x83,0x2A,0x4F,0x68,0x5B,0x61,0xC1,0x49,0x55,0xA4,0xB3,0x03,0xD8,0x2C,0x7F,0x2F,0xDD,0xED,0x8E,0xD0,0xF2,0xBD,0x12,0x4D,0x1E,0x53,0x4B,0x1D,0x5F,0x08,0x25,0x9B,0x3D,0xA2,0xA1,0xEA,0x44,0x99,0x6D,0x71,0x3B,0x48,0x49,0xFD,0x2E,0x5A,0x71,0xEC,0xA0,0x86,0x13,0x26,0x02,0x0B,0x49,0xF8,0x10,0xD6,0x60,0xAA,0x6B,0x02,0xDF,0xE5,0xAA,0xBA,0x26,0xFA,0xCD,0x50,0xDE,0xE3,0x31,0x93,0x53,0x4E,0x0F,0x65,0x77,0xF9,0xBF,0x29,0x95,0x86,0xB9,0x7E,0x83,0x45,0xDB,0xF2,0x4A,0x05,0x3C,0x2D,0xDD,0x58,0x6A,0xEA,0xFE,0x53,0x77,0x7F,0x2F,0x05,0xF7,0x29,0x3C,0x17,0x69,0x36,0xB8,0xDB,0x33,0x13,0x8D,0x76,0xFD,0xA5,0xBC,0x65,0xAE,0xFD,0xC7,0xED,0x48,0xC9,0x4C,0x30,0x40,0xD6,0x38,0x5A,0xCE,0x1A,0x04,0x8F,0xF8,0xEE,0x44,0x60,0xAD,0x3A,0x94,0xA3,0x8C,0x26,0x63,0x5B,0xC1,0x18,0xC6,0x73,0x7F,0x12,0x20,0x04,0xB5,0x67,0x5A,0x29,0xB5,0xE9,0x8D,0x28,0x92,0x05,0xDA,0x67,0xA4,0x9F,0xB8,0xCC,0x35,0x0F,0x2B,0xF1,0xB9,0x50,0x46,0xEF,0xA0,0x7D,0xC6,0x42,0xEA,0x38,0x4E,0xE8,0xB4,0xE2,0xB1,0x4C,0x65,0x18,0xD7,0x18,0x73,0xD9,0x6D,0x28,0x24,0x6D,0xEB,0x4D,0xF7,0xBD,0x31,0xAC,0x8C,0x80,0xC6,0xF8,0x72,0x5B,0xAE,0xF0,0x16,0x88,0x25,0x9A,0xEF,0xB2,0xE5,0x8E,0xAD,0xD0,0xC2,0x8D,0x96,0x80,0xB6,0x00,0xD0,0x08,0x2C,0x8C,0xE1,0x0D,0xC3,0x57,0xC0,0x2B,0xF7,0xA5,0x5A,0x82,0xFF,0x69,0xAD,0x01,0xE6,0x42,0xCD,0x38,0x4D,0x4E,0xB6,0x6D,0xC6,0xA4,0x6A,0x53,0x5C,0x13,0x92,0x05,0x36,0x02,0xB3,0x98,0x8E,0x9E,0xBB,0x48,0x74,0xE3,0x2E,0x86,0x84,0xFF,0x80,0xB4,0xEE,0x94,0x3F,0xBB,0x37,0xD7,0xC3,0xA8,0x4B,0x5A,0x85,0x5A,0x6A,0xB7,0x4D,0x4B,0xB3,0x47,0x6F,0x6C,0x43,0xBA,0x12,0x38,0x61,0xA1,0x61,0x2C,0x7B,0x50,0xFA,0x3A,0x05,0x4C,0x16,0x0E,0x2F,0x88,0x6C,0xCF,0xAC,0x4F,0xB7,0xD9,0x0E,0xC7,0x55,0x72,0x9D,0xF5,0x64,0xC4,0xB8,0x9A,0x82,0x18,0xDA,0x51,0x2C,0x7F,0x39,0xC1,0x17,0xB9,0xF4,0x2F,0x98,0x3B,0x55,0x7B,0x69,0xCC,0x83,0xE3,0xDE,0x75,0x44,0xFD,0x55,0x06,0x73,0x47,0xC7,0xEE,0x47,0xA2,0x3B,0x35,0x17,0xF0,0xF3,0x0B,0xE8,0x01,0x97,0x77,0x67,0x28,0x14,0xA4,0x3F,0x96,0x74,0xA2,0xA4,0x35,0xE3,0x1F,0x69,0x41,0x5A,0x89,0x4F,0x19,0x06,0xDF,0xD7,0x57,0xC0,0x54,0x27,0x72,0x0F,0x36,0xE0,0xF9,0x57,0xC0,0x9A,0x56,0xFD,0x5C,0x19,0xC5,0x79,0x50,0x88,0xB8,0x70,0x57,0xDB,0x55,0x98,0xA8,0x2F,0xBB,0xB8,0xAF,0xF8,0xE5,0x33,0x0D,0x40,0xBE,0xBC,0x3C,0x7E,0xC8,0xFF,0x11,0x7C,0x12,0x39,0x76,0x12,0x9C,0x8D,0x9C,0x95,0x23,0x6A,0x1A,0xE9,0xAF,0xD7,0x9B,0xD1,0x8E,0xA1,0x32,0x2F,0x17,0x4D,0x84,0x9C,0xCC,0x8F,0xA9,0x14,0xEC,0x86,0xCF,0x1A,0xFD,0x1D,0x45,0x14,0x5D,0x9B,0x0C,0x63,0x3A,0xF2,0x84,0x44,0xAA,0x4D,0x69,0x76,0x15,0x32,0xD2,0xCB,0x6B,0x03,0x30,0x9A,0x6A,0x64,0x66,0x8C,0x06,0xEC,0x70,0xCC,0x33,0x92,0xAA,0x43,0x09,0x06,0xE2,0x52,0x48,0xE1,0x76,0x09,0x0F,0x44,0x7B,0x40,0x04,0x7B,0xD7,0xBD,0x8C,0xEC,0xBD,0x8E,0x16,0xBF,0x2F,0x40,0x48,0x72,0x78,0xA0,0x45,0x16,0x90,0x37,0xAA,0x7A,0xCA,0x8F,0x7A,0x6C,0xAA,0x68,0xB3,0xEB,0x63,0xE9,0x7F,0xD0,0xE7,0x3A,0x82,0xFF,0xEB,0x45,0x7F,0x75,0xDC,0xB5,0xF9,0x6A,0x27,0x8E,0x49,0x39,0x0A,0xAE,0x98,0x24,0xC4,0xEE,0xF5,0x80,0xBC,0xF5,0x30,0x4F,0x7D,0x5A,0x0C,0x79,0x0F,0x37,0x3D,0x9C,0x53,0xD6,0xEE,0x95,0xEA,0x85,0x54,0xE6,0x9A,0x2A,0xCF,0x80,0xDC,0x14,0x76,0x8D,0x9C,0x83,0x1F,0x40,0xAC,0x66,0x27,0x67,0x69,0xB6,0xBC,0x05,0x7E,0xE9,0xC6,0xCE,0xB2,0xD6,0xB1,0xAC,0x79,0x20,0x13,0x24,0xCE,0xC4,0xD1,0x02,0x6B,0x88,0xD4,0x0D,0xD9,0x41,0x9D,0x94,0x71,0xF2,0x06,0x15,0xDF,0x34,0xF1,0x4D,0xB3,0x02,0x84,0xAE,0x83,0x7D,0xDC,0xC8,0xC3,0x3E,0x53,0x01,0x5C,0x1D,0xB0,0xFE,0x84,0xA3,0x73,0xA9,0x6A,0x8A,0x13,0xD3,0xEF,0x8B,0xEA,0x90,0x78,0x87,0xB5,0xFF,0xCE,0x34,0xF9,0x78,0x7B,0xAD,0xB8,0x62,0xDE,0xB5,0xB5,0x6C,0xF9,0xB3,0x67,0x2E,0x83,0x9D,0x52,0xBE,0x44,0xD1,0x89,0xD6,0x2B,0xE4,0x58,0x67,0x9D,0xAC,0xC4,0x25,0xEB,0x50,0x20,0x1F,0x2E,0xF5,0xE7,0x38,0x05,0xEF,0x70,0x9C,0xF3,0x0C,0x4A,0xB4,0x47,0xD4,0x1C,0x89,0x9C,0xD3,0x09,0x6A,0x97,0xCC,0xF3,0xC6,0x85,0x4A,0xB3,0x0F,0xAF,0xF0,0x0A,0xC0,0x40,0xE0,0x22,0x19,0xEB,0x81,0x63,0x3E,0x5D,0x36,0x28,0x63,0xCD,0x48,0xBB,0xB5,0x3F,0x52,0xD2,0xAB,0x27,0x01,0xC4,0x75,0x67,0xF5,0xC2,0x89,0x43,0x48,0xCF,0x4B,0x8C,0xB2,0xED,0x11,0x87,0x5F,0x16,0xFF,0xC7,0xDC,0x77,0x4A,0xFE,0xEA,0xEE,0xC4,0x9D,0x9F,0xB4,0xA2,0x3A,0x01,0xD3,0x20,0xEB,0x95,0x84,0xAD,0x4C,0xCC,0xD9,0x12,0xA1,0x4B,0xC7,0xC3,0x60,0x26,0xBA,0xDB,0x26,0x9F,0xF1,0x3A,0x66,0xE1,0x8C,0x06,0xD1,0x47,0x0B,0x77,0x84,0xAA,0xEE,0x8A,0x3F,0xCB,0x51,0x8E,0x15,0x71,0xB7,0x45,0x79,0x8C,0x34,0xC3,0xB2,0x56,0xE5,0xC4,0x24,0xAF,0x05,0x3F,0x56,0x86,0x87,0xAE,0xA2,0x96,0xA4,0x78,0xB2,0x29,0x34,0xA5,0xE3,0x02,0x52,0x5A,0xD6,0x5F,0x8F,0xE7,0x55,0xE8,0x89,0xCA,0x1F,0xDD,0x29,0x81,0x80,0xBA,0xA0,0x0C,0x28,0xFA,0x85,0x8A,0xAC,0xA3,0x8F,0x48,0xB5,0xC2,0xB8,0xD1,0x87,0x0F,0x89,0x5B,0xA1,0x94,0x2C,0xE4,0x05,0xC6,0x60,0x94,0x57,0xC2,0x69,0x53,0x01,0xA9,0xEF,0xC4,0x3D,0x92,0x21,0x0D,0x78,0x2C,0xFE,0x58,0x65,0xBB,0xB7,0x0A,0x39,0x6A,0x20,0xC4,0xAE,0x4B,0xF0,0x57,0xEE,0x0A,0x59,0xA0,0x71,0xD1,0xBF,0xB9,0x39,0xC7,0x12,0x3C,0xAA,0xCA,0xFB,0xCE,0x0F,0x43,0x48,0xDD,0xA7,0xB5,0x0D,0x25,0xF3,0x88,0xA7,0xD4,0xDA,0xDC,0x6B,0xBE,0x18,0x36,0x09,0x82,0xE8,0x99,0x74,0xD1,0x83,0xFF,0x94,0x2B,0xA5,0xD9,0xC0,0x8E,0xBF,0x0C,0xF3,0xAF,0xCE,0x06,0x4B,0x86,0x4D,0x2E,0xB8,0xAA,0x0C,0xA5,0x0C,0xC3,0x38,0xA8,0x60,0x0E,0xD9,0x58,0x71,0x10,0x00,0x37,0x99,0x81,0x9D,0xB8,0x4F,0xEF,0x74,0xAC,0x37,0xBC,0x57,0x53,0x4E,0xAF,0xAE,0x87,0x78,0xFB,0x82,0x18,0x60,0x78,0x99,0x98,0x16,0x01,0x41,0x42,0x5E,0xDE,0xDF,0xA9,0xBD,0x7B,0x93,0xDC,0xC4,0xB8,0x9F,0x4E,0xD5,0x8A,0x20,0x15,0x49,0x0C,0xCF,0x0A,0x2E,0x6E,0xDE,0xCB,0x67,0x59,0x1B,0x1B,0xB8,0x24,0xB0,0xB0,0xE4,0x13,0x1A,0x8E,0x4E,0x39,0xF4,0x52,0x69,0xE3,0xDC,0x95,0xC0,0xC8,0xC0,0xB3,0x96,0xE2,0x72,0x99,0xA1,0xE9,0xFD,0xC4,0x9E,0xFA,0x43,0xD3,0x62,0x17,0x6B,0x54,0x35,0x7D,0xB1,0xBF,0xA9,0xB3,0x03,0x18,0x36,0x73,0xE2,0xC7,0xC2,0xD9,0xB2,0x35,0x6B,0x7D,0x9F,0x55,0x38,0xF9,0xA1,0x61,0xA0,0x99,0x34,0x02,0x39,0x29,0x21,0x97,0xDF,0x87,0xDA,0xCB,0x87,0x75,0x4F,0xFA,0x57,0x54,0x69,0x3A,0x97,0x24,0xFE,0xBE,0x2F,0xB4,0x7B,0x12,0xC3,0xA7,0x0A,0xE9,0x39,0x9A,0x2C,0x08,0x6A,0x05,0x66,0x0F,0xD3,0x38,0xA5,0xD9,0xC8,0x83,0x2A,0x6B,0xC5,0x44,0xE3,0x7B,0x01,0xAB,0x32,0x96,0x8C,0x23,0x2A,0x14,0x7C,0x3C,0xBB,0x46,0x51,0x04,0x12,0xB6,0x1B,0xB6,0xE3,0xF0,0xAD,0x23,0xEB,0x67,0xF8,0xB9,0x95,0xC1,0x98,0x55,0xE3,0x75,0xA7,0x1A,0x7C,0x3A,0xB8,0x9D,0xA7,0x12,0xDF,0xFC,0xA0,0x1A,0xBB,0x5C,0xC8,0x69,0x95,0x5A,0x67,0xE3,0x5A,0xFC,0x14,0x3F,0x17,0x6E,0x54,0x0A,0x80,0xA9,0x51,0xE8,0x41,0x20,0xFD,0x58,0x12,0x31,0x45,0xD3,0x50,0xF4,0x46,0x67,0x75,0x4B,0x21,0x3C,0x57,0x6D,0xDD,0x7C,0xAC,0xE0,0xA7,0x86,0xC9,0xF8,0xA7,0x09,0xB5,0x45,0x1C,0xE9,0xD5,0xB5,0xC0,0xC5,0x67,0x2F,0xE9,0x34,0xA1,0x0D,0xCD,0xB4,0xE5,0x3D,0xB2,0x41,0x9C,0x72,0x4C,0x88,0x22,0x0F,0x48,0xE6,0x78,0x3C,0xCD,0xEF,0x06,0x70,0x10,0xBF,0x66,0x14,0xE0,0xA9,0x2F,0xBA,0xF5,0x96,0x47,0xB0,0x79,0x59,0x98,0x0A,0x9B,0x16,0xD3,0xB1,0x11,0xB1,0xBD,0xDA,0x81,0xDB,0x4F,0x56,0xBC,0x68,0x15,0xA8,0xBA,0x10,0x0B,0xD1,0xBE,0x76,0x2C,0x4D,0xA8,0x4F,0x3F,0xC8,0x9E,0xA5,0xAE,0x88,0x6B,0x7D,0x11,0xFE,0x89,0xFC,0x17,0x0F,0x0C,0x32,0x51,0xF4,0xDB,0x3E,0x94,0x55,0xC6,0xDA,0xED,0xD5,0x0F,0x87,0xB9,0x7F,0x33,0xC3,0xD1,0x0B,0x83,0x63,0x32,0x72,0x36,0xED,0xA1,0x2A,0xF8,0x6E,0x88,0x42,0xC4,0x94,0xBB,0x00,0x64,0xC1,0x72,0x25,0x36,0x53,0xBB,0x71,0x02,0x68,0x78,0xC1,0x7A,0x5F,0x70,0xD0,0x8D,0x15,0x94,0xC0,0x90,0xA7,0x81,0x4F,0x87,0x30,0x49,0x44,0xC8,0x96,0xED,0x9C,0x6E,0xD4,0x9D,0x2A,0x81,0x73,0xD3,0x89,0x8C,0x32,0x3C,0xAD,0xAC,0x0B,0x99,0x7A,0xD8,0x25,0x94,0x77,0xB0,0x21,0x24,0x4E,0xE6,0x47,0x6C,0xB1,0x6B,0x87,0xF9,0x76,0x95,0x65,0x2D,0x05,0x03,0x55,0x24,0x1F,0x6B,0xAF,0xC2,0x6B,0x17,0xAC,0x5F,0x0C,0x74,0x06,0xAB,0xDD,0x04,0x30,0xC8,0xD6,0x4F,0xD1,0xE8,0xA2,0xF4,0xB1,0xE0,0x47,0x19,0x00,0x13,0x83,0x87,0xEB,0xC7,0xD9,0xAB,0x6C,0x57,0xDA,0x00,0xD4,0x9D,0x4D,0x6D,0x66,0xC7,0x51,0xB5,0xCF,0x1F,0x91,0x04,0x16,0x30,0xCC,0xCE,0x7B,0xD2,0x69,0x77,0xED,0xCC,0x07,0x6D,0xEB,0x63,0x2B,0x99,0x16,0x14,0x1E,0x0D,0x1D,0xDA,0x2C,0x98,0x16,0xDF,0xDC,0xD4,0x92,0xD3,0xCC,0x6A,0x35,0x80,0xF1,0xCC,0x0F,0xF1,0xF7,0x43,0xE6,0x82,0xC6,0xF5,0x6A,0x2D,0x16,0xCC,0xFB,0x28,0x23,0xE0,0x27,0xB5,0xC1,0x83,0x88,0x17,0xB2,0x9E,0x24,0xBD,0xA6,0x17,0x3B,0xBD,0xF8,0xFB,0x96,0xC4,0x77,0x93,0x2E,0x51,0x45,0xB1,0x45,0x97,0x3A,0x08,0x78,0xA0,0x34,0x6B,0x4B,0x5C,0xDF,0xFE,0x40,0x04,0x8A,0xE9,0xFB,0xCC,0x6C,0xD6,0x56,0x28,0x89,0x7F,0xDE,0x2A,0xC3,0xD9,0x92,0x8F,0x22,0x03,0x1B,0xEA,0x22,0xAB,0x99,0x18,0x5B,0x47,0xC3,0x06,0x02,0xBC,0xBB,0x42,0xB4,0x2C,0x05,0x61,0x97,0x86,0x9B,0x77,0x91,0x5B,0x48,0xAC,0x68,0x23,0x01,0x62,0x7F,0xA5,0x7F,0xF0,0x7B,0x6F,0x04,0x37,0x91,0x13,0xF4,0xEB,0x3C,0x2E,0x2C,0x9A,0xE6,0x1F,0xB1,0x5F,0xAF,0xD4,0x8A,0xDB,0x77,0xCC,0x0A,0xA7,0x7C,0xC4,0x46,0x02,0xA5,0x8F,0x81,0xEF,0x92,0x39,0xB0,0x8C,0xEA,0xFA,0x4C,0x77,0x30,0x21,0xE8,0x6D,0xA0,0x4C,0x0A,0x65,0xFA,0x20,0xD1,0x7F,0xCE,0x69,0x11,0x1F,0x63,0xFB,0x70,0xCB,0x42,0xE1,0xB5,0x09,0xB2,0x02,0x83,0x67,0xE8,0x60,0x20,0x34,0x7A,0x59,0xC0,0x7A,0x7A,0xC1,0x8D,0x83,0x0E,0x90,0x3A,0x72,0xAF,0x6C,0x9F,0xA5,0x95,0x1B,0x1D,0x2D,0x98,0x52,0xDF,0xCF,0x55,0x2A,0xAD,0x13,0xD2,0x38,0xA5,0x66,0xBC,0x69,0xA0,0xA3,0x37,0x7D,0x0D,0x70,0x63,0x17,0x49,0x43,0xA1,0x0D,0xDA,0xAE,0xD1,0x02,0xFC,0x0F,0x6E,0x7F,0x26,0xD8,0x4C,0x16,0xAB,0xB8,0x6A,0x64,0x03,0x69,0xF4,0x32,0x69,0xCD,0x17,0x85,0xF9,0xCE,0xD2,0xBE,0xAE,0x9C,0x59,0xD8,0x50,0xF1,0x93,0x1C,0x06,0xC6,0x32,0x61,0xC2,0x54,0x85,0x88,0xF3,0x77,0xFD,0xA3,0x8D,0x82,0x94,0x63,0xB4,0xCA,0x4C,0x47,0xE5,0xB1,0x02,0xA4,0x53,0xBB,0xDF,0x43,0xE7,0x72,0xD7,0xE1,0xD0,0x18,0x06,0xCE,0x63,0x63,0x8A,0x96,0xAF,0x1F,0xEA,0xCD,0x9B,0x74,0x21,0xEA,0x52,0x7A,0xDE,0xBA,0x98,0xA7,0xAE,0x01,0x9A,0xD5,0x94,0xF7,0x07,0x6F,0x46,0x49,0xE8,0x08,0xEB,0xA7,0x4A,0x6D,0xF0,0xC6,0xFD,0x9E,0x64,0xFB,0xDB,0x47,0x0A,0x22,0xB5,0x93,0xF3,0x5C,0xA4,0xF7,0xEE,0x5E,0x8C,0xBD,0x15,0x06,0x65,0xDA,0xBE,0xF5,0xA1,0x70,0x18,0x1B,0x36,0x91,0x34,0x65,0x7B,0xE2,0x20,0xA9,0xA2,0x4B,0x9E,0xBC,0x7F,0xAE,0x5C,0xCE,0x58,0xC6,0x5F,0x0B,0x30,0x73,0xB6,0xD4,0x92,0xD9,0x85,0xFE,0x64,0x53,0xD4,0x03,0xAF,0x6B,0x5E,0x46,0x69,0x5A,0xEC,0x65,0x73,0xCD,0x98,0xE1,0x11,0x9C,0x24,0xE1,0xCD,0x81,0x7D,0x91,0xF9,0xD3,0x86,0x9E,0xA7,0x38,0x00,0xA0,0x98,0x21,0xD7,0x4A,0x1D,0x86,0xF4,0x4E,0x96,0x34,0x8E,0x9F,0x25,0x3D,0x95,0xA3,0xD8,0xB7,0x7A,0xFD,0xB0,0xA5,0xC8,0x31,0x73,0xA1,0x91,0x33,0x34,0x88,0xAA,0xFB,0xB8,0x56,0x2A,0xE3,0xD6,0xA7,0x9C,0x98,0x4B,0x4B,0xDC,0x6D,0xC5,0x29,0xA4,0xC0,0xC8,0x11,0xCD,0x1E,0x19,0x6B,0x9E,0x82,0x09,0x90,0x48,0xAF,0xDE,0x08,0xBD,0xBD,0xC0,0x5F,0x9B,0xB2,0x22,0x1A,0xBD,0xD7,0x0F,0x9D,0x1C,0x34,0xFA,0xA2,0xFC,0x96,0xE0,0x47,0xA7,0x1A,0xC1,0x29,0xBA,0x3D,0xCC,0x3B,0x5F,0x84,0xCF,0x24,0x27,0x1C,0x39,0x3D,0xB3,0x99,0xD1,0x06,0x31,0x7B,0x55,0xB8,0x1B,0x46,0x35,0x9B,0x77,0x21,0xEC,0x8F,0x31,0x9C,0x8F,0xA8,0x97,0xE9,0x08,0xC3,0x86,0xB4,0xF0,0x98,0x2C,0xF1,0xEF,0x96,0x52,0x3A,0xC5,0x9C,0x91,0x75,0xD4,0x5F,0xC1,0x78,0x79,0x1A,0x7A,0xC8,0x9A,0x10,0x40,0x7A,0xFE,0xAF,0x28,0x63,0x5E,0xF6,0x10,0x42,0xC6,0xC5,0x2D,0x79,0x8C,0xB2,0x54,0x2E,0xFE,0x25,0x7F,0x12,0x69,0x47,0xD9,0x71,0x97,0xF5,0xA9,0xC8,0x0C,0x9A,0x28,0x1F,0xDE,0xFB,0xD9,0xDC,0x79,0xD8,0x6E,0x70,0xFD,0x74,0x20,0xD5,0xC9,0x51,0xCF,0xC3,0x2D,0x57,0xA9,0xEE,0x65,0xAA,0xC3,0x17,0xD6,0x21,0xBA,0xFA,0x43,0x53,0xD2,0x84,0x86,0x0C,0xD5,0x51,0x48,0x64,0x40,0x76,0x47,0x1D,0xD5,0xEF,0x24,0x71,0x85,0xFC,0xF7,0xCB,0xCA,0xE5,0x3E,0x56,0x39,0x22,0x50,0x4F,0xAF,0x5D,0x3A,0xE2,0xE4,0x09,0x3B,0x68,0xCC,0xFE,0xD5,0x0C,0x9D,0xBB,0xD2,0x16,0xA1,0xA5,0x82,0x8D,0x7B,0xAC,0xEF,0x7A,0xE2,0x88,0xB6,0x19,0x8F,0x24,0x1E,0x53,0x7A,0x8C,0xE9,0xD3,0x62,0xC8,0x9E,0xD1,0x35,0x60,0x8E,0xC3,0x23,0xAB,0x70,0x83,0x38,0xFC,0xF4,0x6F,0xFF,0x2E,0x61,0xDF,0x07,0xA8,0xA4,0xBE,0xD3,0xD7,0x97,0x3E,0x3D,0xC9,0xAD,0xE6,0xCB,0x47,0x09,0x34,0xC7,0x1F,0xD9,0x7C,0xBC,0xE5,0xB0,0xE2,0x4D,0x9E,0x2A,0xFA,0xFF,0x40,0x30,0xE5,0xFE,0xFF,0x55,0x38,0x26,0xC5,0x0E,0x16,0xBD,0x53,0xC5,0x24,0xA7,0xE0,0x5A,0x89,0xAF,0x3B,0x07,0xA2,0xF7,0xCD,0x42,0x21,0x8C,0x93,0x34,0xCF,0xF3,0x65,0x7A,0x33,0x1A,0x8B,0xE4,0x57,0x54,0x9D,0x1E,0xCC,0x38,0xBE,0xAC,0xF2,0x59,0x4E,0x4A,0x05,0x9C,0x64,0xDC,0x6E,0x87,0x4A,0x93,0x94,0xE6,0x04,0x64,0xBD,0xEC,0xA8,0xC5,0xCA,0x8A,0xBE,0x34,0xF4,0x0B,0xC1,0x19,0x39,0x59,0xD7,0xBD,0x4B,0xB2,0xA3,0xE7,0xB7,0x0E,0x03,0xDC,0x02,0x03,0x87,0x5D,0xC1,0xB7,0x8F,0xD9,0x1D,0xFE,0xA1,0xDA,0x1D,0x9C,0x88,0x60,0x14,0xBA,0xCD,0xA7,0x38,0xFB,0x36,0x45,0xE2,0xAB,0x47,0x17,0x41,0x2C,0x3E,0x89,0x2C,0xA8,0x79,0xB2,0x91,0x17,0xEF,0x63,0x4D,0xE8,0x78,0xB5,0xEC,0xFE,0x32,0xCA,0xCC,0xE3,0xD3,0x7F,0xD7,0x93,0x22,0xD2,0x6C,0xAD,0xD7,0xC2,0xF6,0x2E,0x33,0x7F,0x4A,0x7C,0x99,0xE5,0xAB,0x50,0x58,0x4D,0x4B,0x38,0x00,0x51,0xF0,0x9A,0x39,0x7E,0xB6,0xFE,0x86,0xEC,0x61,0x22,0x30,0x78,0xE3,0x86,0xE0,0xE7,0xA4,0x75,0x5E,0xF3,0x09,0x5C,0xC5,0x5E,0x57,0xE0,0x08,0xDA,0x3A,0x50,0x10,0xE3,0xEF,0x63,0xCF,0x14,0x45,0xFF,0x94,0xD4,0x08,0x0E,0xD2,0xA7,0xE3,0x49,0x5B,0x99,0xFC,0x5C,0x5B,0x5F,0x5F,0xC1,0x84,0x2C,0x4E,0x42,0xF5,0x62,0x3F,0xEC,0x01,0x6C,0x65,0x38,0x1A,0xD5,0xD4,0x58,0xA4,0xC5,0xEA,0xF2,0xB8,0xF3,0xBE,0xD6,0xA2,0x27,0x39,0x78,0x7B,0xB3,0xF6,0x49,0x28,0x3C,0x0C,0xB4,0x1A,0x10,0x14,0x78,0xD4,0xB1,0x71,0x5E,0xFF,0x6D,0x12,0x88,0xEA,0xFE,0xDE,0xF4,0xD4,0xD2,0xC2,0x51,0x23,0xD2,0x33,0x5B,0xC4,0x35,0x8A,0xA1,0x6E,0x39,0x8C,0x31,0x16,0x76,0x4A,0x1B,0xCB,0x91,0x44,0xFD,0x64,0xBB,0xA6,0xCB,0x0A,0x56,0xEB,0x55,0x8D,0xEA,0x94,0x91,0xF7,0x9D,0xE6,0x9F,0x13,0xC1,0xB8,0x1E,0xBC,0x1E,0x8E,0x2B,0x3B,0x87,0x9A,0xD8,0x32,0xF8,0xC4,0xAD,0x69,0x08,0xF9,0x10,0xD3,0x9C,0x89,0x03,0xA8,0x96,0xFF,0x2D,0x85,0x81,0xF4,0x65,0x2F,0x72,0x60,0x63,0x54,0x5F,0x97,0xB6,0x46,0xB5,0xB7,0x7C,0xE0,0x16,0x61,0x36,0x2F,0x41,0x4B,0x81,0xFE,0x24,0x7B,0xAB,0x09,0x34,0xCD,0xA0,0x40,0x0E,0xB1,0xB1,0x05,0xA2,0x88,0x14,0x22,0xE3,0xCC,0x45,0x62,0xD2,0x34,0xC5,0x9F,0xEB,0x36,0xF4,0x26,0x6C,0xBF,0x9E,0xC1,0x72,0xF8,0x6A,0x23,0xA7,0x87,0xCF,0xD2,0x0A,0x99,0x37,0xE5,0x0D,0x68,0x47,0xAC,0x4D,0x52,0x47,0x00,0x53,0x15,0x68,0x43,0x12,0x9F,0x9B,0xF8,0xD9,0xF9,0x5F,0x78,0xAA,0xB5,0x41,0xB9,0x84,0x0A,0x3A,0xC8,0x2A,0x6F,0xFF,0x0B,0xF0,0xEE,0xB4,0xE8,0xE4,0x42,0xCB,0xBB,0xDB,0x46,0x31,0xD0,0x3A,0xAA,0x13,0xB9,0x9D,0x98,0x85,0xE5,0x8B,0x6C,0xA3,0xB6,0xD1,0x97,0x6D,0x81,0x17,0xF0,0x63,0x65,0x81,0x40,0x25,0x31,0xCC,0xEF,0x71,0x56,0x81,0xA6,0x81,0xCA,0x43,0xBB,0xDC,0x79,0xAE,0x61,0x0E,0x99,0x14,0xC2,0x8F,0xD8,0x6E,0x54,0xC0,0x71,0xCF,0x98,0x53,0x0E,0x0B,0x64,0x87,0x6E,0x88,0xF8,0xA1,0xC0,0xB6,0x30,0x58,0x35,0xEC,0x60,0x04,0x01,0xC8,0x73,0x24,0xB4,0xB0,0x46,0xAD,0xC7,0x4B,0xFB,0xEC,0xC3,0x0D,0x86,0x44,0x32,0x07,0xD1,0xC9,0x94,0xA7,0xE4,0x4E,0xD4,0xD7,0x14,0xFC,0x9F,0x7B,0xD1,0x3D,0x94,0x56,0xC2,0x7C,0xED,0x62,0xFD,0x91,0x87,0x08,0xA2,0x6B,0x44,0xE5,0x8C,0x28,0xAD,0xF7,0x45,0x15,0xD3,0x76,0xAA,0x29,0x27,0x0D,0xC2,0x72,0x93,0xF0,0x5A,0xB8,0xBE,0xBB,0xD4,0x0E,0xA7,0x11,0x13,0xFC,0xAA,0x47,0xD2,0x4D,0x05,0x93,0x1B,0xBD,0x3A,0x01,0x0E,0x53,0x31,0x33,0x3C,0x23,0x83,0x8A,0x65,0x1E,0x82,0x66,0x3C,0x0F,0x65,0x67,0x20,0xAE,0x3A,0x5A,0xF8,0x4D,0x8F,0xA9,0x7C,0xA0,0x26,0xBD,0x1F,0xE3,0x38,0x4F,0xBE,0x3D,0xCF,0x9F,0x50,0x42,0x95,0x1C,0x76,0x1A,0x9A,0x41,0x08,0xD9,0xBA,0xB9,0xD6,0xF6,0x65,0x41,0x22,0xD4,0xDF,0xBD,0x4E,0xFD,0x58,0xD5,0x1B,0x07,0x14,0x31,0xE5,0xA8,0xBF,0x88,0x22,0xCF,0x70,0x5B,0x72,0x9D,0xC2,0x6D,0x87,0x0F,0x6F,0x1B,0x6C,0xEF,0xD7,0xD1,0xC0,0xEE,0x48,0xB4,0xA2,0xCA,0xC9,0x7B,0xB8,0xE8,0xA2,0x5D,0x39,0x35,0x89,0xFA,0xEB,0x78,0xCE,0x51,0xB1,0xBA,0xE6,0xA4);

           my $dec='';
           my $ki=0;
           for (my $i=0; $i<length($data); $i++)
           {
              $dec.=chr ( ord (substr($data,$i,1)) ^ $key[$ki] );
              $ki++;
              if ($ki>($#key)||($i%0x10000)==0xFFFF) {$ki=0;}
           }

        print   STDERR " -> '$newfilename' - Avast_AVG File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $dec);
    }

# extract_trend routine is based on the code by Optiv
sub extract_trend
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename_out = sprintf($file.'.%08d_TREND1.out',$ofs);
        my $newfilename_met = sprintf($file.'.%08d_TREND1.met',$ofs);

        $data = dexor(substr($data,$ofs,$size),0xFF);

        my $dataoffset = unpack("I",substr($data,4,4));
        my $numoftags  = unpack("S",substr($data,8,2));

        print   STDERR " -> '$newfilename_out' - Trend File #1\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        print   STDERR " -> '$newfilename_met' - Trend File #1 MetaData\n";

        my $meta = '';
        $meta.="    Data Offset = $dataoffset\n";
        $meta.="    Num of tags = $numoftags\n";
        $ofs=10;
        my $enc=-1;
        my $basekey=-1;
        for (my $i=0; $i<$numoftags; $i++)
        {
            my $cod  = unpack("C",substr($data,$ofs+0,1));
            my $len  = unpack("S",substr($data,$ofs+1,2));
            my $tag  =            substr($data,$ofs+3,$len);
            my $tagu = $tag;
            $tagu =~ s/(.)\x00/$1/g;
            $tagu =~ s/\x00+$//g;
            $meta.=sprintf("      ofs=%08d, code=%3d, len=%d\n",$ofs, $cod,$len);
            if (1 == $cod)
            {
                $meta.="        Original Path = '$tagu'\n";
            }
            elsif (2 == $cod)
            {
                $meta.="        Original File Name = '$tagu'\n";
            }
            elsif (3 == $cod)
            {
                $meta.="        Platform = '".$tag."'\n";
            }
            elsif (4 == $cod)
            {
                my $attr = unpack("I32",$tag);
                my $attr_str='';
                my $attrtmp=$attr;
                if ($attr & 0x2000) { $attr_str.= 'I'; $attrtmp-=0x2000;}
                if ($attr & 0x0020) { $attr_str.= 'A'; $attrtmp-=0x0020;}
                if ($attr & 0x0004) { $attr_str.= 'S'; $attrtmp-=0x0004;}
                if ($attr & 0x0002) { $attr_str.= 'H'; $attrtmp-=0x0002;}
                if ($attr & 0x0001) { $attr_str.= 'R'; $attrtmp-=0x0001;}
                if ($attrtmp!=0 ) { $attr_str.= sprintf(" +0x%02X",$attrtmp);}
                $meta.=sprintf("        Attributes = 0x%02lX ('$attr_str')\n",$attr);
            }
            elsif (5 == $cod)
            {
                $meta.=sprintf("        Unknown = %08lX\n",unpack("I32",$tag));
            }
            elsif (6 == $cod)
            {
                $basekey = unpack("I32",$tag);
                $meta.=sprintf("        Base Key = %08lX\n",$basekey);
            }
            elsif (7 == $cod)
            {
                $enc=unpack("I32",$tag);
                my $enc_str = 'Unknown';
                   if (1==$enc) { $enc_str= 'xor FF'; }
                elsif (2==$enc) { $enc_str= 'CRC'; }

                $meta.="        Encryption = $enc ($enc_str)\n";
            }
            $ofs = $ofs+3+$len;
        }
        print   STDERR "$meta\n";
        writefile ($newfilename_met, $meta);
        writefile ($newfilename_out, $data);

        $newfilename_out = sprintf($file.'.%08d_TREND2.out',$ofs);
        print   STDERR " -> '$newfilename_out' - Trend File #2\n -> ofs='$dataoffset' (".sprintf("%08lX",$ofs).")\n";

        if (1 == $enc)
        {
           writefile ($newfilename_out, substr($data,$dataoffset,length($data)-$dataoffset));
        }
        elsif (2 == $enc)
        {
           my $bytesleft = length($data) - $dataoffset;
           my $unaligned = $dataoffset % 4;
           my $newdata='';
           while ($bytesleft>0)
           {
              my $crcbuf = pack("I",crc32(pack("I",$basekey+$dataoffset-$unaligned)));
              for (my $j=$unaligned;$j<4;$j++)
                 {
                  last if (0==$bytesleft);
                  $newdata.=chr (ord(substr($data,$dataoffset,1))^ord(substr($crcbuf,$j,1)) );
                  $dataoffset += 1;
                  $bytesleft -= 1;
                 }
              $unaligned = 0;
           }
           writefile ($newfilename_out, substr($newdata,10,length($newdata)),length($newdata));
        }
    }

sub extract_esafe
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_ESafe.out',$ofs);

        my $newdata = decode_base64($data);

        print   STDERR " -> '$newfilename' - ESafe File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);
    }

sub extract_amiti
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_Amiti.out',$ofs);

        my $x = "AA79e10d15l6o2t8";

        my $key='';
        for (my $k=0; $k<16; $k++)
        {
          $key.=chr(ord(substr($x,$k,1)) ^ 0xA4);
        }

        my $rc4 = Crypt::RC4->new( $key );
        my $newdata = $rc4->RC4( $data );


        print   STDERR " -> '$newfilename' - Amiti File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);
    }


sub extract_eset
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_ESET.out',$ofs);

        my $newdata = '';

        for (my $i=0; $i<length($data); $i++)
            {
                $newdata .= chr(((ord(substr($data,$i,1))-84)%256)^0xa5);
            }

        print   STDERR " -> '$newfilename' - Eset File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);
    }

sub extract_fprot
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_F-Prot.out',$ofs);

        my $o2d = unpack("I",substr($data,0x4,4))+0xDC;
        $data = substr($data,$o2d,length($data)-$o2d);
        my $newdata = '';
        my @flt=(0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0xF2,0xAC,0xB4,0x68,0xC0,0x86,0xB6,0xE3,0xF6,0x45,0xC8,0x5D,0xCF,0x5E,0xA2,0xD6,0xAE,0x1A,0x13,0x46,0x5F,0x3E,0x99,0x96,0x7D,0x57,0x7A,0xF4,0xDD,0x34,0xAF,0x2A,0x78,0x92,0x9B,0x35,0x94,0x98,0xA3,0x76,0xF1,0x44,0xE7,0xB0,0xBE,0x3B,0x0E,0x14,0xC5,0x79,0x85,0xCD,0xC6,0xF5,0xEF,0x8E,0x15,0xD7,0x77,0x17,0x89,0xF8,0xCA,0x82,0x5A,0x32,0xBF,0x3F,0xFF,0x2F,0x6E,0x88,0xA6,0x12,0x7B,0xEC,0x73,0xE5,0x58,0x66,0x52,0x63,0x5C,0xAB,0xEB,0x49,0xD3,0x0F,0x3C,0x3A,0x36,0xA1,0x18,0xED,0x27,0x6B,0xB8,0x3D,0xC4,0x6D,0x4B,0x2B,0x91,0xDB,0x4D,0x8B,0xA5,0x83,0x22,0x1B,0xDE,0x87,0xFC,0xFD,0xBB,0x8D,0xE6,0x7F,0x6A,0x26,0x7C,0xEE,0xB5,0x9F,0xE4,0xE9,0x69,0x74,0xC7,0x56,0xF9,0x39,0x72,0x23,0xD8,0x43,0x25,0x1F,0x4E,0x61,0x21,0x33,0xAD,0x31,0x64,0xCC,0x51,0x9E,0xFA,0xF3,0xD4,0xBA,0xD5,0x6F,0xF0,0x7E,0x1C,0x29,0xFB,0x1D,0x42,0xE8,0x4A,0x47,0xAA,0x90,0x59,0x67,0x65,0xB2,0x8A,0x50,0xDF,0x9D,0x53,0xA8,0x19,0x71,0x54,0x93,0xA0,0x2D,0x24,0x75,0xE2,0xFE,0xBD,0x97,0xA9,0x95,0xF7,0x9A,0xD9,0x60,0x10,0x2C,0x40,0x84,0x2E,0xC3,0x41,0xC1,0x6C,0x38,0x8C,0xB9,0x80,0xDC,0x1E,0xCE,0xC2,0x8F,0xA4,0xC9,0xE1,0x9C,0x30,0xD2,0x81,0x28,0xB7,0xA7,0xDA,0x70,0x5B,0xCB,0xD1,0xB1,0x4F,0x20,0x11,0x37,0x48,0xB3,0xE0,0x16,0x62,0xEA,0xBC,0x55,0x4C,0xD0);

        for (my $i=0; $i<length($data); $i++)
            {
                $newdata .= chr($flt[ord(substr($data,$i,1))]);
            }

        print   STDERR " -> '$newfilename' - F-Prot File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);
    }

sub extract_gdata
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $hdr_len = unpack("I",substr($data,0x4,4));
        if ($hdr_len<$size)
        {
           # printf STDERR ("hdr_len = %08lX\n",$hdr_len);
           my $hdr = substr($data,8,$hdr_len);

           my $key = "\xA7\xBF\x73\xA0\x9F\x03\xD3\x11\x85\x6F\x00\x80\xAD\xA9\x6E\x9B";
           my $rc4 = Crypt::RC4->new( $key );
           my $newdata = $rc4->RC4( $hdr );

           my $newfilename = sprintf($file.'.%08d_Gdata.met1',$ofs);
           print   STDERR " -> '$newfilename' - Gdata Metadata File 1\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
           writefile ($newfilename, $newdata);

           $data = substr($data,8+$hdr_len,length($data)-8-$hdr_len);

           if ($data=~/^\xBA\xAD\xF0\x0D/)
           {
            my $body_len = unpack("I",substr($data,0x4,4));
             printf STDERR ("body_len = %08lX\n",$body_len);
            if ($body_len<$size)
            {
              my $body = substr($data,8,$body_len);

              $rc4 = Crypt::RC4->new( $key );
              $newdata = $rc4->RC4( $body );

              my $newfilename = sprintf($file.'.%08d_Gdata.met2',$ofs);
              print   STDERR " -> '$newfilename' - Gdata Metadata File 2\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
              writefile ($newfilename, $newdata);

              $data = substr($data,8+$body_len,length($data)-8-$body_len);

              $rc4 = Crypt::RC4->new( $key );
              $newdata = $rc4->RC4( $data );

              $newfilename = sprintf($file.'.%08d_Gdata.out',$ofs);
              print   STDERR " -> '$newfilename' - Gdata File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
              writefile ($newfilename, $newdata);


            }
           }
        }
    }

sub u
{
  my $a=shift;
  $a=~s/(.)/$1\x00/g;
  return $a;
}

sub extract_sentinelone
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_SentinelOne.out',$ofs);

        my $newdata = dexor($data,255);
        print   STDERR " -> '$newfilename' - Sentinel One File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);
    }

sub extract_asquared
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_ASquared.out',$ofs);

        $data = substr($data,0x1A,length($data)-0x1A);
        my $fno=unpack("I",substr($data,0x14,4));
        my $fnl=unpack("I",substr($data,0x18,4));
        my $fn=substr($data,$fno,$fnl);

        $fn =~ s/(.)\x00/$1/g;

        my $dn=unpack("I",substr($data,0x1C,4));
        my $tn=substr($data,$dn+32,256);
        $tn =~ s/(.)\x00/$1/g;

        my $do=unpack("I",substr($data,0x24,4));
        $data = substr($data,$do,length($data)-$do);

        my $rc4 = Crypt::RC4->new( md5 (u('{A4A1BFF9-301A-40d3-86D3-D1F29E413B28}')) );
        my $newdata = $rc4->RC4( $data ) ;

        print   STDERR " -> '$newfilename' - ASquared File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        print   STDERR "    Original File name: '$fn' \n";
        print   STDERR "    Threat Name: '$tn' $dn \n";
        writefile ($newfilename, $newdata);

    }

sub extract_k7
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_K7.out',$ofs);

        my $len = unpack("I", substr($data, 0x128, 4));
        print STDERR "$len\n";
        if ($len<$size)
        {
           my $newdata = dexor(substr($data, 0x178, $len), 0xFF);

           print   STDERR " -> '$newfilename' - K7 File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
           writefile ($newfilename, $newdata);
        }
    }

# extract_kaspersky routine is based on the code by Optiv
sub extract_kaspersky
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename_out = sprintf($file.'.%08d_Kaspersky.out',$ofs);
        my $newfilename_met = sprintf($file.'.%08d_Kaspersky.met',$ofs);

        print   STDERR " -> '$newfilename_out' - Kaspersky File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        print   STDERR " -> '$newfilename_met' - Kaspersky File MetaData\n";

        my $headerlen  = unpack("I", substr($data,0x08,4));
        my $metaoffset = unpack("I", substr($data,0x10,4));
        my $metalen    = unpack("I", substr($data,0x20,4));
        my $origlen    = unpack("I", substr($data,0x30,4));

        my $meta = '';
        $meta.="    Header Length   = $headerlen\n";
        $meta.="    Metadata offset = $metaoffset\n";
        $meta.="    Metadata length = $metalen\n";
        $meta.="    Original length = $origlen\n";

        my @key =(0xE2,0x45,0x48,0xEC,0x69,0x0E,0x5C,0xAC);

        my $curoffset = $metaoffset;
        my $len  = unpack("I", substr($data,$curoffset,4));

        while ($len>0&&$len<length($data))
        {
           my $enc = substr($data,$curoffset+4,$len);
           my $dec='';
           for (my $i=0; $i<$len; $i++)
           {
              $dec.=chr ( ord (substr($enc,$i,1)) ^ $key[$i % ($#key+1)] );
           }
           my $idlen  = unpack("I", substr($dec,0,4));
           my $idname = substr($dec,4,$idlen);
           my $idval  = substr($dec,4+$idlen,length($dec)-4-$idlen);
           $idname=~s/\x00+$//;

           $meta.="    ###\n";
           $meta.="    Attribute: '$idname'\n";
              if ('cNP_QB_ID'                    eq $idname)
              {
                $meta.=hexdump($idval)."\n";
              }
           elsif ('cNP_QB_FULLNAME'              eq $idname)
              {
                $idval=~s/(.)\x00/$1/g;
                $meta.="        File name: ".$idval."\n";
              }
           elsif ('cNP_QB_FILE_ATTRIBUTES'       eq $idname)
              {
                my $attr = unpack("I32",$idval);
                my $attr_str='';
                my $attrtmp=$attr;
                if ($attr & 0x2000) { $attr_str.= 'I'; $attrtmp-=0x2000;}
                if ($attr & 0x0020) { $attr_str.= 'A'; $attrtmp-=0x0020;}
                if ($attr & 0x0004) { $attr_str.= 'S'; $attrtmp-=0x0004;}
                if ($attr & 0x0002) { $attr_str.= 'H'; $attrtmp-=0x0002;}
                if ($attr & 0x0001) { $attr_str.= 'R'; $attrtmp-=0x0001;}
                if ($attrtmp!=0 ) { $attr_str.= sprintf(" +0x%02X",$attrtmp);}
                $meta.=sprintf("        Attributes = 0x%02lX ('$attr_str')\n",$attr);
              }
           elsif ('cNP_QB_FILE_CREATION_TIME'    eq $idname)
              {
                $meta.=hexdump($idval)."\n";
              }
           elsif ('cNP_QB_FILE_LAST_ACCESS_TIME' eq $idname)
              {
                $meta.=hexdump($idval)."\n";
              }
           elsif ('cNP_QB_FILE_LAST_WRITE_TIME'  eq $idname)
              {
                $meta.=hexdump($idval)."\n";
              }
           elsif ('cNP_QB_FILE_SECURITY'         eq $idname)
              {
                $meta.=hexdump($idval)."\n";
              }
           elsif ('cNP_QB_RESTORER_PID'          eq $idname)
              {
                $meta.=hexdump($idval)."\n";
              }
           elsif ('cNP_QB_STORE_TIME'            eq $idname)
              {
                $meta.=hexdump($idval)."\n";
              }
           elsif ('cNP_QB_INFO'                  eq $idname)
              {
                $meta.=hexdump($idval)."\n";
              }
           $curoffset += 4 + $len;
           last if ($curoffset>=length($data)-4);
           $len  = unpack("I", substr($data,$curoffset,4));
        }

        my $newdata='';
        for (my $i=0; $i<$origlen; $i++)
        {
           $newdata.=chr ( ord (substr($data,$headerlen+$i,1)) ^ $key[$i % ($#key+1)] );
        }
        print   STDERR "$meta\n";
        writefile ($newfilename_met, $meta);
        writefile ($newfilename_out, $newdata);

    }

sub extract_kaspersky_system_watcher
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_Kaspersky_System_Watcher.out',$ofs);

        print   STDERR " -> '$newfilename' - Kaspersky System Watcher File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";

        my $newdata = dexorv($data,"\x39\x7b\x4d\x58\xc9\x39\x7b\x4d\x58\xc9");

        writefile ($newfilename, $newdata);

    }

sub extract_kaspersky_security_for_windows_server
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_Kaspersky_Server.out',$ofs);

        print   STDERR " -> '$newfilename' - Kaspersky Server File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";

        my $newdata = dexorv($data,"\xe2\x45\x48\xec\x69\x0e\x5c\xac");

        writefile ($newfilename, $newdata);

    }

sub extract_malwarebytes
    {
        my $file = shift;
        my $data = shift;
        my $ofs  = shift;
        my $size = shift;

        my $newfilename = sprintf($file.'.%08d_MBAM.out',$ofs);

        my $rc4 = Crypt::RC4->new( md5 ('XBXM8362QIXD9+637HCB02/VN0JF6Z3)cB9UFZMdF3I.*c.,c5SbO7)WNZ8CY1(XMUDb') );
        my $newdata = $rc4->RC4( $data );

        print   STDERR " -> '$newfilename' - MBAM File\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);

        $newfilename = sprintf($file.'.%08d_MBAM-NEW.out',$ofs);

        $rc4 = Crypt::RC4->new( md5 ('Go9r%8hhAl7Ari;vnQ8wwkmeostfETkzLEf5*+6u8MF.CbsYKbTt9w.cVJbJ+pzyvrsT') );
        $newdata = $rc4->RC4( $data );

        print   STDERR " -> '$newfilename' - MBAM File - NEW\n -> ofs='$ofs' (".sprintf("%08lX",$ofs).")\n";
        writefile ($newfilename, $newdata);

    }

sub writefile
    {
        my $file = shift;
        my $data = shift;

        $output_files{$file} = 1;

        open    (FILE, '>'.$file);
        binmode (FILE);
        print    FILE $data;
        close   (FILE);
    }

sub readfile
    {
        my $file = shift;
        my $ofs  = shift;
        my $siz  = shift;

        return  '' if !-f $file;

        open    (FILE, '<'.$file);
        binmode (FILE);
        seek    (FILE, $ofs, 0);
        read    (FILE, my $data, $siz);
        close   (FILE);

        return $data;
    }

sub olestream
    {
        my ($oPps, $iLvl, $iTtl, $iDir, $file) = @_;

        my $sName = OLE::Storage_Lite::Ucs2Asc($oPps->{Name});
        $sName =~ s/\W/ /g;

        my $data;

        if ($oPps->{Type}==2 and $oPps->{Size} > 0)
            {
                print STDERR $file."\n";
                $data = $oPps->{Data};

                my $newfilename = sprintf($file.+'.'.+$sName.'.out');

                my $newdata = dexor($data, 0x6A);
                open(my $fh, '>', $newfilename);
                print $fh $newdata;
                close $fh;
                print STDERR " -> '$newfilename' - Decrypted data\n -> key = 0x6A (106)\n";
            }

        my $iDirN=1;
        foreach my $iItem (@{$oPps->{Child}})
            {
                olestream($iItem, $iLvl+1, $iTtl, $iDirN, $file);
                $iDirN++;
            }
        return 1;
    }

sub carve
    {
        my $filename = shift;
        my $what     = shift;
        my $fsiz  = -s $filename;

        my %magic;
        $magic{'BMP'}="BM";
        $magic{'JPEG'}="\xFF\xD8\xFF\xE0";
        $magic{'PNG'}="\x89\x50\x4E\x47";
        $magic{'CLASS'}="\xCA\xFE\xBA\xBE";
        $magic{'CAB'}="MSCF";
        $magic{'GIF'}="GIF8";
        $magic{'PE'}="MZ";
        $magic{'SZDD'}="SZDD";
        $magic{'Rar'}="Rar!";
        $magic{'PDF'}='%PDF';
        $magic{'PHP'}='<?php';
        $magic{'LUA'}="\x1bLua";
        $magic{'XMP'}="<?xpacket begin";
        $magic{'ZIP'}="PK\x03\x04";
        $magic{'Crx'}="Cr24";
        $magic{'rtf'}="{\\rtf";

        my $MAXSIZEREAD = 1024*1024;

        open (INFILE, "<$filename") or return;
        binmode (INFILE);
        seek (INFILE, 1, 0); # skip first byte, if necessary
        read (INFILE,my $rawbytes,$MAXSIZEREAD);

        my $lastp=0;
        my $p=0;

        foreach my $TAG (keys %magic)
        {
        my $FIND=$magic{$TAG};
        my $fileCNT=0;
        my %EMBFiles;
        my $p=0;
        my $lastp=0;
        while ($rawbytes =~ /[\r\n]/sg) { $rawbytes =~ s/[\r\n]/*/sg; }
        pos $rawbytes=0;
        while ($rawbytes =~ /\Q$FIND\E/sg)
         {
            $p=(pos $rawbytes)+1-length($FIND);
            my $addfile = 1;
            if ($TAG eq 'PE')
               {
                   $addfile = 0;
                 seek (INFILE,$p+0x3C,0);
                 read (INFILE, my $o2PEx,4);
                 $o2PEx=unpack("I32",$o2PEx);
                 if ($o2PEx<16384)
                 {
                  seek (INFILE, $p+$o2PEx, 0);
                  read (INFILE, my $PEHeaderx,2);
                  if (($PEHeaderx eq 'PE')||($PEHeaderx eq 'NE')||($PEHeaderx eq 'LE'))
                  {
                      $addfile=1;
                  }
                 }
               }
            elsif ($TAG eq 'BMP')
              {
                  $addfile = 0;
                  if (substr($rawbytes,$p,8) =~ /BM....\x00\x00/sg)
                  {
                      $addfile = 1;
                  }

              }

            if ($addfile==1)
            {
                if ($fileCNT>0)
                  {
                    $EMBFiles{$fileCNT-1}{'size'}=($p-$lastp);
                  }
                $EMBFiles{$fileCNT}{'ofs'}=$p;
                $fileCNT++;
                $lastp=$p;
                if ($TAG eq 'PHP')
                {
                     last;
                }
             }
         }

         if (($fileCNT>0)&&($lastp!=0))
         {
             $EMBFiles{$fileCNT-1}{'size'}=($fsiz-$lastp);
             print STDERR "Extracting embedded $TAG file(s) #$fileCNT to:\n";
             for (my $k=0;$k<$fileCNT;$k++)
             {
                #print "$k: $EMBFiles{$k}{'size'}\n";

                next if $EMBFiles{$k}{'size'}<128;
                print STDERR "         -> ".$filename.'_'.sprintf("%08lX",$EMBFiles{$k}{'ofs'}).'_'.sprintf("%08lX",$EMBFiles{$k}{'size'}).".$TAG\n";
                seek (INFILE,$EMBFiles{$k}{'ofs'}, 0);
                read (INFILE, my $FileData,$EMBFiles{$k}{'size'});

                my $filename2 = $filename;
                $filename2 =~ s/^\.\///;
                $filename2 =~ s/^[^&\@#]$/$1/;
                $filename2 =~ s#\\#_#g;
                $filename2 =~ s#\/#_#g;
                $filename2 = $filename2.'_'.sprintf("%08lX",$EMBFiles{$k}{'ofs'}).'_'.sprintf("%08lX",$EMBFiles{$k}{'size'}).".$TAG";
                if (! -f $filename2)
                {
                   open OUTFILE,">$filename2";
                   syswrite OUTFILE,$FileData,$EMBFiles{$k}{'size'};
                   close(OUTFILE);
                }
                #else
                #{
                #   my $fcnt=0;
                #   while (-f $filename2.".".$fcnt)
                #   {
                #      $fcnt++;
                #   }
                #   open OUTFILE,">$filename2".".".$fcnt;
                #   syswrite OUTFILE,$FileData,$EMBFiles{$k}{'size'};
                #   close(OUTFILE);
                #}
             }
           }
        }
        close (INFILE);
    }

sub dexor
    {
        my $data = shift;
        my $xorv = shift;

        my $newdata = '';

        for (my $i=0; $i<length($data); $i++)
            {
                $newdata .= chr(ord(substr($data, $i, 1)) ^ $xorv);
            }

        return $newdata;
    }

sub dexorv
    {
        my $data = shift;
        my $key  = shift;

        my $newdata = '';

        my $n=0;
        for (my $i=0; $i<length($data); $i++)
            {
                my $b=ord(substr($data,$i,1));
                my $k=ord(substr($key,$n,1));
                $newdata.=chr($b^$k);
                $n++;$n=0 if ($n>(length($key)-1));
            }

        return $newdata;
    }

sub blowfishit
{
        my $data = shift;
        my $key = shift;
        my $swap = shift;
        my $dec='';
        my $bf = new Crypt::Blowfish $key;
        print STDERR "Decrypting ".(length($data))." bytes with Blowfish, it's a bit slow, be patient\n" if length($data)>5*1024*1024;
        while ($data=~/(.{8})/sg)
        {
           my $d=$1;
           $d=pack("N",unpack("I",substr($d,0,4))).pack("N",unpack("I",substr($d,4,4))) if ($swap==1);
           $d=$bf->decrypt($d);
           $d=pack("N",unpack("I",substr($d,0,4))).pack("N",unpack("I",substr($d,4,4))) if ($swap==1);
           $dec.= $d;
        }
        return $dec;
}

sub hexdump
{
 my $data = shift;
 return hexdumpl($data,6);
}

sub hexdumpl
{
 my $data = shift;
 my $lev=shift;
 my $ret = '';
 my $ofs=0;
 my $size=length($data);
 while ($data =~/(.{16})/gs)
   {
    my $x = $1;
    my $y = $1;
    $x = uc(unpack ("H*",$x));
    $x =~ s/(..)/$1 /g;
    $y =~ s/[^\x20-\x7E]/\./g;
    $ret .= (' ' x $lev)."$x $y\n";
    $ofs++;
   }
  if ($size % 16 != 0)
   {
      $data = substr ($data,16 * int($size/16),$size % 16);
      my $x = $data;
      my $y = $data;
      $x = uc(unpack ("H*",$x));
      $x =~ s/(..)/$1 /g;
      $y =~ s/[^\x20-\x7E]/\./g;
      for (my $i=length($data);$i<16;$i++)
      {
       $x.=' 'x3;
      }
      $ret .= (' ' x $lev)."$x $y\n";
   }

 return $ret;
}

sub epoch
    {
       my $epoch = shift;

       my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($epoch);
       $year += 1900;
       $mon  += 1;
       return sprintf("%04d-%02d-%02d %02d:%02d:%02d",$year,$mon,$mday,$hour,$min,$sec);
    }

sub sep_meta
    {
    my $file = shift;
    my $data = shift;
    my $ofs  = shift;
    my $key  = shift;

    my $logline;
    my $newfile_met = sprintf($file.'.%02X.met',$key);
    if ($data =~ /([0-9A-F]{12}),/si)
    {
      $logline = $-[0];
    }
    #printf ("### DEBUG: The logline is @ %08lX (%d)\n",$logline,$logline);
    my $metadata = substr($data, $logline, index(substr($data, $logline), "\0\0"));
    #printf ("### DEBUG:$data, $metadata\n\n");
    my @metadata = split(',', $metadata);
    my $meta = '';
    if (length $metadata[0])
    {
      $meta.="TIME                   = ".(sep_time($metadata[0]))."\n";
        }
    if (length $metadata[1])
    {
      $meta.="EVENT                  = ".(sep_event($metadata[1]))."\n";
        }
    if (length $metadata[2])
    {
      $meta.="CATEGORY               = ".(sep_category($metadata[2]))."\n";
        }
    if (length $metadata[3])
    {
      $meta.="LOGGER                 = ".(sep_logger($metadata[3]))."\n";
        }
    if (length $metadata[4])
    {
      $meta.="COMPUTER               = $metadata[4]\n";
        }
    if (length $metadata[5])
    {
      $meta.="USER                   = $metadata[5]\n";
        }
    if (length $metadata[6])
    {
      $meta.="VIRUS                  = $metadata[6]\n";
        }
    if (length $metadata[7])
    {
      $meta.="FILE                   = $metadata[7]\n";
    }
    if (length $metadata[8])
    {
      $meta.="WANTED ACTION 1        = ".(sep_action($metadata[8]))."\n";
        }
    if (length $metadata[9])
    {
      $meta.="WANTED ACTION 2        = ".(sep_action($metadata[9]))."\n";
        }
    if (length $metadata[10])
    {
      $meta.="REAL ACTION            = ".(sep_action($metadata[10]))."\n";
        }
    if (length $metadata[11])
    {
      $meta.="VIRYS TYPE             = ".(sep_vtype($metadata[11]))."\n";
        }
    if (length $metadata[12])
    {
      $meta.="FLAGS                  = $metadata[12]\n";
        }
    if (length $metadata[13])
    {
      $meta.="DESCRIPTION            = $metadata[13]\n";
        }
    if (length $metadata[14])
    {
      $meta.="SCAN ID                = $metadata[14]\n";
        }
    if (length $metadata[15])
    {
      $meta.="NEW_EXT                = $metadata[15]\n";
    }
    if (length $metadata[16])
    {
      $meta.="GROUP ID               = $metadata[16]\n";
        }
    if (length $metadata[17])
    {
      $meta.="EVENT DATA             = $metadata[17]\n";
        }
    if (length $metadata[18])
    {
      $meta.="VBin_ID                = $metadata[18]\n";
        }
    if (length $metadata[19])
    {
      $meta.="VIRUS ID               = $metadata[19]\n";
        }
    if (length $metadata[20])
    {
      $meta.="QUARFWD_STATUS         = $metadata[20]\n";
        }
    if (length $metadata[21])
    {
      $meta.="ACCESS                 = $metadata[21]\n";
    }
    if (length $metadata[22])
    {
      $meta.="SND_STATUS             = $metadata[22]\n";
        }
    if (length $metadata[23])
    {
      $meta.="COMPRESSED             = $metadata[23]\n";
        }
    if (length $metadata[24])
    {
      $meta.="DEPTH                  = $metadata[24]\n";
        }
    if (length $metadata[25])
    {
      $meta.="STILL_INFECTED         = $metadata[25]\n";
        }
    if (length $metadata[26])
    {
      $meta.="DEFINFO                = $metadata[26]\n";
        }
    if (length $metadata[27])
    {
      $meta.="DEFSEQNUMBER           = $metadata[27]\n";
    }
    if (length $metadata[28])
    {
      $meta.="CLEANINFO              = $metadata[28]\n";
    }
    if (length $metadata[29])
    {
      $meta.="DELETINFO              = $metadata[29]\n";
        }
    if (length $metadata[30])
    {
      $meta.="BACKUPID               = $metadata[30]\n";
        }
    if (length $metadata[31])
    {
      $meta.="PARENT                 = $metadata[31]\n";
        }
    if (length $metadata[32])
    {
      $meta.="GUID                   = $metadata[32]\n";
        }
    if (length $metadata[33])
    {
      $meta.="CLIENTGROUP            = $metadata[33]\n";
    }
    if (length $metadata[34])
    {
      $meta.="ADDRESS                = $metadata[34]\n";
        }
    if (length $metadata[35])
    {
      $meta.="DOMAINNAME             = $metadata[35]\n";
        }
    if (length $metadata[36])
    {
      $meta.="NTDOMAIN               = $metadata[36]\n";
        }
    if (length $metadata[37])
    {
      $meta.="MACADDR                = $metadata[37]\n";
    }
    if (length $metadata[38])
    {
      $meta.="VERSION                = $metadata[38]\n";
        }
    if (length $metadata[39])
    {
      $meta.="REMOTE_MACHINE         = $metadata[39]\n";
        }
    if (length $metadata[40])
    {
      $meta.="REMOTE_MACHINE IP      = $metadata[40]\n";
        }
    if (length $metadata[41])
    {
      $meta.="ACTION1_STATUS         = $metadata[41]\n";
        }
    if (length $metadata[42])
    {
      $meta.="ACTION2_STATUS         = $metadata[42]\n";
        }
    if (length $metadata[43])
    {
      $meta.="LICENSE_FEATURE_NAME   = $metadata[43]\n";
    }
    if (length $metadata[44])
    {
      $meta.="LICENSE_FEATURE_VER    = $metadata[44]\n";
        }
    if (length $metadata[45])
    {
      $meta.="LICENSE_SERIAL_NUM     = $metadata[45]\n";
        }
    if (length $metadata[46])
    {
      $meta.="LICENSE_FULFILLMENT_ID = $metadata[46]\n";
    }
    if (length $metadata[47])
    {
      $meta.="LICENSE_START_DT       = $metadata[47]\n";
    }
    if (length $metadata[48])
    {
      $meta.="LICENSE_EXPIRATION_DT  = $metadata[48]\n";
    }
    if (length $metadata[49])
    {
      $meta.="LICENSE_LIFECYCLE      = $metadata[49]\n";
    }
    if (length $metadata[50])
    {
      $meta.="LICENSE_SEATS_TOTAL    = $metadata[50]\n";
    }
    if (length $metadata[51])
    {
      $meta.="LICENSE_SEATS          = $metadata[51]\n";
    }
    if (length $metadata[52])
    {
      $meta.="LI_ERR_CODE            = $metadata[52]\n";
    }
    if (length $metadata[53])
    {
      $meta.="LI_LICENSE_SEATS_DELTA = $metadata[53]\n";
    }
    if (length $metadata[54])
    {
      $meta.="STATUS                 = ".(sep_eraser($metadata[54]))."\n";
    }
    if (length $metadata[55])
    {
      $meta.="DOMAIN_GUID            = $metadata[55]\n";
    }
    if (length $metadata[56])
    {
      $meta.="LOG_SESSION_GUID_VBIN  = $metadata[56]\n";
    }
    if (length $metadata[57])
    {
      $meta.="VBIN_SESSION_ID        = $metadata[57]\n";
        }
    if (length $metadata[58])
    {
      $meta.="LOGIN DOMAIN           = $metadata[58]\n";
    }
    if (length $metadata[59])
    {
      $meta.="EVENT DATA 2           = $metadata[59]\n";
        }
    if ($key == 0xA5)
    {
      if (length $metadata[60])
      {
        $meta.="ERASER_CAT_ID          = ".(sep_eraserid($metadata[60]))."\n";
          }
      if (length $metadata[61])
      {
        $meta.="DYN_CAT_ID             = ".(sep_dycatid($metadata[61]))."\n";
      }
      if (length $metadata[62])
      {
        $meta.="DYN_SUB_ID             = $metadata[62]\n";
      }
      if (length $metadata[63])
      {
        $meta.="DISPLAY NAME TO USE    = ".(sep_dname($metadata[63]))."\n";
      }
      if (length $metadata[64])
      {
        $meta.="REP_DISPOSITION        = ".(sep_rep($metadata[64]))."\n";
      }
      if (length $metadata[65])
      {
        $meta.="REP_CONFIDENCE         = $metadata[65]\n";
      }
      if (length $metadata[66])
      {
        $meta.="FIRST SEEN             = $metadata[66]\n";
      }
      if (length $metadata[67])
      {
        $meta.="REP_PREVALENCE         = $metadata[67]\n";
      }
      if (length $metadata[68])
      {
        $meta.="DOWNLOAD URL           = $metadata[68]\n";
      }
      if (length $metadata[69])
      {
        $meta.="CREATOR FOR DROPPER    = $metadata[69]\n";
      }
      if (length $metadata[70])
      {
        $meta.="CIDS STATE             = $metadata[70]\n";
      }
      if (length $metadata[71])
      {
        $meta.="BEHAVIOR RISK LEVEL    = $metadata[71]\n";
      }
      if (length $metadata[72])
      {
        $meta.="DETECTION TYPE         = ".(sep_dtype($metadata[72]))."\n";
      }
      if (length $metadata[73])
      {
        $meta.="ACK_TEXT               = $metadata[73]\n";
          }
      if (length $metadata[74])
      {
        $meta.="VSCI_STATE             = ".(sep_vsic($metadata[74]))."\n";
          }
      if (length $metadata[75])
      {
        $meta.="SCAN GUID              = $metadata[75]\n";
      }
      if (length $metadata[76])
      {
        $meta.="SCAN DURATION          = ".(sep_dur($metadata[76]))."\n";
      }
      if (length $metadata[77])
      {
        $meta.="SCAN_START_TIME        = ".(sep_time($metadata[77]))."\n";
      }
      if (length $metadata[78])
      {
        $meta.="TARGETAPP_TYPE         = ".(sep_apptype($metadata[78]))."\n";
      }
      if (length $metadata[79])
      {
        $meta.="SCAN COMMAND GUID      = $metadata[79]\n";
      }
      if (length $metadata[80])
      {
        $meta.="UNKNOWN                = $metadata[80]\n";
          }
      if (length $metadata[81])
      {
        $meta.="UNKNOWN                = $metadata[81]\n";
          }
      if (length $metadata[82])
      {
        $meta.="UNKNOWN                = $metadata[82]\n";
      }
    }
    print   STDERR " -> '$newfile_met' \n";
    writefile ($newfile_met, $meta);
    }

sub sep_time
    {
    my $timestring = shift;
    my $yearval = hex(substr($timestring,0,2))+1970;
    my $monthval = hex(substr($timestring,2,2))+1;
    my $dayval = hex(substr($timestring,4,2));
    my $hourval = hex(substr($timestring,6,2));
    my $minuteval = hex(substr($timestring,8,2));
    my $secondval = hex(substr($timestring,10,2));
    return $monthval."/".$dayval."/".$yearval." ".$hourval.":".$minuteval.":".$secondval;
    }

sub sep_event
    {
    my $evtnum = shift;
    my @sepevent = ("","Alert","Scan Stop","Scan Start","Pattern Update","Infection","File Not Open","Load Pattern","Message Info","Message Error","Event Checksum","Event Trap","Event Config Change","Event Shutdown","Event Startup","Pattern Download","Too Many Viruses","Fwd To QServer","Scandlvr","Backup","Scan Abort","RTS Load Error","RTS Load","RTS Unload","Remove Client","Scan Delayed","Scan Restart","Add SavRoamClient ToServer","Remove SavRoamClient FromServer","License Warning","License Error","License Grace","Unauthorized Comm","Log Fwr Thrd Err","License Installed","License Allocated","License OK","License Deallocated","Bad Defs Rollback","Bad Defs Unportected","Sav Provider Parsing Error","RTS Error","Compliance Fail","Compliance Success","Security SymProtect PolicyViolation","Anomaly Start","Detection action Taken","Remediation Action Pending","Remediation Action Failed","Remediation Action Successful","Anomaly Finish","Comms Login Failed","Comms Login Success","Comms Unauthorized Comm","Client Install AV","Client Install FW","Client Uninstall","Client Uninstall Rollback","Comms Server Group Root Cert Issue","Comms Server Cert Issue","Comms Trusted Root Change","Comms Server Cert Startup Failed","Client Checkin","Client No Checkin","Scan Suspended","Scan Resumed","Scan Duration Insufficient","Client Move","Scan Failed Enhanced","Compliance FailedAudit","Heur Threat Now Whitelisted","Heur Threat Now Whitelisted","Interesting Process Detected Start","Load Error Bash","Load Error Bash Deffinitions","Interesting Process Detected Finish","Bash Not Supported For OS","Heur Threa Now Known","Disable Bash","Enable Bash","Defs Load Failed","Localrep Cache Server Error","Reputation Check Time","SymepsecFilter Driver Error","VSIC Communication Warning","VSIC Communication Restored","ELAM Load Failed","ELAM Invalid OS","ELAM Enabled","ELAM Disable","ELAM Bad","ELAM Bad reported as Unknown","Disable Symprotect","Enable Symprotect","Netsec EOC Parse Failed");
    my $event = $sepevent[$evtnum];
    return $event;
    }

sub sep_category
    {
    my $catnum = shift;
    my @sepcat = ("","Infection","Summary","Pattern","Security");
    my $category = $sepcat[$catnum];
    return $category;
    }

sub sep_logger
    {
    my $loggernum = shift;
    my $logger;
    if ($loggernum == 100)
    {
      $logger = "Local End";
        }
    elsif ($loggernum == 101)
        {
          $logger = "Client";
        }
        elsif ($loggernum == 102)
    {
      $logger = "Forwarded";
        }
    elsif ($loggernum == 256)
    {
      $logger = "Transport Client";
        }
    else
    {
      my @seplogger = ("Scheduled","Manual","Real Time","Integrity Shield","Console","VPDown","System","Startup","Idle","DefWatch","License","Manual Quarantine","SymProtect","Reboot Processing","Bash","SymElam","PowerEraser","EOCScan");
      $logger = $seplogger[$loggernum];
        }
    return $logger
    }

sub sep_action
    {
    my $actionnum = shift;
    my $action;
    if ($actionnum == 4294967295)
    {
      $action = "Invalid";
        }
    elsif ($actionnum == 110)
    {
      $action = "Interesting Process Cal";
        }
    elsif ($actionnum == 111)
    {
      $action = "Interesting Process Detection";
        }
    elsif ($actionnum == 1000)
    {
      $action = "Interesting Process Hashed Detected";
        }
    elsif ($actionnum == 1001)
    {
      $action = "DNS Host File Exception";
        }
    else
    {
      my @sepaction = ("","Quarantine","Rename","Delete","Leave Alone","Clean","Remove Macros","Save file as ...","Sent to backent","Restore from Quarantine","Rename Back (unused)","Undo Action","Error","Backup to quarantine (backup view)","Pending Analysis","Partially Fixed","Terminate Process Required","Exclude from Scanning","Reboot Processing","Clean by Deletion","Access Denied","terminate Proccess Oly","No Repair","Fail","Run Powertool","No Repair Powertool");
      $action = $sepaction[$actionnum];
        }
    return $action;
    }

sub sep_vtype
    {
    my $vtypenum = shift;
    my $vtype;
    if ($vtypenum == 48)
    {
      $vtype = "Heuristic";
    }
    elsif ($vtypenum == 64)
    {
      $vtype = "Reputation";
        }
    elsif ($vtypenum == 80)
    {
      $vtype = "Hack Tools";
        }
    elsif ($vtypenum == 96)
    {
      $vtype = "Spyware";
        }
    elsif ($vtypenum == 112)
    {
      $vtype = "Trackware";
        }
    elsif ($vtypenum == 128)
    {
      $vtype = "Dialers";
    }
    elsif ($vtypenum == 144)
    {
          $vtype = "Remote Access";
        }
    elsif ($vtypenum == 160)
    {
      $vtype = "Adware";
        }
    elsif ($vtypenum == 176)
    {
      $vtype = "Joke Programs";
        }
    elsif ($vtypenum == 224)
    {
      $vtype = "Heuristic Application";
        }
    else
    {
      return $vtypenum;
        }
    return $vtype;
    }

## todo
sub sep_flags
    {
      my $flagsnum = shift;
    }

sub sep_eraser
    {
      my $erasernum = shift;
      my $eraser;
      if ($erasernum == 999)
      {
    $eraser = "Leave Alone";
      }
      elsif ($erasernum == 1000)
      {
    $eraser = "General Failure";
      }
      elsif ($erasernum == 1001)
      {
    $eraser = "Out of Memeory";
      }
      elsif ($erasernum == 1002)
      {
    $eraser = "Not Initialized";
      }
      elsif ($erasernum == 1003)
      {
    $eraser = "Invalid Argument";
      }
      elsif ($erasernum == 1004)
      {
    $eraser = "Insufficient Buffer";
      }
      elsif ($erasernum == 1005)
      {
    $eraser = "Decription Error";
      }
      elsif ($erasernum == 1006)
      {
    $eraser = "File Not Found";
      }
      elsif ($erasernum == 1007)
      {
    $eraser = "Out Of Range";
      }
      elsif ($erasernum == 1008)
      {
    $eraser = "COM Error";
      }
      elsif ($erasernum == 1009)
      {
    $eraser = "Partial Failure";
      }
      elsif ($erasernum == 1010)
      {
    $eraser = "Bad Deffinitions";
      }
      elsif ($erasernum == 1011)
      {
    $eraser = "Invalid Command";
      }
      elsif ($erasernum == 1012)
      {
    $eraser = "No Interface";
      }
      elsif ($erasernum == 1013)
      {
    $eraser = "RSA Error";
      }
      elsif ($erasernum == 1014)
      {
    $eraser = "Path Not Empty";
      }
      elsif ($erasernum == 1015)
      {
    $eraser = "Invalid Path";
      }
      elsif ($erasernum == 1016)
      {
    $eraser = "Path Not Empty";
      }
      elsif ($erasernum == 1017)
      {
    $eraser = "File Still Present";
      }
      elsif ($erasernum == 1018)
      {
    $eraser = "Invalid OS";
      }
      elsif ($erasernum == 1019)
      {
    $eraser = "Not Implemented";
      }
      elsif ($erasernum == 1020)
      {
    $eraser = "Acces Denied";
      }
      elsif ($erasernum == 1021)
      {
    $eraser = "Directory Still Present";
      }
      elsif ($erasernum == 1022)
      {
    $eraser = "Inconsistent State";
      }
      elsif ($erasernum == 1023)
      {
    $eraser = "Timeout";
      }
      elsif ($erasernum == 1024)
      {
    $eraser = "Action Pending";
      }
      elsif ($erasernum == 1025)
      {
    $eraser = "Volume Write Protected";
      }
      elsif ($erasernum == 1026)
      {
    $eraser = "Not Reparse Point";
      }
      elsif ($erasernum == 1027)
      {
    $eraser = "File Exists";
      }
      elsif ($erasernum == 1028)
      {
    $eraser = "Target Protected";
      }
      elsif ($erasernum == 1029)
      {
    $eraser = "Disk Full";
      }
      elsif ($erasernum == 1030)
      {
    $eraser = "Shutdown In Progress";
      }
      elsif ($erasernum == 1031)
      {
    $eraser = "Media Error";
      }
      elsif ($erasernum == 1032)
      {
    $eraser = "Network Defs Error";
      }
      else
      {
        my @seperaser = ("Success","Reboot Required","Nothing To Do","Repair","Deleted","False","Abort","Continue","Service Not Stopped","Application Heuristic Scan Failure","Cannot Remediate","Whitelist Failure","Driver Failure","Reserved01","Commercial Application List Failure","Application Heuristic Scan Invalid OS","Content Manager Data Error");
    $eraser = $seperaser[$erasernum];
      }
      return $eraser;
    }

sub sep_eraserid
    {
      my $eraseridnum = shift;
      print $eraseridnum;
      my $eraserid;
      if ($eraserid == 100)
      {
    $eraserid = "CommercialRemoteControl";
      }
      elsif ($eraserid == 101)
      {
    $eraserid = "CommercialKeyLogger";
      }
      elsif ($eraserid == 200)
      {
        $eraserid = "Cookie";
      }
      elsif ($eraserid == 300)
      {
    $eraserid = "Shields";
      }
      else
      {
        my @seperaserid = ("","HeuristicTrojanWorm","HeuristicKeyLogger");
    $eraserid = $seperaserid[$eraseridnum];
      }
      return $eraserid;
    }

sub sep_dycatid
    {
      my $dycatidnum = shift;
      my @sepdycatid = ("","Malware","Security Risk","Potentially Unwanted Applications","Experimental Heuristic","Legacy Viral","Legacy Non Viral","Crimeware","Advanced Heuristics","Reputation Backed Advanced Heuristics","Prevalence Backed Advanced Heuristics");
      my $dycatid = $sepdycatid[$dycatidnum];
      return $dycatid;
    }

sub sep_dname
    {
      my $dnamenum = shift;
      my @sepdname = ("Application Name","VID Virus Name");
      my $dname = $sepdname[$dnamenum];
      return $dname;
    }

sub sep_rep
    {
      my $repnum = shift;
      my $rep;
      if ($repnum == 127)
      {
        $rep = "Unknown";
      }
      else
      {
        my @seprep =("Good","Bad");
    $rep = $seprep[$repnum];
      }
      return $rep;
    }

sub sep_dtype
    {
      my $dtypenum = shift;
      my @sepdtype = ("Traditional","Heuristic");
      my $dtype = $sepdtype[$dtypenum];
      return $dtype;
    }

sub sep_vsic
    {
      my $vsicnum = shift;
      my @sepvsic = ("Off","On","Failed");
      my $vsic = $sepvsic[$vsicnum];
      return $vsic;
    }

sub sep_dur
    {
      my $durnum = shift;
      my @sepdur = gmtime($durnum);
      my $dur = $sepdur[2].":".$sepdur[1].":".$sepdur[0];
      return $dur;
    }

sub sep_apptype
    {
      my $apptypenum = shift;
      my @sepapptype = ("Normal","Modern (Metro)");
      my $apptype = $sepapptype[$apptypenum];
      return $apptype;
    }