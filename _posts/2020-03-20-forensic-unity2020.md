---
title: Forensic - [NEET Diary - 500] UNITY CTF
Kategori: "Forensic"
year: "2020"
author: "Evangel1st"
published: true
---
# Forensic (Author : evangel1st)

Pada tanggal 12 maret kemarin , kami mengikuti lomba ctf kategori mahasiswa , yang diadakan oleh UNY yogyakarta.
untuk kali ini kami akan menulis mengenai kategori forensic yang diberikan kemarin , kita berhasil menemukan flag namun tidak bisa disubmit hingga waktu yang ditentukan berakhir :(
![Tampilan awal soal](/foren/tampilannormal.png "Tampilan awal")
soal yang diberikan kali ini berbentuk pdf , kurang lebih ini tampilan ketika dibuka menggunakan aplikasi pdf viewer. tampak terlihat normal tidak ada yang mencurigakan

namun ketika sata coba analisa menggunakan tools binwalk, muncul sebuah string bertuliskan executable script. awalnya kami fikir didalam file pdf ini terdapat sebuah ROM Sega [game]
```
rio@ACER-SP314-51 ~/Documents/SOAL CTF/UNITY/Qual                                                       [14:02:16] 
> $ binwalk art-book.pdf                                                                                          

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PDF document, version: "1.3"
590187        0x9016B         Executable script, shebang: "/$XN/Uut,i*5+8:N_^[N#PBXYQhL`m:OR'uBc3;j`aP4#=%$;Nl'uLqMIsA($A#lh0?SVQY+7A9h)b+R&?u4&rg.<6hR=S.^::]]"O+]uZ$+2GFQN8TAguk+53`^`\n)"
2608289       0x27CCA1        StuffIt Deluxe Segment (data): fG/m;73gR;OI4Il6DE9[9\G-R\(>'o,f[#esZj$Lr<KbXEPU@:)dorgjM<]eU?OQJ4H,eb6HQX/p=?0tmhQY]oDH/"VAcgsd'e!CD)_/CS.F.LM`J:Ia6^PRo"Nc5NuB
2786642       0x2A8552        StuffIt Deluxe Segment (data): fc]$"&Kcq[Pb(/ZdTk!^m!3e8rEK9TCh=0"%h(7s0r_EbGPOBKuLsKV5$J5_Q*0`ph3k!m=t1(A37)3]FmJs3R8:nq9<qFYe#"CTM6_GfCIZQ/Np!)rmg-p*Nqoc0so@
4326833       0x4205B1        StuffIt Deluxe Segment (data): fsI$2`bgn#D(D6gZ`7tgc'0krVsV6"\?Dc;=67rfe`1jR-LFY)+25V'F:[j6XMg\tK;Hmo(Q+%.qs7tuKJr@3%k2lLibD,_OF<0rK.7eU16&N\8<6K!SArpH*BEEr12E
4508715       0x44CC2B        StuffIt Deluxe Segment (data): f2MU!h`T$iJgh\)?,T@V"6C$@9c)(95@-uBu!HGSEVX]3RsEmD7CE],k<2[j#0DU)C/q]d=MH0,!G(&,eM*Vme9r*5_lEn4;UZFVU%-L,(cYPAs:VL\o>hO-ohq9k8J'
4533718       0x452DD6        StuffIt Deluxe Segment (data): fZZ3GGu.i*mgQ^4erD+g2."dCYt:TOl02JD7Spq*PbAUFP6drHRa!N<;$2FaW5-b"0bR_cVo-3;O$c0jW$6-\ol4HT5.FTJJX5l.n@kTTO8csm[t#L).OtI=WMK61\!=
4554021       0x457D25        StuffIt Deluxe Segment (data): f6,[ur=Qf*;?Lbk&]8J`="[ELpW[IY58)?=)-'nsS?FsG:qBOFtI*pgW5bIYfIDZloK0[X"dH'3'O[$pcqE1,;;/54#*7h6>c=]0(ml2YjqBgK6kIr!*Hmar#[@kYX,C
4568310       0x45B4F6        Sega MegaDrive/Genesis raw ROM dump, Name: "aJGR)0_pAL_Ik=C@", "t\R;6]7<X!"b$clE",
4849969       0x4A0131        StuffIt Deluxe Segment (data): f.;B*7KorN(tUXGhe%/<Mhk82IS#A!9_VK0\8Q+kkYDLQ@2Wps``)S>h7KkpBuW0ggIH9q]X.F>kY?:fB1%cudpAA0S4'f[88s,UHt8D**gt:mMZ=`m4TOr>=H"!DME>
4865325       0x4A3D2D        StuffIt Deluxe Segment (data): fc\)G`(JVE4Mbl_oh0j*hHK%8@iQ(Q&2;bsQJ]//>JGkd+aXJgVr".=B.]qGl6lO[.J`\WLf-8lB];.V+AEFLeA;ijr/(7`F)+j$JK_C4=aFo-RF,tQk+'L42P-hK(Rq
5260110       0x50434E        Unix path: /F87jQFNe/O/J7Opau4F/uFYTnh,5jA\Kt?_SS6SbcY_c!-SBLGlWX4bnrdRlalT-ASk'nA(BBJo82YA2mfqE$Hcc0\ZTT`l3N5HjLunTM;CdG+2Ll_CNHHK*>_)n3u0
5834903       0x590897        Sega MegaDrive/Genesis raw ROM dump, Name: "nAA\9?4>d$[A,N`(", "2Q4GGoK*.o!C_^%S",
7768894       0x768B3E        StuffIt Deluxe Segment (data): f98'>sX*ZbGG,XXr[=;Qm:_`XdRo_]6c,h!%HK6[.`7m5;h4V@rSW>AstV"j<0Md+e1MRUC8AR9DJkdF<_KKsr`Ln`u='4@\rR6nlb+.6PiC/,cK)Y;-!@$YtkVh2pML

```
namun hasilnya nihil setelah di extract menggunakan exiftool tidak menemukan apapun didalamnya.

selanjutnya kami melanjutkan enumerasi informasi menggunakan tools exiftool dan ini merupakan hasil dari informasi yang didapat.
```
ExifTool Version Number         : 10.80
File Name                       : art-book.pdf
Directory                       : .
File Size                       : 7.9 MB
File Modification Date/Time     : 2020:02:27 08:02:55+07:00
File Access Date/Time           : 2020:03:20 14:00:09+07:00
File Inode Change Date/Time     : 2020:03:20 14:00:09+07:00
File Permissions                : rwxr-xr-x
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.3
Linearized                      : No
Modify Date                     : 2020:02:27 00:49:24
Create Date                     : 2020:02:27 00:49:24
Title                           : artbook
Producer                        : https://www.imagemagick.org
Page Count                      : 17
```
tidak ada keanehan dari metadata yang didapat :3 selang beberapa jam panitia akhirnya memberikan sebuah hint tambahan berupa 
```
imagemagick signature
ghostscript
/ObjectX stream
```
sedikit demi sedikit kami coba memahami apa maksud dari hint tersebut. kami coba ikuti arahan hint , menggunakan ghostscript namun hasil tetap nihil :(( kami tidak menemukan apapun.
akhirnya kami menemukan sebuah post di stackoverflow disana tertulis bahwa ada aplikasi alternative selain ghostscript yaitu MUTOOL[mupdf] kalian bisa lihat postnya disini.
https://stackoverflow.com/questions/3446651/how-to-convert-pdf-binary-parts-into-ascii-ansi-so-i-can-look-at-it-in-a-text-ed
![fitur mutool](/foren/mutool[fiture].png "fiture mutool")
seperti yang disebutkan di postingan tersebut tools ini memiliki fitur extract dari JPG ke RGB.

![extract](/foren/extraction.png "extract")
setelah kami coba fitur extract untuk mengextract pdf yang diberikan , kami melihat sebuah kejanggalan. kami mendapatkan banyak gambar text yang cukup mencurigakan.
setelah di perhatikan kami menemukan potongan potongan flag didalamnya.

![flag](/foren/flag.png "flag")
and Gotcha! kami mendapatkan flag yang dimaksud setelah melakukan penyusunan gambar yang tepat .. namun setelah disubmit selalu saja bertuliskan incorrect yang menandakan bahwa susunan flag salah / belum tepat :(
saya sedikit kesal juga dengan panitia karena mereka memberikan format flag pada soal forensic ini lumayan panjang :((.
```
Flag : UNITY2020{4lways_r3m3mb3r_th4t_aqua_b3ing_aqua_is_definitely_us3less_go
ddess_3ver}
```
