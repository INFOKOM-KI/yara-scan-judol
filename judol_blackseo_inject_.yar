/*
   Rules Yara - Deteksi Black SEO dan Injeksi Konten Judi Online (Judol)
   ================================================================
   Ruleset untuk mendeteksi teknik Black SEO yang digunakan pelaku judi online
   untuk memanipulasi hasil mesin pencarian (SEO), yang menggunakan website sah yang telah
   take-over.

   Teknik yang dicakup:
   - Konten tersembunyi via CSS (display:none, visibility:hidden, opacity:0)
   - Link tersembunyi dengan anchor text bermuatan kata kunci judol
   - Injeksi meta tag keywords/description dengan kata kunci judol
   - Manipulasi file .htaccess untuk redirect ke domain judol
   - Penyisipan iframe tersembunyi mengarah ke situs judol
   - Penggunaan warna teks sama dengan latar (white-on-white)

   Author   : Nauliajati <csirt@tangerangkota.go.id>
   Org      : TangerangKota-CSIRT
   Date     : 2026-05-06
   Version  : 1.0
   License  : TangerangKota-CSIRT Detection Rule License 1.0
   Reference: https://csirt.tangerangkota.go.id
*/


rule Judol_BlackSEO_Hidden_Links {
   meta:
      description = "Detect CSS hidden anchor links containing gambling keywords, Black SEO technique used in website compromise for gambling SEO manipulation"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 85
      tags = "JUDOL, BLACKSEO, HIDDEN_LINKS, CSS_HIDE"

   strings:
      // Teknik CSS untuk menyembunyikan konten judol
      $hide1 = "display:none" ascii
      $hide2 = "display: none" ascii
      $hide3 = "visibility:hidden" ascii
      $hide4 = "visibility: hidden" ascii
      $hide5 = "font-size:0px" ascii
      $hide6 = "font-size: 0px" ascii
      $hide7 = "opacity:0;" ascii
      $hide8 = "height:0;overflow:hidden" ascii
      $hide9 = "height: 0; overflow: hidden" ascii
      $hide10 = "position:absolute;left:-9999" ascii
      $hide11 = "position: absolute; left: -9999" ascii
      $hide12 = "text-indent:-9999" ascii
      $hide13 = "clip:rect(0,0,0,0)" ascii

      // Kata kunci judol
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "link slot" nocase ascii
      $judol7 = "deposit pulsa" nocase ascii
      $judol8 = "bocoran rtp" nocase ascii
      $judol9 = "daftar slot" nocase ascii
      $judol10 = "agen slot" nocase ascii
      $judol11 = "casino online" nocase ascii

   condition:
      filesize < 10MB and
      1 of ($hide*) and
      1 of ($judol*)
}


rule Judol_BlackSEO_Meta_Inject {
   meta:
      description = "Detects injection gambling keywords into HTML meta tags (keywords, description) to manipulate search engine indexing on compromised websites"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 80
      tags = "JUDOL, BLACKSEO, META_INJECT"

   strings:
      // Pola meta tag HTML untuk SEO
      $meta1 = "<meta name=\"keywords\"" nocase ascii
      $meta2 = "<meta name='keywords'" nocase ascii
      $meta3 = "<meta name=\"description\"" nocase ascii
      $meta4 = "<meta name='description'" nocase ascii
      $meta5 = "<title>" nocase ascii

      // Kata kunci judi yang disuntikkan ke meta tag
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "bocoran rtp" nocase ascii
      $judol7 = "link slot gacor" nocase ascii
      $judol8 = "deposit pulsa" nocase ascii
      $judol9 = "casino online" nocase ascii
      $judol10 = "daftar slot" nocase ascii

   condition:
      filesize < 5MB and
      1 of ($meta*) and
      2 of ($judol*)
}


rule Judol_BlackSEO_WhiteText {
   meta:
      description = "Detects white-on-white text embed invisible gambling keywords in web pages, create content visible to search crawlers but invisible to human visitors"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 80
      tags = "JUDOL, BLACKSEO, WHITE_TEXT, CSS_HIDE"

   strings:
      // Pola warna teks = warna background
      $white1 = "color:#fff;background:#fff" ascii
      $white2 = "color: #fff; background: #fff" ascii
      $white3 = "color:white;background:white" nocase ascii
      $white4 = "color: white; background: white" nocase ascii
      $white5 = "color:#ffffff;background:#ffffff" nocase ascii
      $white6 = "color: #ffffff; background: #ffffff" nocase ascii
      $white7 = "color:#FFF;background-color:#FFF" ascii
      $white8 = "color: #FFF; background-color: #FFF" ascii

      // Konten judolnya
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "togel online" nocase ascii
      $judol4 = "situs judi" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "link slot" nocase ascii
      $judol7 = "deposit pulsa" nocase ascii

   condition:
      filesize < 5MB and
      1 of ($white*) and
      1 of ($judol*)
}


rule Judol_Htaccess_Redirect {
   meta:
      description = "Detects htaccess configuration files with RewriteRule redirecting to gambling domains or containing gambling patterns"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 85
      tags = "JUDOL, HTACCESS, REDIRECT"

   strings:
      // Apache mod_rewrite
      $apache1 = "RewriteEngine On" ascii
      $apache2 = "RewriteCond" ascii
      $apache3 = "RewriteRule" ascii
      $apache4 = "R=301" ascii
      $apache5 = "R=302" ascii
      $apache6 = "redirect 301" nocase ascii

      // Pola url domain judol
      $url1 = "slot" ascii
      $url2 = "togel" ascii
      $url3 = "judi" ascii
      $url4 = "gacor" ascii
      $url5 = "casino" ascii
      $url6 = "betting" ascii

      // Kata kunci judol
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii

   condition:
      filesize < 50KB and
      $apache1 and
      1 of ($apache2, $apache3) and
      1 of ($apache4, $apache5, $apache6) and
      (2 of ($url*) or 1 of ($judol*))
}


rule Judol_BlackSEO_Hidden_Iframe {
   meta:
      description = "Detects hidden iframes embedded in web pages, used to load gambling content invisibly"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 80
      tags = "JUDOL, BLACKSEO, HIDDEN_IFRAME"

   strings:
      // Hidden Iframe
      $iframe1 = "<iframe" nocase ascii
      $iframe_hide1 = "width=\"0\"" ascii
      $iframe_hide2 = "height=\"0\"" ascii
      $iframe_hide3 = "width=\"1\"" ascii
      $iframe_hide4 = "height=\"1\"" ascii
      $iframe_hide5 = "display:none" ascii
      $iframe_hide6 = "visibility:hidden" ascii

      // Konten judol dalam src iframe
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "casino online" nocase ascii

   condition:
      filesize < 5MB and
      $iframe1 and
      2 of ($iframe_hide*) and
      1 of ($judol*)
}


rule Judol_BlackSEO_AnchorText {
   meta:
      description = "Detects HTML anchor tags using gambling terms as anchor text"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 75
      tags = "JUDOL, BLACKSEO, ANCHOR_TEXT"

   strings:
      // Pola anchor text untuk kata kunci judolnya
      $a1 = /<a [^>]*href[^>]*>[\s\S]{0,50}slot gacor[\s\S]{0,50}<\/a>/ nocase
      $a2 = /<a [^>]*href[^>]*>[\s\S]{0,50}judi online[\s\S]{0,50}<\/a>/ nocase
      $a3 = /<a [^>]*href[^>]*>[\s\S]{0,50}situs judi[\s\S]{0,50}<\/a>/ nocase
      $a4 = /<a [^>]*href[^>]*>[\s\S]{0,50}togel online[\s\S]{0,50}<\/a>/ nocase
      $a5 = /<a [^>]*href[^>]*>[\s\S]{0,50}bandar togel[\s\S]{0,50}<\/a>/ nocase
      $a6 = /<a [^>]*href[^>]*>[\s\S]{0,50}bocoran rtp[\s\S]{0,50}<\/a>/ nocase
      $a7 = /<a [^>]*href[^>]*>[\s\S]{0,50}deposit pulsa[\s\S]{0,50}<\/a>/ nocase
      $a8 = /<a [^>]*href[^>]*>[\s\S]{0,50}link alternatif[\s\S]{0,50}<\/a>/ nocase
      $a9 = /<a [^>]*href[^>]*>[\s\S]{0,50}mahjong ways[\s\S]{0,50}<\/a>/ nocase
      $a10 = /<a [^>]*href[^>]*>[\s\S]{0,50}gates of olympus[\s\S]{0,50}<\/a>/ nocase
      $a11 = /<a [^>]*href[^>]*>[\s\S]{0,50}pola maxwin[\s\S]{0,50}<\/a>/ nocase

   condition:
      filesize < 10MB and 2 of ($a*)
}
