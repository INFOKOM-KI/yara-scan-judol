/*
   Yara Rules - Deteksi Inject JavaScript untuk Judi Online (Judol)
   ===========================================================
   Ruleset untuk mendeteksi JavaScript (JS) yang digunakan dalam serangan judi
   online, termasuk redirect berbasis JS, konten judol yang tersembunyi, cloaking seo
   berbasis user agent, dan exfiltration data ke server judol.

   Pola yang dicakup:
   - Redirect JavaScript ke domain judol (window.location, document.location)
   - Generate konten HTML judol via document.write atau innerHTML
   - Cloaking lewat element navigator.userAgent
   - Script yang memuat konten eksternal dari server C2 judolnya
   - JS Obfuscated dengan payload
   - Inject script tag ke halaman website

   Author   : Nauliajati <csirt@tangerangkota.go.id>
   Org      : TangerangKota-CSIRT
   Date     : 2026-05-06
   Version  : 1.0
   License  : TangerangKota-CSIRT Detection Rule License 1.0
   Reference: https://csirt.tangerangkota.go.id
*/


rule Judol_JS_Redirect {
   meta:
      description = "Detects JavaScript redirect"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 80
      tags = "JUDOL, JAVASCRIPT, REDIRECT, BLACKSEO"

   strings:
      // Element redirect
      $redir1 = "window.location.href" ascii
      $redir2 = "window.location.replace(" ascii
      $redir3 = "window.location =" ascii
      $redir4 = "document.location.href" ascii
      $redir5 = "document.location.replace(" ascii
      $redir6 = "top.location.href" ascii

      // Kata kunci judol dalam URL
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "link alternatif" nocase ascii
      $judol7 = "deposit pulsa" nocase ascii
      $judol8 = "bocoran rtp" nocase ascii
      $judol9 = "daftar slot" nocase ascii

      // Kata dalam URL judol
      $url1 = "slot" ascii
      $url2 = "togel" ascii
      $url3 = "judi" ascii
      $url4 = "gacor" ascii
      $url5 = "casino" ascii

   condition:
      filesize < 5MB and
      1 of ($redir*) and
      (1 of ($judol*) or 2 of ($url*))
}


rule Judol_JS_ContentGen {
   meta:
      description = "Detects JavaScript code that dynamically generates and injects gambling content into web pages"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 80
      tags = "JUDOL, JAVASCRIPT, CONTENT_INJECT, BLACKSEO"

   strings:
      // JS Element Inject
      $write1 = "document.write(" ascii
      $write2 = "document.writeln(" ascii
      $write3 = ".innerHTML" ascii
      $write4 = ".insertAdjacentHTML(" ascii
      $write5 = "createElement(" ascii
      $write6 = "appendChild(" ascii
      $write7 = "textContent" ascii

      // Konten judol
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "link slot" nocase ascii
      $judol7 = "bocoran rtp" nocase ascii
      $judol8 = "deposit pulsa" nocase ascii
      $judol9 = "mahjong ways" nocase ascii
      $judol10 = "pragmatic play" nocase ascii
      $judol11 = "maxwin" nocase ascii

   condition:
      filesize < 5MB and
      1 of ($write*) and
      1 of ($judol*)
}


rule Judol_JS_Cloaking_UA {
   meta:
      description = "Detects JavaScript cloaking that checks navigator.userAgent to serve gambling content specifically to search engine bot"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 90
      tags = "JUDOL, JAVASCRIPT, CLOAKING, BLACKSEO, BOT"

   strings:
      // Cek User Agent via JS
      $ua1 = "navigator.userAgent" ascii

      // bot search engine
      $bot1 = "Googlebot" nocase ascii
      $bot2 = "bingbot" nocase ascii
      $bot3 = "YandexBot" nocase ascii
      $bot4 = "Baiduspider" nocase ascii
      $bot5 = "DuckDuckBot" nocase ascii

      // Konten judol
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "link slot gacor" nocase ascii
      $judol7 = "bocoran rtp" nocase ascii
      $judol8 = "deposit pulsa" nocase ascii
      $judol9 = "maxwin" nocase ascii
      $judol10 = "pola maxwin" nocase ascii

   condition:
      filesize < 2MB and
      $ua1 and
      1 of ($bot*) and
      1 of ($judol*)
}


rule Judol_JS_RemoteLoad {
   meta:
      description = "Detects JavaScript code that fetches gambling content from remote servers (C2) and injects it into compromised web pages"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 80
      tags = "JUDOL, JAVASCRIPT, REMOTE_LOAD, C2, BLACKSEO"

   strings:
      // JS untuk memuat konten dari server C2
      $fetch1 = "fetch(" ascii
      $fetch2 = "XMLHttpRequest" ascii
      $fetch3 = "jQuery.ajax(" ascii
      $fetch4 = "$.ajax(" ascii
      $fetch5 = "$.get(" ascii
      $fetch6 = "$.post(" ascii
      $fetch7 = "axios.get(" ascii
      $fetch8 = "axios.post(" ascii

      // Inject tag script
      $script1 = "createElement('script')" ascii
      $script2 = "createElement(\"script\")" ascii

      // Konten judolnya
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "bocoran rtp" nocase ascii
      $judol7 = "link slot" nocase ascii
      $judol8 = "deposit pulsa" nocase ascii
      $judol9 = "maxwin" nocase ascii

   condition:
      filesize < 2MB and
      (1 of ($fetch*) or 1 of ($script*)) and
      1 of ($judol*)
}


rule Judol_JS_Obfuscated_Payload {
   meta:
      description = "Detects obfuscated JavaScript"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 75
      tags = "JUDOL, JAVASCRIPT, OBFUSCATED, BLACKSEO"

   strings:
      // Obfuscated JS
      $obf1 = "atob(" ascii
      $obf2 = "btoa(" ascii
      $obf3 = "fromCharCode(" ascii
      $obf4 = "eval(atob(" ascii
      $obf5 = "eval(unescape(" ascii
      $obf6 = "unescape(" ascii
      $obf7 = "decodeURIComponent(" ascii
      $obf8 = "_0x" ascii

      // Judol Keywords
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "bocoran rtp" nocase ascii
      $judol7 = "link slot gacor" nocase ascii
      $judol8 = "deposit pulsa" nocase ascii
      $judol9 = "maxwin" nocase ascii

   condition:
      filesize < 5MB and
      2 of ($obf*) and
      1 of ($judol*)
}
