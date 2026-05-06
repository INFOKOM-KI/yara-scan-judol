/*
   Yara Rules - Deteksi PHP Backdoor Judi Online (Judol Backdoor)
   ================================================================
   Ruleset untuk mendeteksi PHP backdoor yang dirancang atau
   dimodifikasi untuk injeksi konten judi online (judol) ke website.

   Pola yang dicari:
   - Kode eksekusi PHP (eval/exec/system) dikombinasi dengan konten judol
   - Cloaking berbasis User Agent untuk menyembunyikan konten judolnya
   - Injeksi WordPress untuk manipulasi metadata
   - Script redirect PHP ke domain judolnya
   - Backdoor dengan parameter berbahaya

   Author   : Nauliajati <csirt@tangerangkota.go.id>
   Org      : TangerangKota-CSIRT
   Date     : 2026-05-06
   Version  : 1.0
   License  : TangerangKota-CSIRT Detection Rule License 1.0
   Reference: https://csirt.tangerangkota.go.id
*/


rule Judol_PHP_Eval_Inject {
   meta:
      description = "Detects php eval/base64 combined with gambling content"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 85
      tags = "JUDOL, BACKDOOR, PHP, EVAL, WEBSHELL"

   strings:
      // php shell
      $exec1 = "eval(base64_decode(" ascii
      $exec2 = "eval(gzinflate(" ascii
      $exec3 = "eval(str_rot13(" ascii
      $exec4 = "eval($_POST[" ascii
      $exec5 = "eval($_GET[" ascii
      $exec6 = "eval($_REQUEST[" ascii
      $exec7 = "eval($_COOKIE[" ascii
      $exec8 = "assert($_POST[" ascii
      $exec9 = "assert($_GET[" ascii
      $exec10 = "preg_replace('/.*/e'" ascii

      // Judolnya
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "daftar slot" nocase ascii
      $judol7 = "deposit pulsa" nocase ascii
      $judol8 = "link slot gacor" nocase ascii
      $judol9 = "mahjong ways" nocase ascii
      $judol10 = "pragmatic play" nocase ascii

   condition:
      filesize < 500KB and
      1 of ($exec*) and
      1 of ($judol*)
}


rule Judol_PHP_Cloaking_Bot {
   meta:
      description = "Detects php cloaking scripts that serve gambling content to search engine crawlers"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 90
      tags = "JUDOL, CLOAKING, BLACKSEO, PHP, BOT"

   strings:
      // Detek UA
      $ua1 = "HTTP_USER_AGENT" ascii
      $ua2 = "Googlebot" nocase ascii
      $ua3 = "Bingbot" nocase ascii
      $ua4 = "Yandex" nocase ascii
      $ua5 = "Yahoo! Slurp" ascii

      // Pola cloaking
      $flow1 = "strpos(" ascii
      $flow2 = "stripos(" ascii
      $flow3 = "strstr(" ascii

      // Judol crawler
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "link alternatif" nocase ascii
      $judol7 = "daftar slot" nocase ascii
      $judol8 = "deposit pulsa" nocase ascii
      $judol9 = "bocoran rtp" nocase ascii

      // redirect crawler
      $action1 = "header(" ascii
      $action2 = "Location:" ascii
      $action3 = "Moved Permanently" ascii
      $action4 = "301" ascii
      $action5 = "echo " ascii

   condition:
      filesize < 200KB and
      $ua1 and
      1 of ($ua2, $ua3, $ua4, $ua5) and
      1 of ($flow*) and
      1 of ($judol*) and
      1 of ($action*)
}


rule Judol_PHP_WP_OptionInject {
   meta:
      description = "Detects WordPress option manipulation used to inject gambling keywords into site metadata"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 90
      tags = "JUDOL, WORDPRESS, PHP, OPTION_INJECT, BLACKSEO"

   strings:
      // Fungsi WP
      $wp1 = "update_option(" ascii
      $wp2 = "add_option(" ascii
      $wp3 = "blogname" ascii
      $wp4 = "blogdescription" ascii
      $wp5 = "wp_insert_post" ascii
      $wp6 = "wp_update_post" ascii

      // Konten judol
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "slot online" nocase ascii
      $judol7 = "bocoran rtp" nocase ascii
      $judol8 = "deposit pulsa" nocase ascii
      $judol9 = "agen slot" nocase ascii
      $judol10 = "mahjong ways" nocase ascii
      $judol11 = "pragmatic play" nocase ascii

   condition:
      filesize < 300KB and
      1 of ($wp*) and
      1 of ($judol*)
}


rule Judol_PHP_Redirect_Domain {
   meta:
      description = "Detects php scripts that redirect visitors to gambling domains using header() call"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 80
      tags = "JUDOL, REDIRECT, PHP, BLACKSEO"

   strings:
      // Pola redirect php
      $redir1 = "header(\"Location:" ascii
      $redir2 = "header('Location:" ascii
      $redir3 = "header(\"HTTP/1.1 301" ascii
      $redir4 = "header('HTTP/1.1 301" ascii

      // Judol keywords
      $url1 = "slot" ascii
      $url2 = "togel" ascii
      $url3 = "judi" ascii
      $url4 = "gacor" ascii
      $url5 = "casino" ascii
      $url6 = "poker" ascii
      $url7 = "betting" ascii
      $url8 = "gambling" ascii

      // Indikator tambahan judol
      $ctx1 = "slot gacor" nocase ascii
      $ctx2 = "judi online" nocase ascii
      $ctx3 = "situs judi" nocase ascii
      $ctx4 = "link alternatif" nocase ascii
      $ctx5 = "bandar togel" nocase ascii

   condition:
      filesize < 100KB and
      1 of ($redir*) and
      (
         2 of ($url*) or
         1 of ($ctx*)
      )
}


rule Judol_PHP_Backdoor_Hidden_SEO {
   meta:
      description = "Detects php backdoors that generate hidden SEO content for gambling sites by fetching remote gambling link lists or embedding concealed html blocks"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 85
      tags = "JUDOL, BACKDOOR, PHP, HIDDEN_SEO, BLACKSEO"

   strings:
      // php function untuk fetch konten eksternal (ambil konten judol)
      $fetch1 = "file_get_contents(" ascii
      $fetch2 = "curl_exec(" ascii
      $fetch3 = "fopen(" ascii

      // Pola html yang dihasilkan backdoor
      $hide1 = "display:none" ascii
      $hide2 = "display: none" ascii
      $hide3 = "visibility:hidden" ascii
      $hide4 = "visibility: hidden" ascii
      $hide5 = "font-size:0" ascii
      $hide6 = "font-size: 0" ascii
      $hide7 = "opacity:0" ascii
      $hide8 = "color:#fff;background:#fff" ascii
      $hide9 = "color: #fff; background: #fff" ascii
      $hide10 = "overflow:hidden;height:0" ascii

      // Konten judol
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "link slot" nocase ascii
      $judol7 = "deposit pulsa" nocase ascii

   condition:
      filesize < 300KB and
      1 of ($fetch*) and
      1 of ($hide*) and
      1 of ($judol*)
}


rule Judol_PHP_Shell_Combo {
   meta:
      description = "Detects multi function php webshells that combine remote command execution capabilities"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 95
      tags = "JUDOL, WEBSHELL, PHP, RCE, BACKDOOR"

   strings:
      // RCE
      $rce1 = "system($_" ascii
      $rce2 = "exec($_" ascii
      $rce3 = "shell_exec($_" ascii
      $rce4 = "passthru($_" ascii
      $rce5 = "popen($_" ascii
      $rce6 = "proc_open($_" ascii

      // file management fetch content
      $fm1 = "move_uploaded_file(" ascii
      $fm2 = "file_put_contents($" ascii
      $fm3 = "fwrite($" ascii

      // Konten judolnya
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "link slot gacor" nocase ascii
      $judol7 = "bocoran rtp" nocase ascii
      $judol8 = "deposit pulsa" nocase ascii

   condition:
      filesize < 1MB and
      (1 of ($rce*) or 1 of ($fm*)) and
      1 of ($judol*)
}
