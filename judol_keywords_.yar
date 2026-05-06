/*
   Yara - Deteksi Judi Online (Judol)
   ============================================================
   Rules ini digunakan untuk mendeteksi konten judi online yang banyak menarget pengguna internet di Indonesia.
   Mencakup halaman sebuah situs judi dan konten yang disuntikan kedalam website -
   korban melalui kampanye Black SEO. Dikategorikan berdasarkan jenis permainan:
   slot online, togel, kasino langsung, dan penyedia game judi.

   Author   : Nauliajati <csirt@tangerangkota.go.id>
   Org      : TangerangKota-CSIRT
   Date     : 2026-05-06
   Version  : 1.0
   License  : TangerangKota-CSIRT Detection Rule License 1.0
   Reference: https://csirt.tangerangkota.go.id
*/


rule Judol_1 {
   meta:
      description = "Detects web content slot gambling keywords, gambling pages or Black SEO injection"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 70
      tags = "JUDOL, SLOT, BLACKSEO"

   strings:
      // Keyword Slot
      $slot1 = "slot gacor" nocase ascii
      $slot2 = "bocoran rtp" nocase ascii
      $slot3 = "link slot gacor" nocase ascii
      $slot4 = "gacor hari ini" nocase ascii
      $slot5 = "slot maxwin" nocase ascii
      $slot6 = "pola slot" nocase ascii
      $slot7 = "rtp live" nocase ascii
      $slot8 = "slot online" nocase ascii
      $slot9 = "daftar slot" nocase ascii
      $slot10 = "agen slot" nocase ascii
      $slot11 = "situs slot" nocase ascii
      $slot12 = "link slot" nocase ascii
      $slot13 = "bocoran slot" nocase ascii
      $slot14 = "info slot" nocase ascii
      $slot15 = "slot777" nocase ascii
      $slot16 = "slot88" nocase ascii
      $slot17 = "jp slot" nocase ascii

   condition:
      filesize < 5MB and 4 of ($slot*)
}


rule Judol_2 {
   meta:
      description = "Detects web content containing illegal lottery (togel), gambling keywords, Black SEO campaigns, and active gambling sites"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 75
      tags = "JUDOL, TOGEL, BLACKSEO"

   strings:
      // Togel Keywords
      $togel1 = "bandar togel" nocase ascii
      $togel2 = "togel online" nocase ascii
      $togel3 = "prediksi togel" nocase ascii
      $togel4 = "pasang togel" nocase ascii
      $togel5 = "angka main togel" nocase ascii
      $togel6 = "keluaran togel" nocase ascii
      $togel7 = "data sgp" nocase ascii
      $togel8 = "data hk" nocase ascii
      $togel9 = "togel sgp" nocase ascii
      $togel10 = "togel hk" nocase ascii
      $togel11 = "togel sdy" nocase ascii
      $togel12 = "keluaran hk" nocase ascii
      $togel13 = "pengeluaran sgp" nocase ascii
      $togel14 = "angka jitu" nocase ascii
      $togel15 = "buku mimpi" nocase ascii

   condition:
      filesize < 5MB and 2 of ($togel*)
}


rule Judol_3 {
   meta:
      description = "Detects web content with online casino and poker gambling keywords, found in SEO-injected content, and active gambling portals"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 65
      tags = "JUDOL, CASINO, POKER, BLACKSEO"

   strings:
      $casino1 = "casino online" nocase ascii
      $casino2 = "live casino" nocase ascii
      $casino3 = "baccarat online" nocase ascii
      $casino4 = "roulette online" nocase ascii
      $casino5 = "agen casino" nocase ascii
      $casino6 = "judi bola" nocase ascii
      $casino7 = "sbobet" nocase ascii
      $casino8 = "judi online" nocase ascii
      $casino9 = "taruhan bola" nocase ascii
      $casino10 = "poker online" nocase ascii
      $casino11 = "domino online" nocase ascii
      $casino12 = "capsa susun" nocase ascii
      $casino13 = "situs judi" nocase ascii
      $casino14 = "agen judi" nocase ascii
      $casino15 = "daftar judi" nocase ascii

   condition:
      filesize < 5MB and 3 of ($casino*)
}


rule Judol_4 {
   meta:
      description = "Detects references well known gambling game providers, combined with gambling action terms, indicating gambling site content or SEO injection"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 60
      tags = "JUDOL, SLOT, PROVIDER"

   strings:
      // Penyedia game judi online
      $provider1 = "pragmatic play" nocase ascii
      $provider2 = "pg soft" nocase ascii
      $provider3 = "habanero" nocase ascii
      $provider4 = "joker gaming" nocase ascii
      $provider5 = "spadegaming" nocase ascii
      $provider6 = "microgaming" nocase ascii
      $provider7 = "playtech" nocase ascii
      $provider8 = "rtg slots" nocase ascii
      $provider9 = "cq9 gaming" nocase ascii

      // Nama game judi populer
      $game1 = "mahjong ways" nocase ascii
      $game2 = "gates of olympus" nocase ascii
      $game3 = "sweet bonanza" nocase ascii
      $game4 = "starlight princess" nocase ascii
      $game5 = "wild west gold" nocase ascii
      $game6 = "the dog house" nocase ascii
      $game7 = "aztec gems" nocase ascii
      $game8 = "zeus slot" nocase ascii
      $game9 = "lucky neko" nocase ascii
      $game10 = "koi gate" nocase ascii

      // Konteks judi online
      $action1 = "daftar" nocase ascii
      $action2 = "deposit" nocase ascii
      $action3 = "link alternatif" nocase ascii
      $action4 = "login" nocase ascii
      $action5 = "winrate" nocase ascii

   condition:
      filesize < 5MB and
      2 of ($provider*, $game*) and
      1 of ($action*)
}


rule Judol_5 {
   meta:
      description = "Detects gambling deposit methods and promotional offers in online gambling operations"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 75
      tags = "JUDOL, DEPOSIT, PROMO"

   strings:
      // Depo judi online
      $deposit1 = "deposit pulsa" nocase ascii
      $deposit2 = "deposit dana" nocase ascii
      $deposit3 = "deposit gopay" nocase ascii
      $deposit4 = "deposit ovo" nocase ascii
      $deposit5 = "deposit linkaja" nocase ascii
      $deposit6 = "tanpa potongan" nocase ascii

      // Promosi situs judi
      $promo1 = "bonus new member" nocase ascii
      $promo2 = "cashback slot" nocase ascii
      $promo3 = "rollingan" nocase ascii
      $promo4 = "turnover" nocase ascii
      $promo5 = "withdraw cepat" nocase ascii
      $promo6 = "bonus referral" nocase ascii
      $promo7 = "freebet" nocase ascii
      $promo8 = "freespin" nocase ascii
      $promo9 = "jackpot terbesar" nocase ascii

   condition:
      filesize < 5MB and 2 of ($deposit*, $promo*)
}


rule Judol_6 {
   meta:
      description = "Detects keyword stuffing gambling terms in small files, Black SEO content injection on compromised websites"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 80
      tags = "JUDOL, BLACKSEO, KEYWORD_STUFFING"

   strings:
      $k1 = "slot gacor" nocase ascii
      $k2 = "togel online" nocase ascii
      $k3 = "judi online" nocase ascii
      $k4 = "situs judi" nocase ascii
      $k5 = "bandar togel" nocase ascii
      $k6 = "agen slot" nocase ascii
      $k7 = "deposit pulsa" nocase ascii
      $k8 = "bocoran rtp" nocase ascii
      $k9 = "link alternatif" nocase ascii
      $k10 = "daftar slot" nocase ascii
      $k11 = "pragmatic play" nocase ascii
      $k12 = "mahjong ways" nocase ascii

   condition:
      filesize < 100KB and 6 of ($k*)
}
