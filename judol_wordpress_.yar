/*
   Yara Rules - Deteksi Wordpress Compromise oleh Judi Online (Judol)
   =====================================================================
   WordPress (WP) adalah CMS populer yang paling banyak ditargetkan oleh pelaku judi online
   di Indonesia karena ekosistemnya yang luas dan banyaknya instalasi yang
   tidak terupdate.

   Pola yang dicakup:
   - Plugin palsu yang disisipkan untuk menyuntikkan konten judol
   - Modifikasi functions.php WordPress Themes
   - Manipulasi database wp_options untuk SEO judol
   - Penambahan user admin untuk persistent access
   - Modifikasi wp-config.php dengan kode backdoor
   - Upload file berbahaya melalui exploit media WP
   - Registrasi hook WordPress (add_action/add_filter) untuk injeksi konten judol

   Author   : NAuliajati <csirt@tangerangkota.go.id>
   Org      : TangerangKota-CSIRT
   Date     : 2026-05-06
   Version  : 1.0
   License  : TangerangKota-CSIRT Detection Rule License 1.0
   Reference: https://csirt.tangerangkota.go.id
*/


rule Judol_WP_FakePlugin {
   meta:
      description = "Detects fake WordPress plugins designed to inject gambling content"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 85
      tags = "JUDOL, WORDPRESS, FAKE_PLUGIN, BLACKSEO"

   strings:
      // Header plugin WordPress
      $wp_plugin1 = "Plugin Name:" ascii
      $wp_plugin2 = "Plugin URI:" ascii
      $wp_plugin3 = "Description:" ascii
      $wp_plugin4 = "Version:" ascii
      $wp_plugin5 = "Author:" ascii

      // Fungsi wp 
      $wp_func1 = "add_action(" ascii
      $wp_func2 = "add_filter(" ascii
      $wp_func3 = "wp_head" ascii
      $wp_func4 = "wp_footer" ascii
      $wp_func5 = "the_content" ascii
      $wp_func6 = "the_excerpt" ascii

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

   condition:
      filesize < 300KB and
      2 of ($wp_plugin*) and
      1 of ($wp_func*) and
      1 of ($judol*)
}


rule Judol_WP_ThemeInject {
   meta:
      description = "Detects WordPress theme files (functions.php, header.php, footer.php, etc.)"
      author = "NAuliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 80
      tags = "JUDOL, WORDPRESS, THEME_INJECT, BLACKSEO"

   strings:
      // WP Themes
      $theme1 = "get_header()" ascii
      $theme2 = "get_footer()" ascii
      $theme3 = "get_template_part(" ascii
      $theme4 = "wp_head()" ascii
      $theme5 = "wp_footer()" ascii
      $theme6 = "the_content()" ascii
      $theme7 = "get_stylesheet_directory" ascii
      $theme8 = "get_template_directory" ascii

      // Php Inject
      $inject1 = "eval(base64_decode(" ascii
      $inject2 = "eval(gzinflate(" ascii
      $inject3 = "file_get_contents(\"http" ascii
      $inject4 = "file_get_contents('http" ascii

      // Konten judol
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "bocoran rtp" nocase ascii
      $judol7 = "deposit pulsa" nocase ascii

   condition:
      filesize < 5MB and
      2 of ($theme*) and
      (1 of ($inject*) or 1 of ($judol*)) and
      (1 of ($inject*) and 1 of ($judol*))
}


rule Judol_WP_Action_Hook_Inject {
   meta:
      description = "Detects php code using WordPress action/filter hooks (add_action/add_filter) to inject gambling content into page output dynamic"
      author = "Nauliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 85
      tags = "JUDOL, WORDPRESS, HOOK_INJECT, BLACKSEO, PHP"

   strings:
      // Hook WordPress
      $hook1 = "add_action('wp_head'" ascii
      $hook2 = "add_action(\"wp_head\"" ascii
      $hook3 = "add_action('wp_footer'" ascii
      $hook4 = "add_action(\"wp_footer\"" ascii
      $hook5 = "add_action('init'" ascii
      $hook6 = "add_action(\"init\"" ascii
      $hook7 = "add_filter('the_content'" ascii
      $hook8 = "add_filter(\"the_content\"" ascii
      $hook9 = "add_filter('the_title'" ascii
      $hook10 = "add_filter(\"the_title\"" ascii

      // Konten judol
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "link slot" nocase ascii
      $judol7 = "bocoran rtp" nocase ascii
      $judol8 = "deposit pulsa" nocase ascii
      $judol9 = "agen slot" nocase ascii
      $judol10 = "mahjong ways" nocase ascii

   condition:
      filesize < 300KB and
      1 of ($hook*) and
      1 of ($judol*)
}


rule Judol_WP_PostDB_Inject {
   meta:
      description = "Detects php scripts that directly manipulate WordPress post/option database to massive injection"
      author = "NAuliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 85
      tags = "JUDOL, WORDPRESS, DATABASE_INJECT, BLACKSEO"

   strings:
      // Fungsi WP untuk memanipulasi post/database
      $db1 = "wp_insert_post(" ascii
      $db2 = "wp_update_post(" ascii
      $db3 = "wp_delete_post(" ascii
      $db4 = "update_option(" ascii
      $db5 = "delete_option(" ascii
      $db6 = "wpdb->query(" ascii
      $db7 = "wpdb->update(" ascii
      $db8 = "wpdb->insert(" ascii

      // Konten judolnya
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "bocoran rtp" nocase ascii
      $judol7 = "link slot gacor" nocase ascii
      $judol8 = "deposit pulsa" nocase ascii
      $judol9 = "mahjong ways" nocase ascii
      $judol10 = "pragmatic play" nocase ascii

   condition:
      filesize < 500KB and
      1 of ($db*) and
      1 of ($judol*)
}


rule Judol_WP_Admin_Backdoor {
   meta:
      description = "Detects php scripts that create hidden WordPress administrator accounts for persistent access"
      author = "NAuliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 90
      tags = "JUDOL, WORDPRESS, ADMIN_BACKDOOR, PERSISTENCE"

   strings:
      // WP add users
      $user1 = "wp_create_user(" ascii
      $user2 = "wp_insert_user(" ascii
      $user3 = "add_user_to_blog(" ascii
      $user4 = "wp_set_password(" ascii

      // role admin
      $role1 = "administrator" ascii
      $role2 = "promote_user(" ascii
      $role3 = "'role' => 'administrator'" ascii
      $role4 = "\"role\" => \"administrator\"" ascii

      // Judolnya
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii

   condition:
      filesize < 200KB and
      1 of ($user*) and
      1 of ($role*) and
      1 of ($judol*)
}


rule Judol_WP_Cloaking_Bypass {
   meta:
      description = "Detects WordPress cloaking that show gambling content to search engine crawlers"
      author = "NAuliajati <csirt@tangerangkota.go.id>"
      reference = "https://csirt.tangerangkota.go.id"
      date = "2026-05-06"
      score = 85
      tags = "JUDOL, WORDPRESS, CLOAKING, BLACKSEO"

   strings:
      // WordPress users tags
      $wp_check1 = "is_user_logged_in()" ascii
      $wp_check2 = "is_admin()" ascii
      $wp_check3 = "current_user_can(" ascii
      $wp_check4 = "is_front_page()" ascii

      // User-Agent check
      $ua1 = "HTTP_USER_AGENT" ascii
      $ua2 = "Googlebot" nocase ascii
      $ua3 = "Bingbot" nocase ascii

      // Konten judolnya
      $judol1 = "slot gacor" nocase ascii
      $judol2 = "judi online" nocase ascii
      $judol3 = "situs judi" nocase ascii
      $judol4 = "togel online" nocase ascii
      $judol5 = "bandar togel" nocase ascii
      $judol6 = "bocoran rtp" nocase ascii
      $judol7 = "link slot" nocase ascii
      $judol8 = "mahjong ways" nocase ascii

   condition:
      filesize < 500KB and
      (1 of ($wp_check*) or ($ua1 and 1 of ($ua2, $ua3))) and
      1 of ($judol*)
}
