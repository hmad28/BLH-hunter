# Peringatan!: Dilarang Keras Mengubah File ini!

# BLH Hunter Rules

File ini adalah kontrak perilaku scanner. Kalau implementasi, README, UI, atau test bertentangan dengan file ini, `rules.md` yang menang.

## Scope Scan

1. Scan domain root berarti termasuk semua subdomain di bawah domain itu.
2. Contoh: scan `nasa.gov` mencakup `www.nasa.gov`, `science.nasa.gov`, `oig.nasa.gov`, `www.jpl.nasa.gov`, dan host lain yang berakhir dengan `.nasa.gov`.
3. URL di luar root domain tidak boleh dicrawl sebagai source page.
4. Link platform target seperti `x.com/NASA` boleh dicek sebagai target, tapi halaman platform itu tidak boleh ikut dicrawl sebagai source page.

## Dedupe Target

1. Tidak boleh ada duplikat link target dalam satu sesi scan.
2. Tidak boleh ada duplikat link target antar sesi scan selama target itu masih tercatat di database.
3. Canonical target dipakai untuk dedupe. Contoh `https://www.twitter.com/NASA/` dan `https://twitter.com/NASA` dianggap target yang sama.
4. Kalau target sudah pernah masuk `results`, scan berikutnya harus skip target itu dan lanjut cari target lain.
5. Target yang di-skip karena sudah pernah ditemukan harus dihitung/log sebagai `already_seen_targets`.

## Dedupe Source URL

1. Source URL dedupe dihitung per root domain dan per coverage platform yang dipilih.
2. Source URL yang sudah dicrawl untuk `instagram` tidak boleh membuat scan `facebook` melewati URL itu.
3. Untuk scan multi-platform, source URL baru boleh di-skip hanya kalau sudah pernah dicrawl untuk semua platform yang dipilih. Contoh: source yang baru covered `facebook` tetap harus dicrawl saat scan `facebook + instagram`.
4. Semua source URL yang dicoba harus dicatat, termasuk halaman yang tidak punya target, non-HTML, error, timeout, blocked, atau redirect.
5. Canonical source URL dipakai untuk dedupe. Fragment dihapus, scheme/host dinormalisasi, trailing slash path dirapikan.
6. Source URL yang sudah covered untuk platform terpilih harus di-skip dari queue dan dihitung/log sebagai `source URLs skipped as already crawled`.
7. Budget `MAX_CRAWLED_PAGES` hanya menghitung source URL baru yang benar-benar dicrawl di sesi berjalan.

## Delete Scan

1. Tombol delete per scan berarti semua data milik scan itu dihapus permanen dari database.
2. Delete scan wajib menghapus row terkait dari `scans`, `results`, `scan_log`, dan crawl history per scan seperti `crawl_pages`.
3. Setelah scan di-delete, app tidak boleh diam-diam menyimpan history scan itu di tabel lain untuk dedupe.
4. Konsekuensi: kalau scan di-delete permanen, app sudah lupa source URL dan target dari scan itu. Scan berikutnya boleh menemukan atau mencrawl URL yang sama lagi karena data dedupe-nya memang sudah dihapus.
5. Kalau nanti dibutuhkan dedupe selamanya walau scan di-delete, itu harus jadi fitur terpisah seperti `global_blocklist`, bukan behavior delete scan.

## Bentuk Link Target Valid

1. Link akun target harus berupa URL profile/account langsung: `platform/akun_target`.
2. Link target tidak boleh punya query parameter.
3. Link target tidak boleh punya fragment.
4. Link target tidak boleh punya path lanjutan setelah akun.
5. Contoh valid: `https://x.com/NASA`, `https://instagram.com/nasa`, `https://github.com/nasa`.
6. Contoh tidak valid: `https://x.com/intent/tweet?...`, `https://x.com/NASA/status/123`, `https://youtube.com/watch?v=abc`, `https://facebook.com/sharer.php?...`.

## Crawl Strategy

1. Crawler harus menjelajahi domain dan subdomain secara merata.
2. Seed URL harus dikelompokkan per hostname lalu diproses round-robin antar host.
3. Host yang punya banyak URL seperti `www.nasa.gov` tidak boleh menghabiskan seluruh crawl budget sebelum host lain kebagian.
4. Seed dari sitemap, robots sitemap, Wayback, CommonCrawl, dan internal links harus tetap masuk scope/dedupe yang sama.
5. Discovery subdomain harus mengambil host unik dari seed yang ditemukan, bukan cuma mengandalkan daftar subdomain hard-coded.

## Logging

1. Log harus membantu memahami scan, bukan membanjiri output dengan URL filter yang sama.
2. Progress crawl harus menampilkan minimal: visited baru, skipped source yang sudah covered untuk platform terpilih, skipped target total, `already_seen_targets`, `duplicate_targets_in_scan`, jumlah target baru, platform/account hits, dan jumlah host yang sudah dicrawl.
3. Log host summary harus menampilkan host paling dominan dari seed/crawl, misalnya `Seed hosts: www.nasa.gov=300, science.nasa.gov=120`.
4. `[filter]` detail boleh ada sebagai sample, tapi harus dibatasi dan tidak muncul ribuan kali untuk share button yang sama.

## Result Semantics

1. `results` hanya berisi target baru yang belum pernah tercatat di database aktif.
2. Status check target boleh memakai cache dari target yang masih ada di database.
3. Scan yang selesai dengan `0` result bukan berarti crawler gagal, kalau log menunjukkan semua kandidat sudah pernah ditemukan atau tidak valid.
4. UI harus membedakan `0 target found`, `all targets already seen`, dan `no valid platform links found`.
