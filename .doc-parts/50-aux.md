# Вспомогательные подсистемы: классификация трафика, WireGuard-туннели, архивация, Telegram-отчётность, форматирование времени

Файлы: `src/classify.rs`, `src/wg.rs`, `src/arch.rs`, `src/tg.rs`, `src/timefmt.rs`. Все — модули бинарника `afeye` (объявлены в `src/main.rs:1-15` как `mod classify; mod wg; mod arch; mod tg; mod timefmt;` и др.). В `src/lib.rs` их НЕТ (там только `bctrace`, `collect`, `events`, `sinkfilter`) — значит в интеграционные тесты `tests/` они напрямую недоступны, только через unit-тесты внутри файлов.

---

## src/classify.rs — пост-обработчик stage-дерева: классифицирует сетевые эндпоинты каждого сайта как antifraud/garbage/neutral, вырезает мусор из timeline, раскладывает артефакты по вендорам, пишет classification.json

### use (строки 1-6)
- `crate::ctx::{endpoint_of, host_of, vendor_of_url}` — нормализация URL и определение вендора антифрода (таблица `VENDORS` в ctx.rs:9-38: cloudflare, datadome, kasada, human, akamai, fpjs, seon, arkose, hcaptcha, recaptcha, imperva, threatmetrix, iovation, shape).
- `serde_json::Value` — разбор строк timeline.jsonl.
- `std::collections::{HashMap, HashSet}`, `std::fs::{File, OpenOptions}`, `std::io::{BufRead, BufReader, Write}`, `std::sync::atomic::{AtomicUsize, Ordering}`.

### pub struct ClsOut (строки 8-17)
- назначение: сводная статистика прогона классификатора, возвращается из `run`/`strict`.
- поля: `af: u64` — число эндпоинтов с вердиктом antifraud; `garbage: u64` — эндпоинты-мусор; `neutral: u64` — нейтральные; `scripts: u64` — число «грязных» (tainted) скриптов; `kept: u64` — строк timeline оставлено; `dup: u64` — дублей net:send удалено; `art_rm: u64` — файлов артефактов удалено; `bytes_rm: u64` — байт при этом удалено.
- связи: main.rs:600-611 печатает все поля в лог и кладёт в manifest.json (main.rs:704-711, поля `cls_af`…`cls_bytes_rm`); tg.rs:129-141 кладёт `af/garbage/kept` в telegram-событие `sent`.

### const STRONG: &[&str] (строки 19-37)
- назначение: «сильные» теги фингерпринтинга — API, которые почти всегда означают сбор отпечатка.
- что внутри (16 штук): `toDataURL`, `toBlob`, `getImageData`, `getParameter`, `getExtension`, `getSupportedExtensions`, `getShaderPrecisionFormat`, `getFloatFrequencyData`, `startRendering`, `convertToBlob`, `new:OffscreenCanvas`, `new:OfflineAudioContext`, `sab`, `wmem:new`, `call:eval`, `new:Function`, `shaderSource` (фактически 17 записей).
- связи: теги приходят из inject-скрипта (`src/inject.rs:25` — `ST(tag)` эмитит `stk:<tag>`); классифицируются в `tag_class` (582-590).

### const WEAK: &[&str] (строки 39-55)
- назначение: «слабые» теги — доступ к свойствам, который может быть и легитимным.
- что внутри (14 штук): `g:plugins`, `g:mimeTypes`, `g:hardwareConcurrency`, `g:deviceMemory`, `g:platform`, `g:languages`, `g:userAgent`, `g:width`, `g:height`, `g:colorDepth`, `Math.random`, `new:AudioContext`, `po:new`, `wasm:instantiate`, `getContext` (15 записей).
- связи: `tag_class` (582-590) — WEAK и всё с префиксом `g:` даёт класс 1.

### const BLACKLIST: &[&str] (строки 57-109)
- назначение: хосты известной аналитики/рекламы/видео — трафик на них помечается garbage и вырезается из timeline.
- что внутри (52 записи): google-analytics.com, googletagmanager.com, doubleclick.net, googleadservices.com, adservice.google.com, hotjar.com, sentry.io, ingest.sentry.io, amplitude.com, mixpanel.com, segment.io, segment.com, clarity.ms, mc.yandex.ru, an.yandex.ru, scorecardresearch.com, quantserve.com, quantcount.com, casalemedia.com, rubiconproject.com, pubmatic.com, criteo.com, criteo.net, adnxs.com, adsrvr.org, taboola.com, outbrain.com, demdex.net, everesttech.net, omtrdc.net, 2o7.net, pixel.facebook.com, analytics.tiktok.com, bat.bing.com, alb.reddit.com, pixel.reddit.com, fonts.googleapis.com, fonts.gstatic.com, cloudflareinsights.com, rum.aliyuncs.com, log.aliyuncs.com, play.google.com, pixel-config.reddit.com, ads-twitter.com, analytics.twitter.com, app-measurement.com, analytics.google.com, youtube.com, youtube-nocookie.com, ytimg.com, video.google.com.
- связи: `blacklisted` (347-349) — точное совпадение ИЛИ суффикс с точкой перед ним (поддомены). Замечание: `challenges.cloudflare.com` НЕ в блэклисте (вендор антифрода, не мусор) — это проверяет тест `blacklist_hosts` (1415-1425).

### const COOKIE_SIGS: &[&str] (строки 111-123)
- назначение: подстроки в Set-Cookie, выдающие антифрод-вендора.
- что внутри (11): `datadome`, `_dd_s`, `_abck`, `bm_sz`, `ak_bmsc` (Akamai), `cf_clearance`, `__cf_bm`, `_cfuvid` (Cloudflare), `pxhd`, `pxcd` (PerimeterX/HUMAN), `kasada`.
- связи: `verdict_site` (680-687) — совпадение (регистронезависимо) добавляет af-причину `cookie:<sig>`.

### const BLACKLIST_PATH: &[(&str, &str)] (строки 125-131)
- назначение: блэклист по паре «хост + префикс пути» для www.google.com.
- что внутри (5 пар): `/g/collect`, `/measurement`, `/ccm/`, `/pagead/`, `/log?`.
- связи: `blacklisted_path` (351-361).

### const RES_TYPES: &[&str] (строка 133)
- `["Image", "Font", "Stylesheet", "Media", "Manifest", "Favicon"]` — типы ресурсов CDP (`d.ty` в k=1), кандидатов на «мусор», если содержимое совпадает с заявленным типом.
- связи: `verdict_site` (655-671).

### #[derive(PartialEq, Clone, Copy)] pub enum Mode (строки 135-139)
- `Main` — основной фильтр: оставляет всё, кроме вердикта garbage (vd==2).
- `Strict` — строгий: оставляет только вердикт antifraud (vd==1).
- связи: `run` → `Mode::Main` (1147-1149), `strict` → `Mode::Strict` (1151-1153); сравнения в `line_keep` (795-862) и в `run_mode` при чистке артефактов.

### fn res_family(ty: &str) -> u8 (строки 141-149)
- Image|Favicon→1, Media→2, Font→3, Stylesheet|Manifest→4, прочее→0.
- связи: используется в `verdict_site` (sniff-проверка «маскировки») и в `process_site` (art_v кортеж).

### fn binary_magic(b: &[u8]) -> u8 (строки 151-175)
- назначение: определение реальной природы файла по magic-байтам.
- что внутри: возвращает 1 (изображение) для PNG `89 50 4E 47`, JPEG `FF D8 FF`, `GIF8`, `BM`, RIFF+WEBP, MPEG-TS (`00 00 01 00`); 2 (аудио/видео) для `ID3`, MPEG-frame sync `FF E0..`, `OggS`, `fLaC`, RIFF+WAVE, RIFF+AVI, `ftyp` (MP4 по байтам 4-8); 3 (шрифт) для `wOFF`, `wOF2`, `OTTO`, TrueType (`00 01 00 00`); иначе 0.
- связи: `res_sniff_ok` (211-220); тест `sniff_families` (1427-1445) проверяет в т.ч. что WASM-магия `\0asm` НЕ опознаётся как картинка (возвращает 0).

### fn textish(b: &[u8]) -> bool (строки 177-189)
- первые min(len,4096) байт; «текстовый» если ≥90% байт — печатаемые ASCII (32..127), `\n`, `\r`, `\t` или ≥0x80. Пустой срез → false.
- связи: `res_sniff_ok` для family 4 (CSS/Manifest).

### fn js_like(b: &[u8]) -> bool (строки 191-209)
- по первым 4096 байтам (lowercase через `String::from_utf8_lossy`) ищет подстроки: `function`, `=>`, `eval(`, `document.`, `window.`, `atob(`, `fromcharcode`, `new function`.
- назначение: детектор «JS, замаскированный под CSS/картинку».

### fn res_sniff_ok(b: &[u8], fam: u8) -> bool (строки 211-220)
- пустой буфер → true (нет данных — не наказываем). fam 1..=3 → `binary_magic(b)==fam`; fam 4 → `textish(b) && !js_like(b)`; иначе true.
- связи: `verdict_site` (657-663) — если ресурс заявлен как Image, а sniff НЕ совпал → af-причина `masked:<ty>` (JS под картинкой = маскировка антифрода); `run_mode` (1247-1262) — «настоящий» мусорный медиа-файл удаляется в Main-режиме.

### fn read_head(p: &Path, n: usize) -> Vec<u8> (строки 222-232)
- читает первые n байт файла; ошибка → пустой Vec.

### const KEEP_PREFIXES: &[&str] (строки 234-237)
- назначение: kk-события (инжект-телеметрия), которые ВСЕГДА переживают фильтрацию.
- что внутри (18): `stk:`, `src:`, `wasm`, `wmem:`, `sab`, `po:`, `_boot`, `_th`, `_c`, `_m`, `_dr`, `new:`, `call:`, `listen`, `setattr:`, `slow:`, `mq:`, `worker:src`, `gl:shader` (19 записей).
- связи: `line_keep` (796-799).

### fn is_del(c: u8) -> bool (строки 239-245)
- «разделители токенов»: `" ' , : ; = & { } [ ] ( ) < > ? / \ + | * # %`.
- связи: `body_taint_hits` — зеркалит `DEL`/`DLM` из inject.rs:27-28 (та же таблица в JS), чтобы FNV-хеши токенов совпадали между JS-стороной и Rust-стороной.

### pub fn fnv32(b: &[u8]) -> u32 (строки 247-254)
- FNV-1a 32: `h=0x811c9dc5; h^=c; h*=16777619` (wrapping).
- связи: идентичен `FNV()` из inject.rs:29 — т.е. хеши `_th`-пула (созданные в браузере) совпадают с `fnv32` от тех же токенов в Rust. Используется в `body_taint_hits` и в дедупликации `filter_file` (762-766).

### #[cfg(test)] fn fnv32_units(s: &str) -> u32 (строки 256-269)
- эталонная реализация по UTF-16 code units (как JS `charCodeAt`): хеширует младшие 16 бит, при `u>0xffff` доворачивает старшие. Нужна, чтобы доказать совпадение с байтовой версией на ASCII.

### #[cfg(test)] fn ascii_units_parity(s: &str) -> bool (строки 271-274)
- `fnv32(s.as_bytes()) == fnv32_units(s)`.

### fn body_taint_hits(b: &[u8], taint: &HashSet<u32>) -> usize (строки 276-295)
- назначение: считает, сколько токенов из taint-пула встречается в теле POST-запроса.
- что внутри: идёт по первым min(len,4096) байтам + виртуальный завершающий пробел; накапливает FNV-1a по «токенам» (символы >32, <127, не `is_del`); на разделителе, если длина токена ≥3 и хеш есть в `taint` — счётчик +1; хеш сбрасывается в `0x811c9dc5`. Возвращает число попаданий.
- связи: алгоритм байт-в-байт повторяет `TCT()` из inject.rs:33 (там лимит 4096 тот же, разделители те же). `verdict_site` (688-699) — hits>0 → af-причина `taint-body:<hits>`.

### pub fn entropy(b: &[u8]) -> f64 (строки 297-314)
- Shannon-энтропия байтов (log2), пустой срез → 0.0.
- связи: `verdict_site` (695-699): тело POST 64B..512KB с энтропией >6.5 → af-причина `entropy:<x.xx>` (шифрованный/случайный payload = признак отправки фингерпринта).

### fn strip_ln(mut u: &str) -> &str (строки 316-327)
- срезает до двух суффиксов `:<digits>` с конца (line:column из стектрейсов): `...af.js:1:8842` → `...af.js`.

### pub fn first_stack_url(s: &str) -> Option<&str> (строки 329-345)
- назначение: вытащить ПЕРВЫЙ URL из JS-стектрейса (`new Error().stack`).
- что внутри: цикл по `find("http")`; конец URL — первый из `)`, пробел, `\n`, `"`, `;`, `,`, `'`, `}`, `\\`; результат через `strip_ln`; принимается если длина >10; иначе поиск продолжается с `e.max(p+4)`.
- связи: `collect_site` (475-480) — по URL стектрейса привязывает `stk:<tag>`-события к скрипту (`script_tags`); тесты `stack_urls` (1392-1401).

### fn blacklisted(host: &str) -> bool (строки 347-349)
- точное совпадение с записью BLACKLIST либо суффикс `.запись` (поддомен).

### fn blacklisted_path(url: &str) -> bool (строки 351-361)
- парсит url: после `://` берёт хост (до первого `/`) и путь; сверяет с BLACKLIST_PATH (хост равен И путь начинается с префикса). URL без `://` или без пути → false.

### #[derive(Clone)] struct ReqInfo (строки 363-371)
- состояние одного HTTP-запроса (по rid).
- поля: `url: String` — URL запроса; `method: String`; `ty: Option<String>` — тип ресурса CDP (`Fetch`, `Image`, `Document`…); `stk: Vec<String>` — URL скриптов-инициаторов (из `d.stk` через `strip_ln` + `d.iniu`); `post_hash: Option<String>` — хеш артефакта POST-тела (из k=3 где `x=="post"`); `setcookie: Option<String>` — значение Set-Cookie из ответа.

### #[derive(Clone)] struct Ep (строки 373-381)
- агрегат по эндпоинту (URL без query/fragment, см. `ctx::endpoint_of`).
- поля: `n: u64` — число запросов; `dup: u64` — сколько дублей net:send отброшено; `method: String` — метод первого запроса; `vendor: Option<String>` — вендор антифрода; `af: Vec<String>` — причины вердикта antifraud; `garbage: Vec<String>` — причины вердикта garbage.

### impl Ep (строки 383-403)
- `fn new(method)` (384-393): n=0, dup=0, vendor=None, пустые af/garbage.
- `fn verdict(&self) -> u8` (394-402): af непуст → 1 (antifraud); иначе garbage непуст → 2; иначе 0 (neutral). ВАЖНО: af приоритетнее garbage; blacklist-причина не понижает вердикт, если есть af-причины (но см. финальный цикл `verdict_site` 712-718 — garbage чистится, только если blacklist-причины нет).

### struct SiteState (строки 405-415)
- всё накопленное состояние одного сайта.
- поля: `taint: HashSet<u32>` — пул FNV-хешей токенов из `_th`-событий (что браузер пометил как чувствительные значения); `script_tags: HashMap<String, HashSet<String>>` — URL скрипта → набор `stk:`-тегов; `req: HashMap<String, ReqInfo>` — rid → запрос; `ep: HashMap<String, Ep>` — ключ эндпоинта → агрегат; `tn_sum: HashMap<String, u64>` — сумма taint-count из net:send по эндпоинтам; `ws_url: HashMap<String, String>` — rid WebSocket → URL; `scripts_seen: HashSet<String>` — URL из k=7 (заполняется, но больше нигде не читается — мёртвое поле); `art_bodies: HashMap<String, String>` — хеш артефакта → rid (из k=3); `art_src: HashMap<String, String>` — хеш → URL скрипта (из k=8).

### impl SiteState (строки 417-442)
- `fn new()` (418-430): всё пустое.
- `fn ep_of(&mut self, url, method) -> &mut Ep` (432-436): ключ = `endpoint_of(url)` (пустой → сам url), `entry().or_insert_with(Ep::new)`.
- `fn ep_key(&self, url) -> String` (438-441): owned-версия ключа.

### fn collect_site(state: &mut SiteState, tl: &Path) (строки 444-580)
- назначение: первый проход по timeline.jsonl — наполняет SiteState.
- что внутри, по шагам:
  1. открывает файл (ошибка → молчаливый return), построчно `serde_json::from_str` (битая строка → continue).
  2. Ветка `kk`-событий (452-483): `_th` → массив u64 в `state.taint` (как u32); `net:send` → `v[0]`=url, `v[1]`=method, `v[4]`=tn (taint count) → `tn_sum[ep_key] += tn` и `ep_of(...).n += 1`; `stk:<tag>` → `first_stack_url(v[0])` → `script_tags[url].insert(tag)`.
  3. Ветка `k`-событий (485-578): требуются поля `k` (u64) и `d` (объект).
     - `k==1` (net.request, 494-527): rid, u, m, ty; стек `d.stk` сплитится по `;`, из каждой части берётся всё после последнего `@` и через `strip_ln` (формат Firefox/CDP `fn@url:line`); плюс `d.iniu` (initiator URL). Если rid уже есть и url пуст — дозаполняет url/method; иначе вставляет новый ReqInfo.
     - `k==2` (net.response, 528-542): из `d.h` (объект заголовков) вытаскивает `set-cookie` (регистронезависимо) в ReqInfo.
     - `k==3` (net.body, 543-556): `d.a` (хеш артефакта) → `art_bodies[a]=rid`; если `d.x=="post"` → `post_hash=a`.
     - `k==6` (net.ws, 557-565): если `d.f=="created"` и `d.u` начинается с `ws`/`http` → `ws_url[rid]=u`.
     - `k==7` (js.script, 566-571): `d.u` http* → `scripts_seen`.
     - `k==8` (js.source, 572-577): `d.a` + `d.u` http* → `art_src[a]=u`.
- связи: вызывается из `process_site` для каждого timeline; формат строк производит `writer.rs` (k-события в `handle` 364-431, kk-события в `batch` 272-361); kk-теги — из inject.rs (браузерная инъекция).

### fn tag_class(t: &str) -> u8 (строки 582-590)
- t ∈ STRONG → 2; t начинается с `g:` ИЛИ t ∈ WEAK → 1; иначе 0.

### fn tainted_scripts(state: &SiteState) -> Vec<(String, Vec<String>)> (строки 592-612)
- назначение: выбрать скрипты, занимающиеся фингерпринтингом.
- правило: по `script_tags` считает s=число тегов класса 2, w=класса 1; скрипт «грязный» если `s>=2` ИЛИ `(s>=1 && w>=5)`. Возвращает (url, отсортированные теги), список отсортирован.
- связи: `verdict_site` (627) — множество tainted URL для причины `taint-script`; `process_site` (917-919) — для фильтрации и отчёта; порог проверяется e2e-тестом (скрипт с stk:toDataURL + stk:getParameter = 2 strong → tainted).

### fn first_party(host: &str, site_host: &str) -> bool (строки 614-616)
- host равен site_host либо является поддоменом (суффикс `.<site_host>`).

### fn push_once(ep: &mut HashMap<String, Ep>, k: &str, why: &str) (строки 618-624)
- добавляет af-причину к эндпоинту k, если её там ещё нет (дедуп причин).

### fn verdict_site(state, stage, arts, site_host) (строки 626-719)
- назначение: второй проход — выносит вердикт каждому эндпоинту сайта.
- что внутри, по шагам:
  1. `tainted` = множество URL из `tainted_scripts` (627).
  2. `rid_art` = rid → первый хеш артефакта из `art_bodies` (628-631).
  3. Клонирование `state.req` в Vec (632) — чтобы не было двойного заимствования.
  4. Для каждого запроса с непустым url (633-703):
     - `ep_of(...).n += 1` (счётчик запросов);
     - `blacklisted(host)` или `blacklisted_path(url)` → garbage-причина `blacklist`, continue (дальнейшие проверки пропускаются);
     - `vendor_of_url(url)` = Some(v) и хост НЕ first-party → `e.vendor=v`, af-причина `vendor:<v>`;
     - тип != Document и какой-то URL из стека инициаторов ∈ tainted → af-причина `taint-script`;
     - `ty ∈ RES_TYPES`: через rid_art→arts→путь файла читает `read_head(4096)`; если sniff НЕ совпал с family → af `masked:<ty>`, иначе garbage `res:<ty>`;
     - setcookie содержит сигнатуру из COOKIE_SIGS → af `cookie:<sig>` (через push_once);
     - post_hash: читает `<stage>/artifacts/<hash>.post`; если 64 ≤ len ≤ 512KB → `body_taint_hits` >0 → af `taint-body:<n>`; `entropy` >6.5 → af `entropy:<x.xx>`.
  5. `tn_sum`: tn>0 и эндпоинт не blacklisted → af `tn:<n>` (704-711).
  6. Финал (712-718): у эндпоинтов с af-причинами garbage-список очищается, ЕСЛИ в нём нет `blacklist` (blacklist переживает af — но сам вердикт всё равно 1 из-за приоритета af в `Ep::verdict`; garbage-причины при этом не попадают в отчёт `why`).
- связи: вызывается из `process_site`; читает артефакты `.post` из stage.

### fn filter_file(state, tainted, tl, keep_hashes, mode) -> (u64, u64) (строки 721-793)
- назначение: третий проход — переписать timeline.jsonl на месте, оставив только нужные строки; вернуть (kept, dup).
- что внутри:
  1. строит `rid_ep: HashMap<rid, verdict>` по всем запросам (728-736);
  2. открывает tl (ошибка → (0,0)), создаёт `<tl>.jsonl.tmp` (with_extension("jsonl.tmp") — фактически заменяет расширение на `.tmp`);
  3. построчно: parse → `line_keep` → false: continue;
  4. дедуп net:send (756-774): ключ = (ep_key(url), (fnv32(method), fnv32(body))), где body — v[2]: строка → fnv32 байт, иной JSON → fnv32 от его `to_string()`, отсутствует → 0; повтор → dup+=1, `Ep.dup+=1`, строка выбрасывается;
  5. из оставленных строк собирает `keep_hashes` — все `d.a` (хеши артефактов), упомянутые в выживших строках (775-781);
  6. пишет строку verbatim + `\n` в tmp; kept+=1;
  7. `rename(tmp → tl)`; при ошибке tmp удаляется (788-791).
- связи: keep_hashes позже спасает артефакты от удаления в `run_mode` (1240-1246).

### fn line_keep(v, state, tainted, rid_ep, mode) -> bool (строки 795-862)
- назначение: решение «оставить ли строку timeline».
- что внутри:
  - kk-строки (796-812): префикс ∈ KEEP_PREFIXES → true безусловно; `net:send` → по вердикту эндпоинта: Strict → vd==1, Main → vd!=2 (url пустой → false); прочие kk → false.
  - k-строки (813-861), требуют `d`, иначе false:
    - k=1..=5 (запрос/ответ/тело/fail/заголовки): вердикт по rid из rid_ep; Strict → vd==1, Main → vd!=2; rid неизвестен → vd=0 → Main оставляет, Strict выбрасывает;
    - k=6 (WebSocket): rid без ws_url → true; иначе Main → `!blacklisted(host_of(u))`; Strict → `(!blacklisted && vendor_of_url.is_none()) || verdict_of_url(state,u)!=2` (в коде без скобок — `&&` приоритетнее `||`);
    - k=7|8 (скрипт/исходник): по `d.u`; Main → не blacklisted хост; Strict → url ∈ tainted ИЛИ vendor_of_url есть;
    - k=12 (exception): Main → не blacklisted; Strict → tainted;
    - k=10|11|13|14|15 (input/console/execcontext/navigation/lifecycle): только Main;
    - прочие k (9 batch, 16 file, 17 meta) → false.
- связи: вызывается только из `filter_file`.

### fn verdict_of_url(state, url) -> u8 (строки 864-867)
- вердикт эндпоинта по url (0 если неизвестен).

### fn esc(s: &str) -> String (строки 869-885)
- ручное JSON-экранирование строки вместе с кавычками: `"`→`\"`, `\`→`\\`, `\n`,`\r`,`\t`, управляющие <0x20 → `\u00xx`, остальное verbatim.
- связи: сериализация classification.json без serde (строковый монтаж).

### struct SiteOut (строки 887-898)
- результат обработки одного сайта.
- поля: `name` — имя каталога сайта; `inner` — готовый JSON-кусок (endpoints/garbage/tainted_scripts/totals); `af`,`garbage`,`neutral`,`scripts`,`kept`,`dup` — счётчики; `art: Vec<(String,String)>` — (хеш артефакта, вендор/`first-party`/`unknown`); `art_v: Vec<(String,u8,bool,u8)>` — (хеш, вердикт, blacklisted?, family).

### fn process_site(site, stage, arts, mode, keep_hashes) -> SiteOut (строки 900-1067)
- назначение: полный цикл обработки одного site-каталога.
- что внутри, по шагам:
  1. `site_name` = имя каталога (901) — используется и как site_host для first_party;
  2. сбор timeline'ов: рекурсивно `collect_ttls(site/tunnels)`; если пусто — fallback `site/timeline.jsonl`; сортировка (903-913). Т.е. поддерживает и «сырую» раскладку writer'а (`sites/<site>/tunnels/<tun>/<slot>/timeline.jsonl`), и уже смерженную;
  3. `collect_site` по каждому tl (914-916);
  4. `verdict_site` (917);
  5. `tainted_scripts` → список и множество (918-919);
  6. `filter_file` по каждому tl, сумма kept/dup (925-929);
  7. эндпоинты сортируются по n desc, затем по ключу; топ-300 (930-963): JSON-сегмент `{"u":..,"n":..,"dup":..,"m":..,"v":"antifraud|garbage|neutral","why":[af+garbage причины],"vendor":..|"null"}`; вердикт 1 → ep_doc + af_n, 2 → gb_doc + gb_n, 0 → nt_n;
  8. удаление `site/antifraud/<vendor>/timeline.jsonl` (966-980) — вендорные копии timeline избыточны после merge;
  9. `sc_doc` = топ-200 tainted-скриптов `{"u":..,"tags":[..]}` (981-985);
  10. `inner` = `"endpoints":[..],"garbage":[..],"tainted_scripts":[..],"totals":{"endpoints":N,"antifraud":N,"garbage":N,"neutral":N,"taint_pool":N,"kept_lines":N,"dup_lines":N}` (986-1000);
  11. артефакты тел (1013-1030): для каждого (a,rid) из art_bodies — url запроса, ep_key, вердикт, blacklisted, family → art_v; вендор = vendor_of_url(url) ИЛИ e.vendor ИЛИ `first-party` → art;
  12. артефакты исходников (1031-1043): для (a,u) из art_src — blacklisted → vd=2; tainted ИЛИ vendor → vd=1; иначе 0; вендор = vendor_of_url ИЛИ `unknown`;
  13. merge всех tl в один `site/timeline.jsonl`: читает ВСЕ строки из всех (уже отфильтрованных) tl, сортирует по `line_t` (910-1063), перезаписывает site/timeline.jsonl;
  14. `lift_site_tabs(site)` (1065) — перекладка tabs/cookies из tunnels-поддерева и удаление tunnels;
  15. возврат SiteOut с art/art_v (1066).
- связи: единственный вызов — worker-потоки `run_mode`.

### fn line_t(s: &str) -> u64 (строки 1069-1077)
- ищет подстроку `"t":` и парсит идущие цифры (без serde); нет → 0. Ключ сортировки merged timeline.

### fn safe_seg(s: &str) -> String (строки 1079-1083)
- заменяет `/`, `\`, `:` на `_` — безопасный сегмент пути (имя туннеля вида `1.2.3.4_51820` не меняется; slot-имена с `:`/`_` нормализуются).

### fn lift_site_tabs(site: &Path) (строки 1085-1115)
- назначение: поднять per-tunnel данные на уровень сайта и удалить tunnels-поддерево.
- что внутри: для каждого подкаталога `site/tunnels/<tun>`: файлы из `<tun>/tabs/` переносятся (rename) в `site/tabs/<safe_seg(tun)>/`; `<tun>/cookies.json` → `site/cookies/<safe_seg(tun)>.json`; в конце `remove_dir_all(site/tunnels)`.
- связи: e2e-тест проверяет `!d.join("sites/example.net/tunnels").exists()`.

### fn prune_empty(dir: &Path) (строки 1117-1127)
- рекурсивно обходит подкаталоги и делает `remove_dir` ( неудаляет только пустые). Вызывается для `artifacts` и `sites` в конце run_mode (1318-1319).

### fn collect_arts(dir: &Path, out: &mut HashMap<String, PathBuf>) (строки 1129-1145)
- рекурсивно собирает map «stem (имя до первой точки) → путь»; первый найденный побеждает (`entry().or_insert`).

### pub fn run(stage: &Path) -> ClsOut (строки 1147-1149)
- `run_mode(stage, Mode::Main)`.

### pub fn strict(stage: &Path) -> ClsOut (строки 1151-1153)
- `run_mode(stage, Mode::Strict)`.

### fn run_mode(stage: &Path, mode: Mode) -> ClsOut (строки 1155-1336)
- назначение: оркестратор всего classify — параллельно по сайтам, затем глобальная чистка артефактов и classification.json.
- что внутри, по шагам:
  1. `sites = stage/sites/*` (каталоги, sorted); нет каталога или пусто → пишет `{"sites":{}}` в `stage/classification.json` и возвращает нули (1156-1170);
  2. `arts`: collect_arts по корням `stage/artifacts` + каждый `stage/sites/*/antifraud` (1179-1190);
  3. параллелизм (1191-1209): `std::thread::scope`, workers = min(available_parallelism (fallback 4), sites.len()); индекс сайта берётся атомарно `AtomicUsize::fetch_add`; каждый worker зовёт `process_site` с ЛОКАЛЬНЫМ keep_hashes, затем под мьютексом сливает в глобальный `keep_hashes: Mutex<HashSet<String>>` и кладёт SiteOut в `results: Mutex<Vec<Option<SiteOut>>>` по индексу;
  4. агрегация ClsOut по всем SiteOut (1210-1221);
  5. `hash_verdict: HashMap<hash,(vd,bl,fam)>` (1222-1233) — сводка по всем сайтам: вердикт «улучшается» от 2 к не-2 (первый не-garbage побеждает), bl сбрасывается в false если хоть один сайт не пометил blacklisted;
  6. чистка `stage/artifacts` (1234-1270): для каждого файла stem НЕ в keep_hashes:
     - вердикт неизвестен (None) → удалить только в Strict;
     - (2, bl=true, _) → удалить всегда (blacklist-артефакт);
     - (2, false, fam) → Strict: удалить; Main: удалить если `res_sniff_ok(head4096, fam)` — т.е. файл ДЕЙСТВИТЕЛЬНО картинка/медиа/шрифт/CSS (честный мусор); «маскировка» (JS под png) остаётся;
     - (1,_,_) → не удалять никогда;
     - (0,_,_) → удалить только в Strict;
     - при удалении: bytes_rm += len, art_rm += 1;
  7. раскладка артефактов по сайтам (1272-1317): `claimed: HashSet` — один хеш достаётся одному сайту (первому по порядку сайтов); `art_files` = arts + свежий листинг stage/artifacts; для каждого (h,v) из so.art:
     - не keep (Strict: vd!=1; Main: vd==2) → если файл лежит ВНЕ stage/artifacts — удалить (мусорные вендорные копии), continue;
     - keep → `rename` файла в `sites[i]/antifraud/<safe_seg(vendor)>/<имя>`; успех → добавляет `"hash":"vendor"` в строку `arts` сайта;
  8. `prune_empty(artifacts)`, `prune_empty(sites)` (1318-1319) — мёртвые каталоги удаляются (сайты, где всё вычищено, исчезают из дерева);
  9. сборка документа (1320-1334): `{"sites":{"<имя>":{<inner>[,"artifacts":{"<hash>":"<vendor>",...}]}}}` одной строкой + `\n`, пишется в `stage/classification.json` (ошибка записи игнорируется).
- связи: вызывается из main.rs:600 (Main-режим по stage_run после sinkfilter) и main.rs:623 (Strict по копии `/tmp/afeye/filtered` для «filtered»-архива) и tg.rs:84 (Main по копии checkpoint'а).

### fn collect_ttls(dir: &Path, out: &mut Vec<PathBuf>) (строки 1338-1349)
- рекурсивный поиск файлов с именем ровно `timeline.jsonl`.

### mod tests (строки 1351-1535)
- `fnv_known_vectors` (1355-1360): эталонные векторы FNV-1a 32 — `""`→0x811c9dc5, `"a"`→0xe40c292c, `"foobar"`→0xbf9cf968.
- `fnv_ascii_units_parity` (1362-1368): байтовый и UTF-16-unit вариант совпадают на ASCII-строках (UA, "0.5", "screen1920x1080", "abc123") и НЕ совпадают на не-ASCII (`"від correspondance"`) — фиксирует границу применимости.
- `entropy_levels` (1370-1380): `entropy(b"aaaa")==0.0`; JSON-подобная строка <5.0; псевдослучайный LCG-поток 4096 байт >6.5.
- `taint_hits_tokens` (1382-1390): taint-пул {fnv32("Mozilla"), fnv32("0.5")}; в теле `{"ua":"Mozilla (X11)","r":0.5,"x":"Zepra/6.0"}` ровно 2 попадания; в ordinary payload — 0.
- `stack_urls` (1392-1401): first_stack_url берёт ПЕРВЫЙ url (V8-формат `at fn (url:1:2)`), режет `:line:col`; `(native)` и текст без url → None.
- `cdp_stack_parse` (1403-1413): Firefox/CDP-формат `fn@url:line` через `;`-сплит + rfind('@') + strip_ln даёт список URL.
- `blacklist_hosts` (1415-1425): поддомены и точные хосты из BLACKLIST матчатся; challenges.cloudflare.com, accounts.x.ai, ingest.humanbehavior.co — нет.
- `sniff_families` (1427-1445): binary_magic по PNG/JPEG/GIF/wOFF2/OTTO/OggS; WASM-магия → 0; textish/js_like; res_sniff_ok: JS под картинкой (fam 1) и под CSS (fam 4) → false, настоящий CSS → true.
- `end_to_end_classify_dedup_and_clean` (1447-1534): полный прогон на temp-дереве `afeye-cls-test2`: строит sites/example.net/tunnels/<tun>/<slot>/timeline.jsonl (23 строки: 5 запросов R1..R5, script/source события, stk-теги toDataURL/getParameter/g:userAgent, _th пул [3826005026], 3 net:send (2 одинаковых → dup=1), _c), артефакты aa11.post (с тейнт-токенами), bb22.post (GA), cc33.js, dd44.json, ee55.png (JS под PNG), ff66.png (настоящий PNG), вендорный timeline antifraud/datadome. Проверяет: scripts==1, af≥1, garbage≥1, dup==1; в merged timeline нет google-analytics, ровно 2 net:send, stk:toDataURL и R1/R4 выжили, нейтральный api.other.net выжил в Main; tunnels удалены; артефакты разложены: aa11.post→first-party, cc33.js→unknown, dd44.json→first-party, ee55.png (маскировка)→first-party; bb22.post и ff66.png удалены; classification.json содержит "antifraud", url, cookie:datadome, masked:Image, "dup":1, "artifacts", aa11. Затем копирует дерево через `arch::copy_tree` и прогоняет `strict`: нейтральный api.other.net и dd44.json выброшены, af (collect, R4/ee55) выжил.

## Взаимодействия (classify.rs)
- ВХОД: дерево stage, созданное writer.rs (`sites/<site>/tunnels/<tun>/<slot>/timeline.jsonl`, `sites/<site>/antifraud/<vendor>/timeline.jsonl`, `artifacts/<hex32(blake3)>.<ext>`, включая `.post`) и inject-телеметрия (kk-события) из браузера. Формат kk/k-строк — writer.rs handle()/batch().
- ВЫХОД: перезаписанные timeline.jsonl (filtered+merged), `sites/<site>/tabs/<tun>/`, `sites/<site>/cookies/<tun>.json`, переложенные `sites/<site>/antifraud/<vendor>/<hash>.<ext>`, удалённый мусор из artifacts/, `stage/classification.json`.
- ЗАВИСИТ ОТ: ctx.rs (endpoint_of/host_of/vendor_of_url + VENDORS); arch.rs (copy_tree — только в тесте); zipper не использует.
- КТО ЗОВЁТ: main.rs:600 `run(&stage_run)` (Main, после sinkfilter, перед упаковкой zip); main.rs:623 `strict(&fdir)` (Strict по копии для filtered-архива); tg.rs:84 `run(&ck)` (Main по копии checkpoint'а, счётчики идут в telegram-событие `sent`).
- НЕ связан напрямую с sinkfilter.rs: они работают над разными частями stage (sinkfilter — `collect/`, classify — `sites/`+`artifacts/`); порядок в main.rs:549-600 — сначала bctrace, потом sinkfilter, потом classify.

---

## src/wg.rs — настройка/разборка изолированных WireGuard-туннелей (netns + veth + wg) для каждого конфига, проверка egress-IP

### use (строки 1-3)
- `crate::ctx::Tunnel`, `std::path::Path`, `tokio::process::Command`.

### pub fn parse_conf(i: u32, name: &str, raw: &str) -> Result<Tunnel, String> (строки 5-56)
- назначение: разобрать текст wg-конфига (формат wireguard-tools INI) в структуру Tunnel с производными именами.
- что внутри: построчно; пустые и `#`-строки пропускаются; `[Section]` переключает `section`; строки без `=` пропускаются; k/v тримятся. Распознаётся ровно 5 ключей: `("Interface","PrivateKey")`→privkey; `("Interface","Address")`→addr (comma-split); `("Interface","DNS")`→dns (comma-split); `("Peer","Endpoint")`→endpoint; `("Peer","PublicKey")`→pubkey. Прочие (AllowedIPs, PersistentKeepalive и т.д.) игнорируются — они потом жёстко перезадаются в setup. Если privkey/pubkey/endpoint пусты → `Err("conf {name}: missing key fields")`.
- производные поля Tunnel (37-55): `user = "fx{i}"`, `ns = "afns{i}"`, `wg_if = "afwg{i}"`, `h_if = "afvh{i}"`, `n_if = "afvn{i}"`, `host_ip = "10.77.{i}.1"`, `ns_ip = "10.77.{i}.2"`, `port = 9400 + i` (CDP-порт Chrome внутри netns), `egress = None` (заполняет main.rs:329 после verify).
- связи: main.rs:193-213 — читает `<root>/wg/*.conf` (в CI распаковываются из base64-секрета WG_CONF_B64, workflow afeye.yml:144-151), сортирует по имени, парсит с i=1..N; ошибки — `[afeye] skip {name}: {e}`.

### async fn run(cmd: &str, args: &[&str]) -> Result<(), String> (строки 58-73)
- запуск внешней команды через tokio; Ok если status.success(), иначе Err с `{cmd} {args}: {stderr.trim()}`. Приватный хелпер всех ip/wg-шагов.

### pub async fn setup(t: &Tunnel, work: &Path) -> Result<(), String> (строки 75-232)
- назначение: полностью поднять туннель: netns, resolv.conf, veth-пара, wg-интерфейс, адреса, маршруты.
- что внутри, по шагам:
  1. `mkdir -p /etc/netns/<ns>` и пишет туда `resolv.conf`: по строке `nameserver <dns>` на каждый t.dns; если dns пуст — fallback `nameserver 10.2.0.1` (76-88). resolv.conf в /etc/netns/<ns> автоматически применяется внутри `ip netns exec`;
  2. `mkdir -p work` (в main.rs:308 это `/tmp/afeye/wg`); генерирует `<work>/<wg_if>.setconf` (90-100): `[Interface]\nPrivateKey = <privkey>\n\n[Peer]\nPublicKey = <pubkey>\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = <endpoint>\nPersistentKeepalive = 25\n` — т.е. AllowedIPs ВСЕГДА полный default route, keepalive 25с, независимо от исходного конфига;
  3. chmod 0600 на setconf (unix-only блок, 101-106) — файл содержит приватный ключ;
  4. `ip netns add <ns>` (107-114);
  5. seq из 8 ip-команд (115-160): veth-пара `<h_if> peer <n_if>`; `addr add <host_ip>/24 dev <h_if>`; `link set <h_if> up`; `link set <n_if> netns <ns>`; внутри ns: `lo up`; `addr add <ns_ip>/24 dev <n_if>`; `link set <n_if> up`; `link add <wg_if> type wireguard` (создаётся в корневом ns);
  6. `wg setconf <wg_if> <путь setconf>` и СРАЗУ `remove_file(setconf)` (161-163) — приватный ключ лежит на диске минимум времени;
  7. seq2 (164-215): `link set <wg_if> netns <ns>`; для каждого адреса из t.addr — `netns exec <ns> ip addr add <a> dev <wg_if>` (адреса приходят из конфига уже с маской, напр. `10.2.0.2/32`); `netns exec <ns> ip link set dev <wg_if> mtu 1420 up`; `netns exec <ns> ip route add default dev <wg_if>`; если хоть один адрес содержит `:` — дополнительно `ip -6 route add default dev <wg_if>`;
  8. любой шаг с ошибкой → Err из run() (туннель остаётся полуподнятым — main.rs зовёт teardown).
- связи: main.rs:310-322 — параллельно (join_all) для всех туннелей после prep_user_dirs; провал → teardown.

### pub async fn teardown(t: &Tunnel) (строки 234-239)
- `ip netns del <ns>` (убивает и veth-конец, и wg внутри ns); `ip link del <h_if>` (страховка от остатков в корне); `bash -c "pkill -KILL -u <user>"` — убить все процессы пользователя fx{i} (Chrome и т.п.). Все ошибки игнорируются (`let _`).
- связи: main.rs:320 (после провала setup), main.rs:358 (после провала verify), main.rs:529 (финальная уборка всех туннелей).

### pub async fn verify(t: &Tunnel) -> Result<String, String> (строки 241-261)
- назначение: проверить, что трафик реально уходит через туннель, и узнать egress-IP.
- что внутри: `ip netns exec <ns> runuser -u <user> -- curl -sS --max-time 15 https://www.cloudflare.com/cdn-cgi/trace`; парсит строку `ip=<addr>` из ответа; первая непустая → Ok(ip); иначе Err(`egress check failed: <stderr>`).
- связи: main.rs:325-360 — параллельно по всем туннелям; Ok → `t.egress=Some(ip)`, meta-событие `{"egress":..,"endpoint":..,"ok":true}` в timeline, туннель в `good`; Err → meta-событие с ok:false + err, teardown.

### pub async fn runner_ip() -> String (строки 263-280)
- тот же cloudflare trace, но БЕЗ netns (с хоста), --max-time 10; не удалось → "unknown".
- связи: main.rs:296-300 — только в не-local режиме; попадает в manifest.json (`runner_ip`) и в лог.

### pub async fn prep_user_dirs(t: &Tunnel) -> Result<(), String> (строки 282-297)
- для `/tmp/afeye/p{i}` (profile Chrome) и `/tmp/afeye/h{i}` (HOME): remove_dir_all → create_dir_all → `chown <user>:<user>` (внешней командой); chown неуспешен → Err.
- связи: main.rs:312 — перед setup каждого туннеля; пути совпадают с browser.rs:59-61 (user-data-dir=/tmp/afeye/p{i}) и browser.rs:122 (HOME=/tmp/afeye/h{i}). Пользователи fx1..fx7 создаются в CI через `useradd -M -u $((2000+i)) fx{i}` (afeye.yml:152-157) — сам wg.rs пользователей НЕ создаёт.

### mod tests (строки 299-322)
- `parse_full` (303-317): полный валидный конфиг (PrivateKey ABC=/, Address с IPv4+IPv6, DNS два сервера, Peer с PublicKey/AllowedIPs/Endpoint 138.199.7.234:51820/PersistentKeepalive) → проверяет i=3, endpoint, privkey, pubkey, addr=["10.2.0.2/32","2a07::2/128"], dns=["10.2.0.1","2a07::1"], ns="afns3", user="fx3", port=9403.
- `parse_broken` (318-321): конфиг только с [Peer] PublicKey → Err (нет privkey/endpoint).

## Взаимодействия (wg.rs)
- ЗАВИСИТ ОТ: ctx::Tunnel (структура определена в ctx.rs:170-187); внешние бинарники `ip`, `wg` (wireguard-tools), `curl`, `runuser`, `pkill`, `bash`, `chown`; права root (netns/link).
- КТО ЗОВЁТ: только main.rs (parse_conf:209, runner_ip:297, prep_user_dirs:312, setup:313, verify:326, teardown:320/358/529).
- ДАННЫЕ: egress-IP из verify уходит в meta-события timeline (через events::J + writer) и в manifest.json (MTun.egress/ok, main.rs:679-690); имена ns/user/port потребляет browser.rs (запуск Chrome внутри netns от имени fx{i} с CDP на 10.77.{i}.2:9400+i).
- Пути: `/etc/netns/<ns>/resolv.conf`, `<work>/<wg_if>.setconf` (work=/tmp/afeye/wg), `/tmp/afeye/p{i}`, `/tmp/afeye/h{i}`.
- ENV: не читает; конфиги берутся из `<root>/wg/*.conf` (main.rs).

---

## src/arch.rs — «архиватор»: обёртки над внешними 7z/curl, копирование дерева, подсчёт байт, append-запись (название = archive, НЕ архитектура/CPU)

### use (строки 1-5)
- `std::fs`, `std::io`, `std::path::{Path, PathBuf}`, `std::process::{Command as StdCommand, Stdio}` (синхронный — только для probe бинарников), `tokio::process::Command` (асинхронный — для рабочих вызовов).

### pub fn have_7z() -> bool (строки 7-21)
- пробует `7z i`, `7zz i`, `7za i` (синхронно, вывод в null); первый успешный → true.
- связи: tg.rs:93 (выбор 7z vs zip), main.rs:649 (упаковка filtered-архива).

### pub fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> (строки 23-43)
- рекурсивное копирование: файл → mkdir -p родителя, сначала `hard_link` (дёшево, один inode), при неудаче `fs::copy`; каталог → create_dir_all + рекурсия; symlink/прочее (symlink_metadata не file/dir) → молча Ok (пропускается — битые симлинки не роняют копирование). Ошибки → Err(String).
- связи: tg.rs:80 (копия stage в /tmp/afeye/tg/ckN), main.rs:620 (копия stage в /tmp/afeye/filtered), classify.rs:1523 (в тесте).

### pub async fn sz_pack(dir: &Path, out: &Path, volume_mb: u64) -> Result<Vec<PathBuf>, String> (строки 45-90)
- назначение: упаковать каталог в 7z с максимальным сжатием и (опционально) томами.
- что внутри: dir не существует → Err("stage dir missing"); out приводится к абсолютному (относительный — от current_dir); удаляет старые тома (`glob_volumes`) и сам out; mkdir -p родителя; `pick_7z()` → Err("no 7z binary"); canonicalize(dir); команда: `nice -n 19 <7z> a -t7z -m0=lzma2 -mx=9 -md=512m -mfb=273 -ms=on -mmt=on [-v{volume_mb}m] <out_abs> .` с current_dir=dir (в архиве относительные пути); stderr piped; неуспех → Err(`7z rc=N: <первые 400 символов stderr>`); результат — `glob_volumes(out_abs)`, пусто → Err("7z produced no archive").
- параметры сжатия: LZMA2, уровень 9, словарь 512MB, fast bytes 273, solid (`-ms=on`), многопоточность (`-mmt=on`), nice 19 (минимальный приоритет CPU).
- связи: tg.rs:94-96 (volume_mb=49 — под лимит Telegram Bot API 50MB на документ), main.rs:650 (volume_mb=0 — один файл `<stem>-filtered.7z`).

### fn pick_7z() -> Option<&'static str> (строки 92-102)
- тот же probe что have_7z, но возвращает имя бинаря: первый из ["7z","7zz","7za"], отвечающий на `i`.

### fn glob_volumes(out: &Path) -> Vec<PathBuf> (строки 104-127)
- список томов: сам out (если существует) + последовательные `<имя>.001`, `.002`, … пока файл существует (до 4095); сортируется лексикографически. Совпадает с форматом `-v` 7z.

### pub fn dir_bytes(p: &Path) -> u64 (строки 129-142)
- рекурсивная сумма размеров файлов (каталоги не учитываются сами, только содержимое); ошибки read_dir/metadata молча пропускаются.
- связи: tg.rs:85 (`in` в событии sent).

### pub async fn curl_post_file(url, fields, file_field, path) -> Result<String, String> (строки 144-160)
- `curl -sS --max-time 300 -o - <url> -F k=v ... -F <file_field>=@<path>`; stdout piped, stderr null; неуспех → Err(`curl rc=N`); иначе тело ответа String (lossy).
- связи: tg.rs:63 (sendDocument multipart: chat_id + document=@файл).

### pub async fn curl_get(url, hdr: Option<&str>, max_secs) -> Result<String, String> (строки 162-176)
- `curl -sSL --max-time <secs> -o - <url> [-H <hdr>]`; то же по ошибкам. `-L` — следует редиректам.
- связи: relay.rs:166 — поллинг очереди задач (AFEYE_QUEUE_URL, max 12с, опциональный Authorization-заголовок).

### pub fn write_append(path: &Path, line: &str) -> io::Result<()> (строки 178-186)
- mkdir -p родителя; open create+append; пишет line + `\n`.
- связи: relay.rs:195-201 — журнал исполненных relay-задач в `dumps/relay-state.jsonl` и state-файл.

### mod tests (строки 188-224)
- `packs_and_volumes` (192-223, #[tokio::test]): готовит temp-дерево `afeye-arch-test` (sites/x/timeline.jsonl из 20000 строк "abc" + sites/x/blob.bin 3MB несжимаемого LCG-шума); копирует copy_tree в `-copy`; проверяет существование blob.bin и равенство dir_bytes(src)==dir_bytes(copy). Если 7z нет — ранний return (тест деградирует до проверки copy_tree). Иначе `sz_pack(&copy, &out, 0)` (volume 0 = без томов): ровно 1 файл, существует, >1000 байт. Уборка temp в конце.

## Взаимодействия (arch.rs)
- КТО ЗОВЁТ: tg.rs (copy_tree, have_7z, sz_pack, dir_bytes, curl_post_file), main.rs:620/649-650 (copy_tree, have_7z, sz_pack), relay.rs:166/195/199 (curl_get, write_append), classify.rs тест (copy_tree).
- ВНЕШНИЕ БИНАРНИКИ: 7z/7zz/7za, curl, nice. Пути: ничего своего не хардкодит — пути задаёт вызывающий.
- ENV: не читает.

---

## src/tg.rs — периодические «чекпоинты»: копирует stage, классифицирует копию, пакует в 7z-тома по 49MB и шлёт в Telegram-чат документами + meta-телеметрия

### use (строки 1-11)
- `crate::arch`, `crate::classify`, `crate::ctx::Ctx`, `crate::events::{FxEvent, K_META}`, `crate::timefmt`, `bytes::{BufMut, Bytes, BytesMut}`, `serde_json::Value`, `std::path::PathBuf`, `std::sync::atomic::Ordering`, `std::sync::Arc`, `std::time::Duration`.

### fn now_ms() -> u64 (строки 13-18)
- `SystemTime::now() - UNIX_EPOCH` в ms; ошибка → 0.

### fn env_u64(k: &str, d: u64) -> u64 (строки 20-22)
- env-переменная как u64, иначе дефолт d.

### pub struct TgOut (строки 24-27)
- поля: `sent: u64` — число успешных чекпоинтов (ok_n>0 хотя бы для одного тома); `errors: u64` — суммарно ошибок (copy/7z/zip/send).
- связи: main.rs:494-497 забирает результат join'ом потока; `sent` → manifest.json `tg_sent` (main.rs:703).

### fn meta_ev(ctx: &Ctx, d: Bytes) (строки 29-41)
- отправляет FxEvent{t: now_ms(), site/tun/tab/vendor/name=0, kind: K_META, d} в ctx.tx. Writer (writer.rs:377-392) кладёт такие события в `stage/meta.jsonl` как `{"t":<ms>,"d":<payload>}`.

### fn tg_line(kind: &str, extra: &str) -> Bytes (строки 43-55)
- монтаж JSON-строки вручную: `{"tg":"<kind>"` + если extra непустой — `,` + extra БЕЗ первого байта (вызывающие всегда передают extra, начинающийся с `,`) + `}`. Пример результата: `{"tg":"sent","ck":1,"vols":3,...}`.

### fn esc_num(s: &str) -> String (строки 57-59)
- «обезвреживание» произвольного текста для вставки в JSON-значение: выбрасывает `"`, `\`, `\n`, `\r`, обрезает до 200 chars.

### async fn send_doc(token, chat, path) -> Result<bool, String> (строки 61-73)
- POST `https://api.telegram.org/bot<token>/sendDocument` через arch::curl_post_file с полями `chat_id=<chat>` и файлом `document=@<path>`; парсит ответ как JSON; `ok==true` → Ok(true); иначе/bad json → Err(esc_num(ответ)).

### async fn checkpoint(ctx: &Arc<Ctx>, idx: u64, out: &mut TgOut) (строки 75-148)
- назначение: один снимок текущего состояния stage → в Telegram.
- что внутри, по шагам:
  1. корень `/tmp/afeye/tg`; каталог `ck{idx}`; старый удаляется (76-78);
  2. `arch::copy_tree(&ctx.stage, &ck)` — hardlink-копия живого stage (ошибка → meta `{"tg":"copy-err"}`, errors+=1, return) (79-83);
  3. `classify::run(&ck)` — Main-классификация КОПИИ (не трогает боевой stage); `arch::dir_bytes(&ck)` — размер входа (84-85);
  4. `timefmt::zip_stem(now_ms())` → имя `<stem>.7z` в /tmp/afeye/tg (86-87);
  5. упаковка (88-116): есть 7z → `arch::sz_pack(&ck, &target, 49)` (тома по 49MB — под bot-лимит 50MB; ошибка → meta `{"tg":"7z-err","e":"..."}`, errors+=1, удаление ck, return); нет 7z → fallback `crate::zipper::pack(&ck, <stem>.zip)` + meta `{"tg":"7z-missing"}` (ошибка → `{"tg":"zip-err","e":...}`);
  6. total = сумма размеров томов (117-122);
  7. token/chat из env `AFEYE_TG_TOKEN`/`AFEYE_TG_CHAT` (123-124);
  8. отправка каждого тома send_doc; ошибка → meta `{"tg":"send-err","e":...}`, errors+=1 (125-134);
  9. итоговое meta-событие (135-146): `{"tg":"sent","ck":<idx>,"vols":<n>,"ok":<n>,"in":<байт входа>,"out":<байт томов>,"af":<cls.af>,"garbage":<cls.garbage>,"kept":<cls.kept>}`;
  10. ok_n>0 → out.sent+=1; тома и ck удаляются (147-148) — на диске чекпоинты не копятся.
- связь с main: события через ctx.tx попадают в meta.jsonl текущего слота, т.е. журнал чекпоинтов уезжает вместе с основным архивом.

### pub async fn run(ctx: Arc<Ctx>) -> TgOut (строки 150-184)
- назначение: цикл чекпоинтов до остановки.
- что внутри: если `AFEYE_TG_TOKEN` или `AFEYE_TG_CHAT` пусты — сразу возвращает нулевой TgOut (152-156); интервал `every = max(env AFEYE_TG_EVERY (дефолт 300), 5)` секунд (157); idx=0; бесконечный цикл: выход при `ctx.cn.stop`/`ctx.cn.dead` (Acquire) или если до `ctx.deadline` осталось <20с (161-167); сон по 1с с проверкой флагов (168-175); повторная проверка стоп-условий (176-181); idx+=1; checkpoint (182-183). Первый чекпоинт — через every секунд после старта (не сразу).
- связи: main.rs:461-477 — запускается в ОТДЕЛЬНОМ ОС-потоке `afeye-tg` со своим current-thread tokio-рантаймом, только если не test-режим и оба env заданы; main.rs:494-497 — join в конце; main.rs:461: `tb_on = !test && token && chat` — замечание: workflow передаёт ещё `AFEYE_TG_ON` (afeye.yml:21,184), но в Rust-коде эта переменная НЕ читается nigде (grep по src/ — только в yml).

## Взаимодействия (tg.rs)
- ЗАВИСИТ ОТ: arch (copy_tree/have_7z/sz_pack/dir_bytes/curl_post_file), classify::run, zipper::pack (fallback), timefmt::zip_stem, ctx::Ctx (stage, tx, cn.stop/dead, deadline), events (FxEvent/K_META).
- КТО ЗОВЁТ: main.rs:473 `rt.block_on(tg::run(ctx2))` в потоке afeye-tg.
- ENV: `AFEYE_TG_TOKEN` (bot-токен), `AFEYE_TG_CHAT` (chat_id), `AFEYE_TG_EVERY` (секунды, дефолт 300, минимум 5). В CI — из secrets/vars (afeye.yml:19-21).
- Пути: `/tmp/afeye/tg/ck{idx}` (копия stage), `/tmp/afeye/tg/<stem>.7z(.001…)`, `/tmp/afeye/tg/<stem>.zip`.
- Wire: multipart/form-data POST на api.telegram.org sendDocument; JSON-ответ Telegram (`ok:true/false`); meta-строки tg_line в meta.jsonl.

---

## src/timefmt.rs — арифметика календаря без chrono: epoch-ms → гражданская дата, и три строковых формата имён (slot/run_id/zip-stem)

### pub struct Stamp (строки 1-8)
- поля: `y: i64` (год), `mo: u32` (месяц 1-12), `d: u32` (день 1-31), `h: u32`, `mi: u32`, `s: u32` (часы/минуты/секунды UTC).

### pub fn stamp(ms: u64) -> Stamp (строки 10-23)
- ms → secs (i64) → `days = secs.div_euclid(86400)`, `rem = secs.rem_euclid(86400)`; дата через `civil_from_days(days)`; h=rem/3600, mi=(rem%3600)/60, s=rem%60. Всегда UTC, без таймзон.

### pub fn civil_from_days(z: i64) -> (i64, u32, u32) (строки 25-36)
- классический алгоритм Howard Hinnant'а (days_from_civil наоборот): сдвиг на 719468 (1970-01-01 в эре 0000-03-01), era = 146097 дней, doe/yoe/doy/mp, март-базовый год; `m<=2 → y+1`. Корректен для дат до и после эпохи (div_euclid-подобная обработка отрицательных z через `if z>=0 {z} else {z-146096}` — floor-деление на 146097).

### pub fn slot(ms: u64, span_min: u32) -> String (строки 38-46)
- формат: `ДД.ММ.ГГГГ_ЧЧ.ММ-ЧЧ.ММ` — начало в ms, конец в ms+span_min*60000 (вторая пара — только ЧЧ.ММ конца). Пример: `01.01.2000_00.00-00.30`.
- связи: main.rs:223 `slot(t0ms, 30)` — имя подкаталога stage (`/tmp/afeye/stage/<slot>`) и часть пути timeline'ов writer'а (`.../tunnels/<tun>/<slot>/timeline.jsonl`); хранится в Ctx.slot и manifest.json.

### pub fn run_id(ms: u64) -> String (строки 48-54)
- ISO-8601: `ГГГГ-ММ-ДДTЧЧ:ММ:ССZ`. Связи: main.rs:224 — лог-строка `[afeye] run <rid>` и manifest.json `started`.

### pub fn zip_stem(ms: u64) -> String (строки 56-62)
- `afeye-ГГГГММДД-ЧЧММСС`. Связи: main.rs:613-615 (`<stem>.zip`, `<stem>-filtered.7z`, `<stem>.manifest.json` в dumps/) и tg.rs:86 (имена чекпоинт-архивов). Пример в корне репо: `afeye-20260918-144834.zip`.

### mod tests (строки 64-98)
- `epoch` (68-73): stamp(0) = 1970-01-01 00:00.
- `y2k` (75-79): stamp(946684800000) = 2000-01-01.
- `leap` (81-85): stamp(1709164800000) = 2024-02-29 (високосный).
- `midday` (87-91): stamp(1709208000000) → h/mi/s = 12:00:00.
- `slot_fmt` (93-97): `slot(946684800000, 30)` == "01.01.2000_00.00-00.30"; `zip_stem(946684800000)` == "afeye-20000101-000000".

## Взаимодействия (timefmt.rs)
- ЗАВИСИТ ОТ: ничего (чистая арифметика, даже без std::time — время передаёт вызывающий).
- КТО ЗОВЁТ: main.rs:223-224 (slot, run_id), main.rs:613 (zip_stem), tg.rs:86 (zip_stem).
- ФОРМАТЫ: slot — `DD.MM.YYYY_HH.MM-HH.MM`; run_id — `YYYY-MM-DDTHH:MM:SSZ`; zip_stem — `afeye-YYYYMMDD-HHMMSS`.

---

## АУДИТ СООТВЕТСТВИЯ ЭТАЛОНУ

Сравнение реального кода с «эталоном» из 4+1 пунктов. Только факты с номерами строк.

### 1. jitless / no-opt / no-sparkplug (флаги V8 в src/browser.rs)

Реально в `chrome_flags` (browser.rs:58-101):
- `--jitless` — ЕСТЬ, browser.rs:93-99. Гейт: env `AF_JITLESS` строго `=="1"`. Комментарий (94-97) прямо связывает с 0033: весь JS остаётся в Ignition, тайминги закрывает 0034.
- `--no-opt` — НЕТ. grep по всему репо (`src/`, `patches/`, `scripts/`, `.github/`) — 0 вхождений.
- `--no-sparkplug` — НЕТ. 0 вхождений.
- Сборочные gn-арги (scripts/build-chromium.sh:48-72) JIT тоже не отключают: только `v8_enable_afeye=true`, `blink_enable_afeye=true`, `network_enable_afeye=true`, `extra_cflags=[-DV8_AFEYE=1,-DBLINK_AFEYE=1,-DNET_AFEYE=1]`.

Чего не хватает списком:
1. Флага `--no-opt` нет нигде.
2. Флага `--no-sparkplug` нет нигде.
3. `AF_JITLESS=1` НЕ выставляется в CI: запуск в afeye.yml:184 передаёт только `AFEYE_TG_ON/TOKEN/CHAT, AFEYE_QUEUE_URL/TOKEN, AF_BUDGET_MB=350, AFEYE_SINK=1, AF_BROWSE_SECS=2280, AF_HARD_SECS=2340`. Значит в реальном прогоне `--jitless` НЕ применяется — байткод-трейс 0033 видит только инструкции до JIT-компиляции (горячие циклы уходят в Sparkplug/Maglev/TurboFan и исчезают из трейса). Это прямое противоречие комментарию browser.rs:94-96 и SERIES.md:85.
4. Смежные гейты тоже не выставлены в CI: `AFEYE_VIRTUAL_CLOCK` и `AFEYE_TRACE_BYTECODE` в afeye.yml не передаются (grep — только browser.rs:97 комментарий, SERIES.md, тела патчей). Виртуальные часы по умолчанию ВЫКЛ (см. п.3).

### 2. Патч диспетчера Ignition (0033) vs эталон

Эталон требует: хук в `GENERATE_BYTECODE_HANDLER` в `src/interpreter/interpreter-generator.cc`; фиксировать BytecodeOffset, опкод+аргументы (имя свойства из constant pool, регистры), SharedFunctionInfo, имя скрипта.

Реально (patches/0033-v8-ignition-bytecode-trace.patch):
- Место хука — НЕ interpreter-generator.cc и НЕ макрос GENERATE_BYTECODE_HANDLER. Хук стоит в `v8/src/interpreter/interpreter-assembler.cc`:
  - hunk `@@ -48,6 +48,18` (строки патча 419-437): в КОНСТРУКТОРЕ `InterpreterAssembler::InterpreterAssembler` — `CallRuntime(Runtime::kAfeyeTraceBytecodeEntry, GetContext(), BytecodeArrayTaggedPointer(), SmiTag(BytecodeOffset()), GetAccumulatorUnchecked(), SmiTag(operand_scale_))`. Комментарий в патче: «compiled INTO every bytecode handler by the generator» — т.е. генератор вызывает этот конструктор для каждого handler'а, эффект эквивалентен хуку в генераторе, но фактическая точка — constructor + InlineShortStar.
  - hunk `@@ -1381,6 +1393,16` (строки патча 438-454): `InlineShortStar` — второй хук, потому что Star0..Star15 инлайнятся lookahead'ом в предыдущий handler и через конструктор не проходят. Без него 16 опкодов Star терялись бы.
- grep `interpreter-generator|GENERATE_BYTECODE_HANDLER` по patches/ и src/ — 0 вхождений. Файл `src/interpreter/interpreter.cc` не тронут.
- Рантайм-часть: `RUNTIME_FUNCTION(Runtime_AfeyeTraceBytecodeEntry)` в `v8/src/runtime/runtime-trace.cc` (hunk `@@ -114,6 +132,416`, строки патча 484-900), регистрация в runtime.h: `F(AfeyeTraceBytecodeEntry, 4, 1, kCannotTriggerGC)` (строки патча 905-919).
- Что фиксируется реально (wire-формат bcrec.h, новый файл v8/src/afeye/bcrec.h, строки патча 1-366; Hdr 72 байта, static_assert):
  - BytecodeOffset — ЕСТЬ: `hdr.offset` (аргумент 2 хука, `SmiTag(BytecodeOffset())`; runtime пересчитывает `offset = bytecode_offset - kHeaderSize + kHeapObjectTag`).
  - Опкод — ЕСТЬ: `hdr.opcode` читается из реального pc (`op_byte = *pc`), плюс `hdr.scale` (1/2/4) — codegen-константа handler'а.
  - Аргументы — ЕСТЬ, глубже эталона: каждый операнд декодируется САМИМ движком (`BytecodeDecoder::DecodeRegisterOperand/DecodeSignedOperand`) и эмитится блоком `kTagOperand [u8 idx][u64 value]`; для регистровых операндов дополнительно сырое слово регистра (`kTagReg`) и полное значение String/HeapNumber/Smi (`kTagRegStr/Str16/RegF64/RegSmi`) — строки патча ~815-863. Имена свойств из constant pool в самой instruction-записи НЕ эмитятся — они едут отдельным func-def блобом (весь constant pool: `kCpTagStr/Str16/F64/Raw`, строки патча ~678-727) и резолвятся на Rust-стороне (bctrace.rs:633-660: для GetNamedProperty/LdaGlobal/CallProperty и т.д. операнд 0 → строка из cp).
  - SharedFunctionInfo — ЧАСТИЧНО: sfi читается (`fn->shared()`), но в запись попадают только производные: `func_id = FNV-1a(script_id, function_literal_id, StartPosition, iso_tag)>>16` (MakeFuncId, bcrec.h строки патча ~118-131) — детерминированный, GC-стабильный. Сам указатель SFI не эмитится (и не должен — он подвижен).
  - Имя скрипта — ЕСТЬ: в func-def блобе `name` = `Script::name()` полными байтами + `line = Script::GetLineNumber(StartPosition)` (AfeyeEmitFuncDef, строки патча ~660-676). ИМЯ ФУНКЦИИ (sfi->FunctionDebugName) НЕ эмитится — grep по патчу: 0 вхождений FunctionDebugName; идентификатор функции — только func_id-хеш.
  - Аккумулятор — ЕСТЬ (сверх эталона): сырое слово в `hdr.acc` + полное значение блоками kTagAcc* (строки патча ~866-884).
- Обвязка: meta-запись (opcode 0xfe) со всей таблицей опкодов (имена, число операндов, флаги jump/return/call, acc_use, размеры по 3 scale, типы/оффсеты операндов) и таблицей имён runtime-функций — эмитится один раз (AfeyeEmitMeta, `std::atomic<bool> done`). func-def (opcode 0xff) — дедуп по `(func_id, bc_len)` через thread_local `unordered_set` без лимита. Записи >1MiB-16 режутся EmitSplit по kFlagCont, склейка по (opcode, func_id) в offset-порядке. Квот/тракации строк нет (комментарий bcrec.h: «No limits anywhere»).
- РАСХОЖДЕНИЕ С ДОКАМИ РЕПО: SERIES.md:85 утверждает «Квоты: 50M инструкций на процесс (backstop), AFEYE_BC_CAP переопределяет» — в патче 0033 НИ квоты 50M, НИ env AFEYE_BC_CAP нет (grep по патчу — 0 вхождений). Доки описывают старую версию патча.

Расхождения по пунктам эталона:
- Файл/функция хука: НЕ соответствует (interpreter-assembler.cc ctor + InlineShortStar вместо interpreter-generator.cc/GENERATE_BYTECODE_HANDLER); покрытие при этом эквивалентно или лучше (short-star учтены явно).
- BytecodeOffset: соответствует (hdr.offset).
- Опкод: соответствует (hdr.opcode + scale).
- Аргументы (значения, регистры): соответствует и превышает (engine-decoded значения + полные строки/числа регистров и аккумулятора); имя свойства — соответствует опосредованно (через cp func-def + резолв в bctrace.rs, не в момент инструкции).
- SharedFunctionInfo: частично — только производный func_id, не ссылка/имя функции.
- Имя скрипта: соответствует (script name в func-def).

### 3. Виртуализация таймингов (0034) vs эталон

Эталон: `src/base/platform/time.cc` ИЛИ `Performance::now`; формула `virtual_time += kBaseInstructionCost * instruction_count`.

Реально (patches/0034-v8-blink-virtual-clock.patch, 2 файла):
- `third_party/blink/renderer/core/timing/performance.cc`, `Performance::now()` (hunk `@@ -1373,6 +1380,25`): под `BLINK_AFEYE` и `blink::afeye::Enabled()`, при env `AFEYE_VIRTUAL_CLOCK` (непустой и != '0', читается один раз в static-лямбде) возвращает `g_afeye_origin_ms + afeye_vclock_ns()/1e6`, где origin = `base::TimeTicks::Now().since_origin()` на момент первого вызова. Символ счётчика линкуется из v8 через `extern "C" uint64_t afeye_vclock_ns(void)` (renderer-бинарник общий для blink и v8).
- `v8/src/objects/js-objects.cc`, `JSDate::CurrentTimeValue` (hunk `@@ -5914,6 +5918,25`): то же для Date.now() — `g_afeye_epoch_ms + afeye_vclock_ns()/1e6`, эпоха-база = `V8::GetCurrentPlatform()->CurrentClockTimeMilliseconds()` один раз.
- Счётчик: `v8/src/afeye/sink.cc` (в патче 0033, hunk `@@ -219,6 +219,16`): `std::atomic<uint64_t> g_vclock_ns{0}`, `afeye_vclock_ns()` — relaxed load, `VclockTick(ns)` — relaxed fetch_add. Инкремент — в `Runtime_AfeyeTraceBytecodeEntry`: `if (AfeyeVclockOn()) VclockTick(AfeyeVclockNsPerInstr())` на КАЖДУЮ исполненную инструкцию; шаг = env `AFEYE_VCLOCK_NS_PER_INSTR`, дефолт 10 нс (runtime-trace.cc, строки патча ~530-545, ~768-770).

Сравнение:
- Место: соответствует ветке «ИЛИ Performance::now» (performance.cc) + сверх эталона Date.now (js-objects.cc). `src/base/platform/time.cc` НЕ тронут (grep по patches/ — 0 вхождений) — и не требуется при выбранной ветке, НО: всё, что читает время мимо performance.now/Date.now (например `setTimeout`-тайминги через platform scheduler, `MessageEvent.timeOrigin` и т.п.), остаётся на реальном квантовом/стенном времени — эталонная задача «замедление трейсинга не ломает внутренние таймауты» закрыта только для двух JS-видимых часов.
- Формула: соответствует по сути — `virtual_time += cost(=AFEYE_VCLOCK_NS_PER_INSTR, дефолт 10нс) * 1` на каждую инструкцию, что эквивалентно `kBaseInstructionCost * instruction_count`; константа не compile-time (`kBaseInstructionCost`), а env-настраиваемая, счётчик — глобальный atomic (не per-isolate; при нескольких isolate'ах в одном процессе время суммарное).
- Гейт: `AFEYE_VIRTUAL_CLOCK` в CI НЕ выставляется (afeye.yml:184) → в боевых прогонах виртуальные часы ВЫКЛЮЧЕНЫ, и замедление от трейса (если AF_JITLESS включён вручную) детектируется тайминговыми проверками.

### 4. WebIDL/DOM биндинги (0008 / 0024 / 0019) vs эталон

Эталон: патч `src/bindings/core/v8/`, логировать геттер/сеттер интерфейса с АРГУМЕНТАМИ и ТИПОМ ВОЗВРАЩАЕМОГО ЗНАЧЕНИЯ.

Реально:
- 0008-blink-dom-api.patch: хукается НЕ `core/v8/`, а `third_party/blink/renderer/platform/bindings/idl_member_installer.cc` — общий механизм установки ВСЕХ IDL-атрибутов и операций (через него проходят и core/v8-обёртки). Механика (hunk `@@ -15,6 +22,63`): `AfeyeWrapDomApi` подменяет `v8::FunctionCallback` на `AfeyeDomApiThunk`, идентичность несёт `v8::External` в data-слоте (таблица 65536 ячеек `AfeyeApiCell{orig, prop, what[104]}`, линейный пробинг под мьютексом); строка `what` = `"dom <interface>.<get|set|call> <property_name>"` (accessor выводится из ExceptionContext kind в CreateFunctionTemplate, hunk `@@ -134,12 +198,33`). Эмит: `EmitStr(kDomApi, NowNs(), what)`, глобальный счётчик-лимит 8 000 000 вызовов.
  - АРГУМЕНТЫ: НЕ фиксируются (thunk логирует только идентичность вызова, затем зовёт orig).
  - ВОЗВРАТ: НЕ фиксируется в 0008.
- 0024-blink-dom-api-values.patch (тот же idl_member_installer.cc): добавляет `AfeyeCaptureValue` — ПОСЛЕ вызова orig снимает `info.GetReturnValue().Get()` и сериализует: undefined/null → литералы, boolean → 0/1, number → `%.17g`, string → до 159 байт с заменой непечатаемых/≥0x7f на `?`, array → `[array len=N]`, остальное → `[object]`. Итоговая строка `"%s val=%.150s"`. Гейт отключения: `AFEYE_TRACE_DOM_VALUES=0`.
  - ТИП ВОЗВРАТА: явного поля типа НЕТ — тип различим по форме значения (неявно). Значение — ЕСТЬ (строковое, усечённое 150 символами).
  - АРГУМЕНТЫ: по-прежнему НЕТ.
- 0019-blink-fp-values.patch: точечные ручные хуки в конкретных реализациях (не в bindings-слое), kind `kFingerprint`, строки формата `"<домен>/<операция> k=v ..."`; аргументы и значения фиксируются ТАМ, где автор счёл нужным:
  - css_computed_style_declaration.cc `GetPropertyCSSValue` (hunk `@@ -383,6 +396,18`): `css/get-computed prop=<name> val=<CssText 96ch>`, лимит 2M;
  - font_face_set.cc `load` (hunk `@@ -232,6 +245,17`);
  - media_query_list.cc `matches()` (hunk `@@ -118,6 +131,16`): `media/matches q=<media> m=<0|1>`;
  - local_dom_window.cc `matchMedia` (hunk `@@ -1106,6 +1119,16`): `media/query q=<media 128ch>`, лимит 200k;
  - base_rendering_context_2d.cc `DrawTextInternal` (hunk `@@ -1025,6 +1032,21`);
  - notification.cc `permission()` — три ветки (insecure/prerender/обычная): `perm/notification value=<granted|denied|default|prompt>`;
  - permissions.cc `query` (hunk `@@ -113,6 +120,15`): `perm/query name=<descriptor 40ch>`.

Сравнение с эталоном:
- Расположение патча: НЕ соответствует буквально (`platform/bindings/idl_member_installer.cc` вместо `core/v8/`), но это корректное choke-point — через него ставятся все IDL-члены, включая core/v8-генерированные.
- Геттер/сеттер + имя интерфейса + свойство: соответствует (what-строка 0008).
- Аргументы вызова: НЕ соответствует для общего механизма (0008/0024 аргументы не пишут); частично покрыто точечно в 0019 (prop/q/name) и на уровне байткода — аргументы JS-вызовов всё равно видны в трейсе 0033 (операнды + регистры) и в kk-телеметрии inject.rs (g:*-теги).
- Тип возвращаемого значения: НЕ соответствует буквально (нет явного type-тега); значение — соответствует (0024, строковая форма; тип выводится из формы).

### 5. Финальный формат лога: эталон vs факт

Что реально пишет 0033: sink-запись kind 40 = 16-байтовый wire-заголовок sink + 72-байтовый `bcrec::Hdr` + payload-блоки `[u8 tag][u32 len][bytes]`. Что парсит src/bctrace.rs: `collect/index.jsonl` (k=="bytecode-trace") → part-файлы; склейка cont-частей; meta (opcode 0xfe) → OpMeta-таблица; func-def (0xff) → FuncDef{name=ИМЯ СКРИПТА, line, cp, bytecode}; инструкции → InstrRec{ts,pid,func_id,offset,opcode,scale,flags,iso,acc,payloads}; выход: `collect/filtered/bctrace/sem/<func_id:08x>.jsonl` (по инструкции: ts, off, op, args, acc, res, regs) + `<func_id>.json` (отчёт по функции) + `collect/filtered/bctrace.json` (summary с api_calls/dead-blocks).

| Поле эталона | Есть ли реально | Где именно | Что делать, если нет |
|---|---|---|---|
| `timestamp_virtual` | НЕТ (есть wall-clock ts) | ts записи = `v8::afeye::NowNs()` на момент Emit (runtime-trace.cc, AfeyeEmit, строки патча ~578-588) → sink-конверт → collect index → bctrace.rs:413 (`v.get("ts")`), InstrRec.ts (bctrace.rs:86). Виртуальный счётчик g_vclock_ns в запись НЕ кладётся | Эмитить `afeye_vclock_ns()` вторым u64 в Hdr (есть резерв: hdr.line перегружен под iso_tag) либо отдельным payload-блоком; либо на Rust-стороне считать виртуальный ts как `first_ts + 10нс * порядковый номер инструкции в (pid,iso)` — данные для этого уже есть |
| `script_id` | ЧАСТИЧНО (впечён в func_id, отдельно не эмитится) | `MakeFuncId(script_id, literal_id, start_pos, iso_tag)` — bcrec.h строки патча ~118-131; runtime-trace.cc ~795-798 читает `sc->id()`. В записи/отчётах отдельного поля script_id нет; FuncDef.name несёт имя скрипта (бывает пустым для inline/eval) | Добавить script_id u32 в func-def заголовок (сейчас там line/frame_size/param_count, bcrec.h FuncDefBuilder::Build строки патча ~290-320) и в bctrace.rs FuncDef/func-report (bctrace.rs:60-68, 569-578) |
| `function_name` | НЕТ | В func-def `name` = `Script::name()` (runtime-trace.cc ~665-676, переменная name_buf из `sc->name()`); `sfi->FunctionDebugName()` не вызывается нигде в патче (grep — 0). В sem/*.jsonl имени функции нет, только func_id; в `<func_id>.json` поле "name" — это имя скрипта (bctrace.rs:570) | В AfeyeEmitFuncDef дополнительно читать `sfi->FunctionDebugName()` и класть вторым строковым полем в блоб (формат блоба: [u32 bc_len][u32 name_len][u32 cp_bytes][i32 frame_size][u32 param_count]... — bcrec.h ~283-287, парсер bctrace.rs:244-292 — менять синхронно, roundtrip-тест tests/bcrec_roundtrip.rs тоже) |
| `bytecode_op` | ДА | Hdr.opcode (bcrec.h ~35); имя опкода резолвится через meta-таблицу: bctrace.rs sem-pass `"op": m.name` (bctrace.rs:716-720) | — |
| `target_property` | ДА (резолвится на Rust-стороне) | cp-строки в func-def (kCpTagStr/Str16, bcrec.h ~83-86; runtime-trace.cc ~678-727); операнд 0 для GetNamedProperty/LdaGlobal/CallProperty и др. резолвится через cp в bctrace.rs:637-655; агрегаты `"prop X"`/`"global X"`/`"call X"` в bctrace.rs:674-700, api_calls в bctrace.json | — |
| `arguments_hash` | НЕТ как хеш — ЕСТЬ как полные значения | kTagOperand/kTagReg*/kTagAcc* блоки (bcrec.h PayloadTag ~63-84; runtime-trace.cc ~815-884); в sem jsonl — массивы args/acc/res/regs (bctrace.rs:721-757) | Ничего: полные значения строго информативнее хеша. Если хеш нужен для дедупа — считать fnv32/blake3 от args на Rust-стороне (bctrace.rs), не в движке |

Дополнительные факты аудита:
- Хук 0033 стоит в рантайм-функции (`CallRuntime` на каждую инструкцию), а не инлайново в handler'е — это цена за полноту (engine-decoded операнды, GC-safe доступ к регистрам через `DisallowGarbageCollection`); эталонный «хук логирования в макросе генерации» в таком виде физически не может читать значения регистров без перехода в рантайм.
- `kCannotTriggerGC` в регистрации runtime-функции (runtime.h hunk, строки патча 905-912) согласуется с `DisallowGarbageCollection no_gc` в теле — хеш-таблицы/string-доступы под no_gc безопасны.
- Покрытие инструкций: 2 точки (конструктор handler'а + InlineShortStar) = все диспатчи, включая wide/extra-wide (scale передаётся codegen-константой) и short-star.
- Итог по эталону: п.2 — соответствует по существу при другом месте хука; п.3 — соответствует по выбранной ветке (performance.now+Date.now), time.cc не тронут, в CI выключен; п.4 — частично (нет аргументов и явного типа возврата в общем механизме); п.1 — НЕ соответствует в боевом режиме: `--jitless` есть в коде, но не включается в CI, `--no-opt`/`--no-sparkplug` отсутствуют; п.5 — 3 из 6 полей эталона отсутствуют или частичны (timestamp_virtual, script_id, function_name).
