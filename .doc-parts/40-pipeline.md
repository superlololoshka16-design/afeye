# Пайплайн телеметрии: collect → bctrace → sinkfilter

Ядро офлайн-обработки записей. Порядок вызова в `src/main.rs`: `collect::Collector::spawn` (main.rs:245) работает фоном весь прогон → `collector.stop()` (main.rs:532) → `bctrace::run` (main.rs:552) → `sinkfilter::run` (main.rs:561) → при успехе sinkfilter удаляет `collect/raw` (main.rs:578-580) → `classify::run` (main.rs:600). bctrace запускается ДО sinkfilter именно потому, что sinkfilter-успех сносит raw-партии, в которых лежат записи байткод-трейса (комментарий main.rs:547-551).

---

## src/collect.rs — парсер wire-формата `.rec` и материализация payload'ов в `index.jsonl` + `raw/*.bin`

### Wire-формат записи `.rec` (сверен с C++-эмиттером patches/0001-v8-sink.patch:237-276)
Каждая запись:
```
[0..4)   u32 LE  total   — полный размер записи = 16 + len(payload)
[4]      u8      kind    — индекс в KINDS (0..=40)
[5]      u8      flags   — бит0 = payload обрезан (truncated)
[6..8)   2 байта pad     — всегда 0
[8..16)  u64 LE  ts      — CLOCK_MONOTONIC нс (C++ MonoNs, 0001:92-97)
[16..)   payload         — байты полезной нагрузки
```
C++-сторона: `kMaxRecord = 1<<20` (0001:74) — total ≤ 1 MiB; при `len > kMaxRecord-16` payload обрезается и ставится `flags |= 1` (0001:241-243). Файлы: `<layer>-<pid>.rec` в `AFEYE_RAW_DIR` (дефолт `/tmp/afeye-raw`), O_APPEND (0001:149-152). Первая запись файла — `sink-hello`: `"afeye-sink/<layer> v2 pid=<pid>"` (0001:128-144).

### const DEFAULT_RAW_DIR (строка 11)
`"/tmp/afeye-raw"` — каталог, куда C++-sink пишет `.rec`. Совпадает с дефолтом `RawDir()` в 0001.

### const MAX_RECORD (строка 12)
`16 + (1 << 20)` = 1048592. Верхняя граница `total` для plausible-проверки. РАСХОЖДЕНИЕ с C++: там `kMaxRecord = 1<<20` = 1048576 (total вместе с заголовком), т.е. Rust-граница на 16 байт свободнее — запись total∈(1048576,1048592] C++ эмиттировать не может, но парсер принял бы.

### const PREVIEW (строка 13)
`4096` — максимум байт payload, из которых `text_preview` пытается сделать UTF-8 превью для `index.jsonl`.

### const KINDS: [&str; 41] (строки 15-57)
Индекс → имя kind. Полный список (индекс: имя; сверено с `enum EventKind` в патчах 0001/0005/0011/0023/0033):
```
0  sink-hello        1  script-source(v8)   2  bytecode-entry    3  wasm-module
4  wasm-memory       5  wasm-table          6  microtask-enqueue 7  microtask-run
8  call-completed    9  atomics             10 sab-backing       11 crypto-op
12 timer             13 perf-entry          14 message           15 structured-clone
16 fingerprint       17 net-request         18 net-resp-body     19 websocket
20 client-hints      21 sw-cache            22 script-source(blink) 23 input
24 event-dispatch    25 dom-metric          26 audio             27 webrtc
28 fetch             29 dom-api             30 microtask(=C++ kMicrotaskDrain)
31 wasm-instance     32 fn-tostring         33 clock             34 isolate(=kIsolateBirth)
35 worker            36 nav-start           37 taint-edge        38 error-stack
39 sink-drop         40 bytecode-trace
```
`"script-source"` встречается ДВАЖДЫ (индексы 1 и 22): v8-слой и blink-слой используют один kind-номер в разных слоях. `kind_name()` по номеру всегда вернёт первое вхождение не важно — различие несёт `layer` из имени файла, ключи статистики `<layer>/<kname>`.

### const BATCHED_KINDS: [&str; 8] (строки 59-68)
`dom-api, call-completed, event-dispatch, input, clock, microtask, timer, bytecode-trace` — высокопоточные kinds. Их payload не пишется отдельным файлом, а аппендится в общий part-файл `raw/<layer>-<kname>-pNNNN.bin`, а в индекс попадает пара `("p": part, "o": offset)`.

### const PART_ROLL_BYTES (строка 69)
`8 << 20` = 8 MiB — порог прокрутки part-файла: при `written >= 8MiB` следующий `push` открывает `p{seq+1:04}.bin`.

### const MAX_KIND (строка 71)
`(KINDS.len()-1) as u8` = 40. Валидатор байта kind в заголовке.

### fn kind_name(kind: u8) -> &'static str (строки 73-75)
`KINDS.get(kind).copied().unwrap_or("unknown")` — индекс вне 0..40 даёт `"unknown"` (впрочем plausible-проверка такие записи и так бракует).

### fn layer_of(file_stem: &str) -> Option<&'static str> (строки 77-85)
Берёт префикс имени файла до первого `-`: `v8` / `blink` / `net`, иначе None. Файлы `<другое>-<pid>.rec` игнорируются полностью (фильтр в scan_once:209-215).

### struct Stats (pub, строки 87-97)
Сериализуется в `collect/stats.json`. Поля:
- `records: u64` — всего распознанных записей (накапливается между сканами);
- `bytes: u64` — сумма длин payload;
- `truncated: u64` — записей с flags&1;
- `corrupt: u64` — сколько раз парсер ловил мусор и ресинхронизировался;
- `files: u64` — число `.rec` подходящих слоёв (перезаписывается каждый скан);
- `first_ts/last_ts: u64` — мин/макс ts (first_ts инициализируется условием `==0`, строки 338-340);
- `per: BTreeMap<String,u64>` — счётчики по ключу `<layer>/<kname>`.

### struct FileTail (строки 99-102)
- `off: u64` — до какого байта файл уже прочитан;
- `partial: Vec<u8>` — хвост недопарсенных байт (обрывок записи с прошлого скана).

### struct ScanState (pub, строки 104-108)
Состояние между сканами: `tails: HashMap<PathBuf,FileTail>` (прогресс по каждому файлу), `seq: u64` (глобальный монотонный номер записи — часть имён одиночных bin-файлов), `parts: HashMap<String,PartWriter>` (открытые part-файлы, ключ `<layer>/<kname>`). `ScanState::new()` (117-125) — пустые поля.

### struct PartWriter (строки 110-115)
- `file: File` — открытый на append part-файл;
- `rel: String` — относительный путь `raw/<fname>` для индекса;
- `seq: u32` — номер текущей партии (0000, 0001, ...);
- `written: u64` — байт записано в текущую партию.

### impl PartWriter::push(&mut self, raw_out, layer, kname, payload) -> Option<(String,u64)> (строки 127-149)
1. Если `written >= PART_ROLL_BYTES`: `seq += 1`, открыть `<layer>-<kname>-p{seq:04}.bin` (create+append). При ошибке открытия — молча (`Err(_) => {}`, строка 139) продолжает писать в СТАРЫЙ файл, не сбрасывая `written` → ролл будет пытаться на каждом push. Дырка обработки ошибок.
2. `off = written`; `write_all(payload)`; при ошибке → None (запись в индекс не попадает, payload потерян).
3. `written += len`; вернуть `(rel, off)`.
ВНИМАНИЕ: файл открывается append-режимом, но `written` стартует с 0 — при повторном использовании того же out_dir (не свежий staging) offset'ы в индексе разъедутся с реальным содержимым. В штатном потоке out_dir создаётся заново на каждый прогон, проблема не проявляется.

### fn part_writer(raw_out, parts, layer, kname) -> Option<&mut PartWriter> (строки 151-176)
Ленивое создание PartWriter: ключ `"<layer>/<kname>"`, первый файл `-p0000.bin` (create+append). Ошибка открытия → None → вызывающий код (scan_once:372-377) деградирует в одиночный файл `<layer>-<kname>-<seq:06>.bin`.

### struct Collector (pub, строки 178-185)
- `stop: Arc<AtomicBool>` — флаг остановки потока;
- `handle: Option<JoinHandle<()>>` — поток сканирования;
- `stats: Arc<Mutex<Stats>>` — общая статистика;
- `raw_dir/out_dir: PathBuf` — вход/выход;
- `state: Arc<Mutex<ScanState>>` — общий scan-state.

### fn ensure_raw_dir(raw_dir) (строки 187-194)
`create_dir_all` + на unix `chmod 0o777` (чтобы любой pid chrome под любым юзером мог писать `.rec`).

### fn scan_once(raw_dir, out_dir, state, stats) (pub, строки 196-401)
Один проход инкрементального парсинга. По шагам:
1. (197-201) ensure_raw_dir; canonicalize; не каталог → return.
2. (202-218) read_dir, отбор: расширение `.rec` И stem начинается с v8/blink/net; сортировка имён; `stats.files = len`.
3. (220-229) создать `<out>/raw`; открыть `<out>/index.jsonl` в режиме APPEND с BufWriter 64 KiB (индекс растёт между сканами, дубли исключены через tails.off).
4. Для каждого файла (231-395):
   - `layer` из stem (232-236); `pid` — число после первого `-`, иначе 0 (237-242);
   - взять `off` из tails (или 0) (243-252), seek на off, `read_to_end` дочитать новые байты (253-263); `new_off = off + chunk.len` сохраняется в tail (264-269);
   - `partial.extend_from_slice(chunk)` (270);
   - замыкания `total_at(p)` — u32 LE на p (272-274), `plausible_at(p)` (275-287): p+16≤len, total∈[16,MAX_RECORD], p+total≤len, kind≤MAX_KIND, flags≤1, оба pad-байта ==0. **flags≤1 означает: любой будущий флаг кроме truncated сделает запись «corrupt»** — хрупкое место;
   - основной цикл (288-392):
     - меньше 16 байт осталось → break («голодный» хвост ждёт следующего скана, строки 290-292);
     - `header_ok` (293-299) — та же проверка без `p+total≤len`. Плохой заголовок → `corrupt += 1`, сдвиг на 1 байт (ресинхронизация побайтово, 300-304);
     - заголовок валиден, но `consumed+total > len` (обрыв записи, 305-321): сканировать вперёд от consumed+1 на наличие ДРУГОГО plausible-заголовка. Найден → текущая позиция мусор: `corrupt += 1`, сдвиг на 1. Не найден → break: байты остаются в `partial` (starved tail — запись просто ещё не дописана, допарсится на следующем скане);
     - полная запись (322-391): kind=rec[4], flags=rec[5], ts=u64 LE rec[8..16], payload=rec[16..]; `state.seq += 1`; `stats.per["<layer>/<kname>"] += 1`; records/bytes; flags&1 → truncated++; min/max ts;
     - сборка JSON-строки индекса билдером `crate::events::J` (ёмкость 160+PREVIEW, 344): ключи `ts,l,pid,k,len`, условный `f` (flags≠0), `h` = первые 16 hex-символов blake3(payload) (360-363);
     - материализация payload (364-383): batched-вид и непустой payload → `part_writer().push()` → ключи `p`(rel part) + `o`(offset); отказ part_writer → одиночный файл `<layer>-<kname>-<seq:06>.bin` и ключ `p` без `o`. НЕ-batched → всегда одиночный файл;
     - `text_preview(payload)` → ключ `txt` (384-387);
     - строка + `\n` в индекс (388-390); `consumed += total`.
   - (393-394) остаток `partial[consumed..]` сохранить в tail.
5. (396-400) flush индекса; перезаписать `<out>/stats.json` сериализованным Stats.

### Формат строки index.jsonl (итог scan_once)
```json
{"ts":<u64>,"l":"v8|blink|net","pid":<u64>,"k":"<kind>","len":<u64>,["f":<flags>,]"h":"<16hex>",
 "p":"raw/<file>.bin",["o":<offset>,]["txt":"<≤4096B UTF-8>"]}
```
`o` присутствует только для batched part-файлов. `f` — только если flags≠0.

### fn text_preview(payload) -> Option<String> (строки 403-412)
Берёт `payload[..min(len,4096)]`, валидирует `simdutf8::basic::from_utf8` — невалидно (payload бинарный или обрезан посреди символа) → None. ДЕФЕКТ: при `payload.len() > PREVIEW` ветка 408-410 ставит `cut` = индекс ПОСЛЕДНЕГО символа (`char_indices().map(|(i,_)|i).last()`), а не конец строки — т.е. от валидного 4096-байтного префикса отбрасывается ещё и последний символ. Логика «обрезать по границе символа» избыточна: from_utf8 уже гарантирует целостность.

### impl Collector (строки 414-503)
- `spawn(stage_root)` (415-420): raw_dir = env `AF_RAW_DIR` иначе `/tmp/afeye-raw`; out = `<stage_root>/collect`; делегирует в spawn_dirs.
- `spawn_dirs(raw_dir, out_dir)` (422-459): создаёт out_dir, поток `"afeye-collect"`: цикл `while !stop` { scan_once под двумя локами (state, stats); пауза } — первые 10 тиков по 200 мс, далее по 2000 мс (440); пауза нарезана sleep'ами по 1 мс с проверкой stop (442-447) — быстрый отклик на остановку. Ошибка spawn → handle=None (stop отработает без join).
- `hellos()` (461-471) и `hellos_handle()` (473-486): сумма `per` по ключам `v8/sink-hello, blink/sink-hello, net/sink-hello` — признак «chrome пропатчен и sink жив». handle-версия возвращает `'static`-замыкание с клоном Arc (для передач в другие подсистемы; вызывается из writer/main).
- `stop(mut self) -> Stats` (488-502): store(true), join потока, ФИНАЛЬНЫЙ scan_once (дособрать хвосты), перезаписать stats.json, `mem::take(&*sc)` вернуть статистику. Poisoned-lock → Stats::default().

### fn run_standalone(raw_dir, out_dir) (pub, строки 505-517)
Бесконечный цикл (1 c): scan_once + eprintln `[collect] records=... bytes=... truncated=... corrupt=... files=...`. Точка входа бинарника `src/bin/afeye-collect.rs` (raw = env `AF_RAW_DIR` иначе DEFAULT_RAW_DIR; out = argv[1]).

### mod tests (строки 519-603) — 3 теста
- helper `rec(kind,flags,ts,payload)` (523-533) — собирает валидную `.rec`-запись.
- `parses_framing_and_materializes_raw` (535-575): 3 полных записи + 12 байт четвёртой; проверяет records=3, corrupt=0, truncated=1, first/last ts, per-ключи, 3 строки индекса, ключи `"f":1`,`"txt"`, содержимое одиночных bin; затем дописывает остаток 4-й записи и повторяет scan — records=4 (проверка starved-tail/частичного продолжения).
- `corrupt_record_resyncs` (577-593): 4 байта 0xFF перед валидной записью net-request → records=1, corrupt≥1 (побайтовая ресинхронизация).
- `layer_filter_rejects_unknown` (595-602): layer_of по stem'ам.

## Взаимодействия (collect.rs)
- Потребители: `main.rs:245` (spawn на прогон), `main.rs:532` (stop), `bin/afeye-collect.rs` (standalone), `bctrace.rs` и `sinkfilter.rs` читают его выход (`index.jsonl`, `raw/*.bin`), тесты sinkfilter (2589,2700,2749,2819,2858) и `tests/bcrec_roundtrip.rs:131` гоняют записи через `scan_once`/`Collector::spawn_dirs`.
- Сам использует: `crate::events::J` (быстрый JSON-билдер), крейты `blake3` (хэш payload), `simdutf8` (валидация превью), `serde_json` (stats.json), `tempfile` (тесты).
- Производители wire-данных: C++-sink из патчей 0001 (v8), 0005 (blink), 0011 (net) — формат заголовка и kind-номера обязаны совпадать с KINDS; kind 39 добавлен 0023, kind 40 — 0033.
- Выход: `<stage>/collect/index.jsonl`, `<stage>/collect/raw/*.bin`, `<stage>/collect/stats.json`.

---

## src/sinkfilter.rs — классификатор JS-цепочек: собирает фрагменты скриптов в «цепи», строит граф идентичности байтов до сетевых sink'ов, выносит вердикты proven/heuristic/dead-end-proven/unresolved и пишет report.json

### struct SinkFilterStats (pub, строки 8-67)
Все поля (возвращаются из `run()`, main.rs печатает часть и кладёт 4 поля в MRun: chains/hot/cold/wasm — main.rs:721-724):
`records` (строк index.jsonl, ВКЛЮЧАЯ sink-hello — инкремент на 1030 до skip на 1032), `fragments` (принятых script-source фрагментов), `chains`, `hot_chains`, `cold_chains`, `chain_bytes` (сумма bytes цепей), `wasm_modules`, `wasm_imports`, `wasm_exports`, `net_chains` (записей в net_chains отчёта), `keep_cold: bool` (из env), `fp_reads` (всего FP-чтений dom-api), `fp_chains` (цепей с ≥2 fp-reads), `integrity_checks` (всего fn-tostring), `integrity_chains`, `wasm_instantiated`, `token_chains` (= token_forming), `dead_end_chains`, `net_adjacent_chains`, `content_sink_chains`, `prune_paths`, `send_initiator_chains`, `token_access_chains`, `fp_entry_chains`, `gopd_chains`, `stack_inspect_chains`, `automation_tells` (сумма попаданий маркеров), `wasm_firstcalls`, `wasm_mem_grows`, `exec_compiles`, `exec_jit`, `exec_byte`, `exec_wasm_code`, `wasm_traps`, `wasm_cached`, `lazy_funcs`, `payload_assembler_chains`, `graph_nodes`, `graph_edges`, `graph_sinks` (число seed-узлов), `graph_tainted`, `graph_hop1`, `graph_deep` (hop≥2), `graph_chains` (цепи с graph_hops), `graph_entry_chains`, `provenance_parents`, `fetched_url_chains`, `proven_chains`, `heuristic_chains`, `unresolved_chains`, `dead_end_proven`, `taint_sink_chains`, `taint_swept_union: u64` (побитовое OR hex-тегов `taint-swept`), `taint_deadend_union: u64`, `graph_distinct_keys`, `graph_fanout_dropped`, `strict_graph: bool` (из env).

### const HOT_PATTERNS (строки 69-89) — 19 подстрок «горячего» кода
`fetch(, XMLHttpRequest, sendBeacon, WebSocket, toDataURL, toBlob, getImageData, measureText, OfflineAudioContext, RTCPeerConnection, createDataChannel, getChannelData, getRandomValues, crypto.subtle, importScripts, postMessage, Worker(, ServiceWorker, WebAssembly`.

### const TRIGGER_KINDS (строки 91-95)
`input, event-dispatch, timer` — kinds, способные быть «спусковым крючком» скрипта.

### const FP_API_NEEDLES (строки 97-134) — 38 игл
Navigator.get {userAgent(×2: с пробелом и без), appVersion, platform, vendor, oscpu, languages, hardwareConcurrency, deviceMemory, plugins, mimeTypes, connection}, Screen.get {width,height,colorDepth,pixelDepth,availLeft,availTop,availWidth,availHeight}, Document.get cookie, getParameter, getExtension, getShaderPrecisionFormat, toDataURL, toBlob, getImageData, measureText, getBoundingClientRect, getClientRects, getChannelData, createOffer, createDataChannel, enumerateDevices, getGamepads, getBattery. Дубликат `Navigator.get userAgent` (98 и 109) — вторая игла с обычным пробелом никогда не сработает раньше первой (find идёт по порядку, первая содержит тот же текст) — фактически мёртвая строка.

### const AUTOMATION_MARKERS (строки 136-155) — 19 маркеров
`pptr:, __puppeteer, playwright, __nightmare, webdriver-evaluate, __webdriver_evaluate, selenium, callSelenium, _Selenium, cdc_, __driver_evaluate, __fxdriver, callPhantom, _phantom, phantomjs, __selenium, CDP, Runtime.evaluate` — ищутся в error-stack (утечка харнесса = тревога целостности).

### struct FpRead (строки 157-160)
`ts: u64`, `needle: &'static str` — одно FP-чтение dom-api.

### Временные окна и лимиты (строки 162-186) — все числа
- `FP_GRACE_NS = 50_000_000` (50 мс) — хвостовой допуск к окну цепи;
- `NET_FP_WINDOW_NS = 5_000_000_000` (5 c) — «net-window»: насколько ПОСЛЕ цепи сетевое событие ещё считается связанным;
- `WASM_INST_WINDOW_NS = 5_000_000_000` (5 c) — окно склейки wasm-модуля с wasm-instantiate;
- `CONTENT_RUN_BYTES = 32` — длина байтового «рана» для ключей графа;
- `CONTENT_RUN_STEP = 16` — шаг окон;
- `CONTENT_MAX_RUNS = 8192` — максимум ключей на запись;
- `CONTENT_LINK_GRACE_NS = 200_000_000` (200 мс) — допуск окна content-bridge/graph-join;
- `CONTENT_MAX_RECORDS = 50_000` — максимум carrier-записей (не-sink) в графе;
- `GRAPH_MAX_EDGES = 8_000_000` — максимум (key,node) пар;
- `GRAPH_MAX_HOPS = 6` — глубина BFS от sink;
- `VARIANT_MIN_BYTES = 64` — минимальный размер sink-тела для вариантовых ключей (base64/hex/алфавит);
- `VARIANT_MAX_SINKS = 4_096` — максимум sink'ов с вариантовыми ключами;
- `QUERY_SINK_MIN_BYTES = 96` — минимальная длина query-строки, чтобы GET-запрос считался sink'ом;
- `HTTP_METHODS` (177-179): GET POST PUT PATCH DELETE HEAD OPTIONS;
- `SINK_CRYPTO_OPS` (180-186): encrypt, sign, deriveBits, digest, crypto-out.
- `ENTRY_JOIN_WINDOW_NS = 250_000_000` (250 мс, строка 850) — окно «entry-join» (call-completed → событие);
- `GRAPH_MAX_FANOUT = 4096` (локальная в run(), строка 1577) — бакет ключа шире этого обрезается при распространении из НЕ-sink узла;
- `big_keep = 96*1024` (локальная, строка 1948) — порог AF_KEEP_BIG.

### struct Rec (строки 188-199)
Строка индекса: `ts, pid, layer, kind, len, h` (blake3-16hex), `path` (rel к collect_dir), `off: Option<u64>` (только batched), `txt: Option<String>` (превью).

### fn read_payload(raw_dir, r) -> Option<Vec<u8>> (строки 201-209)
Читает файл `raw_dir/r.path` ЦЕЛИКОМ, затем срез `[off, off+len)`. Быстрый путь: off==0 и len файла == r.len → вернуть весь файл. `b.get(start..end)?` — вне диапазона → None. Замечание по производительности: для batched part-файлов (до 8 MiB) каждый payload перечитывает весь part-файл — O(N·8MiB) на записи одного part'а.

### const AF_VENDORS (строки 212-230) — 17 суффиксов хостов
challenges.cloudflare.com/cloudflare.com→cloudflare, datadome.co→datadome, kasada.io→kasada, perimeterx.net/px-cdn.net/px-client.net/humansecurity.com/perfdrive.com→human, edgesuite.net/akamaiedge.net→akamai, fpjs.io→fpjs, seon.io→seon, arkoselabs.com→arkose, hcaptcha.com→hcaptcha, imperva.com→imperva, threatmetrix.com→threatmetrix.

### fn af_host_of(url) -> &str (строки 232-253)
Вытаскивает host из URL: после `://`, до `/ ? #`, отбрасывает userinfo (`rfind('@')`), срезает порт (с обработкой IPv6 `[...]`). Без `://` → "".

### fn af_vendor_of_url(url) -> Option<&'static str> (строки 255-276)
Пустой host → None; path содержит `/cdn-cgi/` или `/turnstile` → cloudflare; `/recaptcha` → recaptcha; далее суффиксное совпадение host с AF_VENDORS (точное или `.suffix`).

### fn txt_head(s, n) -> String (строки 278-280)
Первые n chars.

### fn name_of(payload) -> (String, Vec<u8>) (строки 282-290)
Разрез по ПЕРВОМУ NUL: (имя/тег, тело). Нет NUL → ("", весь payload). Это базовый wire-формат payload'ов blink/v8-эмиттеров: `"тег\0байты"` (EmitSpan, EmitTwoStr).

### fn value_of_prose(payload) -> Option<(String, Vec<u8>)> (строки 292-350)
Фолбэк для «прозаических» fingerprint-payload без NUL. Разбирает префиксы:
- `cookie-get|cookie-set` → значение после первого пробела;
- `storage-get|storage-set` → значение после `" vlen=... "` (ищет `" vlen="`, затем следующий пробел);
- `json-stringify` → всё после `" head="`;
- `webgl/unmasked-vendor|webgl/unmasked-renderer|webgl/param` → после `" val="`;
- `canvas/measure-r` → после `" w="`.
Возвращает (тег, value-байты). Ничего не подошло → None.

### fn split_iso(name) -> (Option<String>, String) (строки 352-359)
Префикс `iso:<id> ` → (Some(id), остаток); иначе (None, name). Изолят-тег ставится v8-эмиттерами (0021/0025) для различения worker-изоляторoв.

### fn worker_of(txt) -> Option<(String,String)> (строки 361-369)
Парсит `worker-scope iso=<id> name=<имя> secure=...` → (iso, name).

### fn is_hot(name, body) -> bool (строки 371-385)
Исключения: body или name содержат `afeye-harness` → false (собственный харнесс не «горячий»). `name` начинается с `evt:` или `timer:` → true (скрипт, рождённый обработчиком). Иначе: первые min(len,1MiB) байт тела содержат любую HOT_PATTERNS-подстроку.

### fn overlaps_net_window(net_ts, first_ts, last_ts) -> bool (строки 387-394)
`net_ts` отсортирован. Окно `[first_ts, last_ts + 50мс + 5с]`; partition_point → первое net-событие ≥ lo; существует и ≤ hi → true.

### fn overlaps_content_bridge(content_ts, first_ts, last_ts) -> bool (строки 396-403)
Окно `[first_ts − 200мс, last_ts + 50мс + 200мс]`, та же схема. content_ts = ts tainted-записей с hop≤1 (см. run).

### fn drops_witnessed(drop_events, _pid, ts) -> bool (строки 405-410)
**ПИД ИГНОРИРУЕТСЯ** (параметр `_pid` не используется): true, если существует любое sink-drop-событие `(dts,_,n)` с `dts <= ts + 500_000_000` (ts+0.5c) и `n > 0`. Т.е. «свидетель неполноты» глобальный по всем процессам, хотя ключ отчёта называется `ring_drops_in_pid` (строка 2057) — РАСХОЖДЕНИЕ имени и семантики: drop в ЛЮБОМ pid до горизонта+0.5c переводит цепь из dead-end-proven в unresolved.

### fn graph_hops_for(graph_ts, first_ts, last_ts) -> Option<u32> (строки 412-423)
`graph_ts` — (ts,hop) tainted-узлов, отсортировано. Окно как у content_bridge; MIN hop среди попавших в окно записей; пусто → None. Это «graph-sink@N»: минимальное число демо-хопов байтовой идентичности от материала цепи до wire.

### fn is_monotone(b) -> bool (строки 425-427)
Непустой и все байты равны первому (нули/0xFF-заполнители не дают ключей).

### fn run_keys(body) -> Vec<u64> (строки 430-460)
Ключи контента: blake3(window)[..8] как u64 LE.
- body < 64 байт: если пустой/монотонный → []; иначе ключ КАЖДОГО СУФФИКСА `body[off..]` (не 32-байтные окна!) — O(n) ключей;
- иначе: окна 32 байт с шагом 16, монотонные пропускаются, стоп по `CONTENT_MAX_RUNS=8192`.

### fn hex_bytes(b) -> Vec<u8> (строки 462-470)
lowercase hex-представление (для «sink тоже несёт hex-вариант»).

### fn decode_custom_alphabet(body, alpha) -> Option<Vec<u8>> (строки 472-498)
Декод кастомного base64: alpha должен быть ≥64 байта, body ≥ VARIANT_MIN_BYTES(64); таблица 256→6bit из первых 64 символов (дубликаты в алфавите → None); все байты body должны быть в алфавите (иначе None); аккумулятором 6-битными порциями выдаёт байты. Так ловится мост «шифротело → wire-строка, перекодированная нестандартным алфавитом» (тест e2e_custom_alphabet_bridge).

### fn extract_alphabets(script) -> Vec<Vec<u8>> (строки 500-541)
Ищет в теле скрипта строковые литералы (кавычки `" ' \``) длиной 60..=72 из символов `[A-Za-z0-9+/=$-]`, у которых ≥60 РАЗЛИЧНЫХ символов — кандидаты в кастомные алфавиты base64. Сканирование линейное, i перескакивает за найденный литерал.

### fn chain_signals(c, net_ts, content_ts) -> (Vec<String>, bool, bool) (строки 543-593)
Собирает сигналы token-forming (порядок push'ей = порядок в массиве):
1. `sink-call` — c.hot_pattern (текстовый HOT_PATTERNS в теле);
2. `handler-born` — c.trigger.is_some();
3. `fp-probes` — c.fp_reads.len() ≥ 2;
4. `integrity-check` — c.integrity > 0;
5. `net-window` — overlaps_net_window (возвращается 2-м значением);
6. `content-sink` — overlaps_content_bridge (3-е значение);
7. `send-initiator` — c.send_initiator;
8. `token-access` — c.token_access;
9. `fp-probes-entry` — c.fp_entry непуст;
10. `gopd-check` — c.gopd_check;
11. `stack-inspect` — c.stack_inspect;
12. `spawned-proven` — c.spawned_proven непуст;
13. `graph-entry@N` — c.graph_entry;
14. `taint-sink` — c.taint_sink;
15. `graph-sink@N` — c.graph_hops.

### struct WasmReader<'a> + impl (строки 596-641)
Курсор по байтам: `u8()`, `leb()` (LEB128 u64, сдвиг >63 → None), `bytes(n)`, `name()` (leb-длина + UTF-8 lossy), `limits()` (flags u8 + min [+max если bit0]).

### fn wasm_imports_exports(b) -> (Vec<String>, Vec<String>) (строки 643-719)
Магия `\0asm` обязательна (646); старт с p=8 (пропуск magic+version). Обход секций: id u8 + leb-длина; секция 2 (Import) — count Leb, до 4096 записей: module name (игнорируется), field name → imports, kind u8: 0=func (leb typeidx), 1=table (u8+limits), 2=mem (limits), 3=global (2×u8). Секция 7 (Export) — name → exports, kind u8 + idx leb. Прочие секции пропускаются переходом `r.p = end`. Обрезанный модуль → break, что успели.

### struct Chain (строки 722-759) — все поля
- `file: Option<File>` — открытый файл `filtered/scripts/*.js` (пишется инкрементально);
- `pid: u64`; `name: String` (display-имя без iso-префикса);
- `frags: u64` (сколько script-source фрагментов), `bytes: u64` (сумма длин тел);
- `hot: bool` — «оставить» (текст-паттерн ИЛИ trigger ИЛИ fp≥2);
- `hot_pattern: bool` — только текстовый паттерн (сигнал sink-call);
- `first_ts/last_ts: u64` — окно материализации цепи;
- `path: String` — `filtered/scripts/<fname>` для отчёта/prune;
- `trigger: Option<TriggerRef>` — ближайший входной триггер;
- `iso: Option<String>` — isolate-тег; `worker: Option<String>` — имя worker'а по iso;
- `fp_reads: Vec<String>` (≤32 уникальных игл в окне), `integrity: u64` (fn-tostring в окне), `integrity_samples: Vec<String>` (≤8 по 120 chars), `clock_reads: u64`;
- `token_forming: bool`, `signals: Vec<String>`;
- `net_adjacent: bool` — **МЁРТВОЕ ПОЛЕ**: записывается на 1941, не читается нигде (в отчёт идёт локальная переменная, ключа net_adjacent у chain-entry нет);
- `content_sink: bool` (читается 2003);
- `send_initiator, token_access: bool`; `fp_entry: Vec<String>` (≤32);
- `gopd_check: bool`; `stack_inspect: bool`; `stack_samples: Vec<String>` (≤4 по 240);
- `payload_assembler: bool` — fingerprint `json-stringify` внутри entry-скрипта цепи; в token-forming НЕ участвует (нет в chain_signals), только ключ отчёта;
- `executed_funcs: u64` — max(lazy-compile count, exec count) по имени;
- `graph_hops: Option<u32>`, `graph_entry: Option<u32>`;
- `taint_sink: bool`; `proven: bool`; `dead_end_proven: bool`;
- `fetched_url: bool` — имя цепи == URL, который реально запрашивали;
- `spawned_proven: Vec<String>` (≤16 имён дочерних proven-цепей).

### struct TriggerRef (строки 761-766)
`kind: String, ts: u64, what: String` (120 chars).

### const AMBIENT_EVENT_TYPES (строки 768-779) — 10 «фоновых» событий
mousemove, pointermove, touchmove, pointerover/out/enter/leave, scroll, mouseover, mouseout — НЕ считаются триггером.

### fn is_trigger_event(txt) -> bool (строки 781-789)
Для префиксов `evt `, `evt-mouse `, `evt-key `, `evt-pointer `: первый токен = тип; ambient → false. Иные event-dispatch-тексты → true.

### fn is_trigger_input(txt) -> bool (строки 791-808)
`input/mouse <type>`: mousemove → false. `input/raw type=<T>`: MouseMove, PointerMove, PointerRawUpdate, PointerHoverMove, MouseLeave, MouseEnter, TouchMove, GestureScrollUpdate → false. Остальное → true.

### fn latest_trigger_before(recs, ts, window_ns) -> Option<TriggerRef> (строки 810-843)
recs отсортирован по ts. partition_point(ts) → назад, не глубже `ts - window` и не более 4096 записей; первый TRIGGER_KINDS-рекорд, прошедший is_trigger_input/is_trigger_event → TriggerRef{kind, ts, what=120ch}.

### fn fp_needle_of(txt) -> Option<&'static str> (строки 845-847)
Первая игла FP_API_NEEDLES, содержащаяся в txt.

### const ENTRY_JOIN_WINDOW_NS (строка 850) = 250 мс.

### struct EntryIndex + build_entry_index + script_at (строки 852-900)
- `EntryIndex.per_pid: HashMap<u64, Vec<usize>>` — индексы call-completed записей на pid;
- `entry_script_of(txt)` (856-871): ПОСЛЕДНИЙ `" script="` в тексте; `native` → None; срезает `:<строка>` если после последнего `:` только цифры;
- `build_entry_index(recs)` (873-885): только kind=call-completed, текст НЕ начинается с `lazy-compile` и имеет script=;
- `script_at(recs, pid, ts)` (887-900): ближайший call-completed ≤ ts в пределах 250 мс → его script. Это «kind-8 entry-join»: атрибуция события вызвавшему скрипту БЕЗ стекового развёртывания.

### fn parse_input_rec(txt) -> Option<(&str, Option<(f64,f64)>)> (строки 902-923)
`input/mouse <type> ... x=<f> y=<f>` → (type, Some(x,y)); `input/key ...` → ("key", None); иначе None.

### fn median_of(v) -> Option<u64> (строки 925-931)
sort_unstable, элемент `v[len/2]` (для чётных — верхняя медиана).

### struct InputCadence (строки 933-941)
`total, per_type: BTreeMap, median_delta_us, p90_delta_us, path_px, span_ms, events: Vec<(ts, &'static str, Option<(f64,f64)>)>`.

### fn build_input_cadence(recs) -> InputCadence (строки 943-1010)
Только kind=input, parse_input_rec-совместимые. Считает: total, per_type (по сырому типу), дельты между соседними событиями в мкс (`(ts-prev)/1000`), p90 = d[⌊n·0.9⌋] (при n=10k индекс 9000 — вне диапазона не выходит, но для малых n грубо), path_px = сумма евклидовых расстояний между (x,y), span_ms = (last-first)/1e6, events — с нормировкой типа к mousemove/mousedown/mouseup/click/wheel/key/other.

### pub fn run(collect_dir) -> Result<SinkFilterStats, String> (строки 1012-2279) — ПОШАГОВО
Функция никогда не возвращает Err — все ошибки глушатся (нет index.jsonl → Ok(default), строки 1019-1022).

**Этап 1. Загрузка индекса (1012-1054).** `raw_dir = collect_dir` (пути в индексе вида `raw/...`); `keep_cold = AF_SINK_KEEP_COLD==1` (1016); построчный JSON-парсинг, `stats.records` += 1 на КАЖДУЮ строку (1030), kind==sink-hello пропускается (1032-1034) — поэтому `records ≥ records_indexed`. Rec берёт ts,pid,l,k,len,h,p,o,txt (1035-1045). Создаёт `filtered/scripts`, `filtered/wasm` (1048-1052). Сортировка recs по ts (1054) — дальше все window-запросы через partition_point.

**Этап 2. Глобальный скан событий (1056-1181).** Один проход по recs, match по kind:
- `dom-api` (1077-1081): fp_needle_of(txt) → fp_reads.push(FpRead{ts,needle});
- `fn-tostring` (1082-1086): txt начинается с `fnts` → fnts.push((ts,txt)) — проверки целостности (Function.prototype.toString, эмиттер 0004:134 `"fnts name=%.*s script=%.*s:%d"`);
- `clock` (1087): ts в clock_ts;
- `sink-drop` (1088-1094): из txt `... dropped=<N>` → drop_events.push((ts,pid,N)) (формат 0023:12 `"sink-drop layer=%s dropped=%llu"`);
- `fingerprint` с префиксами `taint-swept tag=` / `taint-deadend tag=` (1095-1108): hex-тег OR'ится в taint_swept_union / taint_deadend_union (run-level битовые маски 0027/0032);
- `isolate` (1109-1133): txt `exec <tier> <fn> script=<имя>:<line> len=<n>` (эмиттер 0025:146): exec_compiles++; по второму токену exec_jit/exec_byte/exec_wasm_code; имя скрипта (без `:line`, без iso-префикса) → exec_per_name[name]++;
- `worker` (1134-1138): worker_of → workers.push((ts,iso,name));
- `wasm-instance` (1139-1149): wasm_inst.push((ts,pid, txt starts_with "wasm-instantiate", txt)); счётчики wasm-firstcall/wasm-trap/wasm-mem grow;
- `error-stack` (1150-1156): каждое вхождение AUTOMATION_MARKERS → automation_tells[marker]++;
- `nav-start` (1157-1166): `mono_ns=<t>` → минимум в nav_start (якорь относительных времён отчёта).
Итоговые присваивания stats (1170-1181).

**Этап 3. Построение цепей из script-source (1183-1283).** Ключ цепи `(pid, layer, name)` → индекс; имя = часть payload до NUL (name_of). Новый ключ: имя файла `<layer>-<pid>-{anon|chain}-<h[..8]>.js`, SANITIZE (1204-1211), File::create (1212); split_iso → (iso, display); worker = worker_name_for(workers, ts, iso) (1214); инициализация Chain (1215-1252). Для каждого фрагмента: в файл пишется шапка-комментарий `/* afeye chain layer= pid= name= */` (только при frags==0) и `/* ==== ts= len= h= ==== */` + тело + `\n` (1259-1276); frags++, bytes += len, last_ts = ts; is_hot → hot=hot_pattern=true (1280-1283). Пустое тело пропускается (1195-1197), read_payload-отказ — continue (1190-1193).

**Этап 4. WASM-модули (1284-1348).** kind=wasm-module: дедуп по h (1285-1288); name_of → tag=="cached" означает тело после NUL, иначе весь payload (1293-1295; wasm_cached++); запись `filtered/wasm/<h[..16]>.wasm` (1299-1300); wasm_imports_exports → счётчики + запись wasm_index (1301-1313): `{hash, bytes, ts, pid, from_cache, imports[≤256], exports[≤256]}`. Entry-join (1314-1345): ищется wasm_inst-заголовок (`wasm-instantiate`) того же pid в `[ts, ts+5с]`; найден → `instantiated=true`, `instantiated_imports` из `imports=<n>`; затем все `wasm-import <name> kind=...` того же pid в `(hts, hts+5с]` до следующего заголовка → `resolved_imports` (≤256 уникальных); wasm_instantiated++.

**Этап 5. Trigger-join (1351-1363).** Окно: env `AF_SCRIPT_TRIGGER_MS` (дефолт 250) → нс. Для каждой цепи latest_trigger_before(recs, first_ts, window) → hot=true, trigger=Some. Это сигнал handler-born: скрипт материализовался сразу после пользовательского ввода/события/таймера.

**Этап 6. Окна fp/integrity/clock на цепь (1365-1396).** Окно `[first_ts, last_ts + 50мс]`: уникальные иглы fp_reads (≤32) → c.fp_reads; ≥2 → hot=true, fp_chains++. fnts в окне → c.integrity; >0 → integrity_chains++, integrity_samples (≤8×120ch). clock_ts в окне → c.clock_reads.

**Этап 7. net_ts (1398-1411).** Из net-request (txt = `METHOD\0URL`): non-GET/HEAD ИЛИ af_vendor_of_url → ts в net_ts; сортировка.

**Этап 8. Граф идентичности байтов (1413-1645).**
- payload_kinds (1413-1421): `crypto-op, structured-clone, net-request, taint-edge, websocket, wasm-memory, fingerprint` (строка «rule» в отчёте 2219 перечисляет только 5 — wasm-memory и fingerprint НЕ упомянуты, РАСХОЖДЕНИЕ комментария и кода);
- VALUE_TAGS (1422-1438): cookie-get/set, storage-get/set, canvas/get-image-data-r, webgl/read-pixels-r, audio/{float,byte}-{frequency,timedomain}, json-stringify, webgl/unmasked-{vendor,renderer}, webgl/param, canvas/measure-r;
- struct GraphNode (1440-1445): ts, pid, sink, keys;
- alphabets_by_pid (1447-1458): extract_alphabets по всем script-source телам (ВТОРОЕ полное чтение payload'ов скриптов);
- построение узлов (1460-1541): для каждой записи payload_kinds: read_payload, name_of; fingerprint с пустым тегом → value_of_prose-фолбэк (1473-1478); пустое тело → пропуск; fingerprint допускается только с тегом из VALUE_TAGS (1482-1484);
  - ПРЕДИКАТЫ SINK (1485-1499): `is_crypto_sink` = crypto-op и tag содержит любое из SINK_CRYPTO_OPS; `is_upload` = net-request и tag ∈ {req-body, req-body-stream}; `is_query_sink` = net-request и tag ∈ HTTP_METHODS и (длина query после '?' ≥ 96 ИЛИ URL принадлежит AF-вендору); `is_ws_sink` = websocket и tag == ws-frame-out. `sink = OR всех`;
  - лимиты (1501-1509): не-sink (carrier) — пропуск при carriers_seen ≥ 50_000 или total_keys ≥ 8M; sink при total_keys ≥ 8M добавляется узлом с ПУСТЫМИ ключами (учтётся в seeds, но не даст рёбер);
  - ключи (1511-1533): run_keys(body); для sink с телом ≥64 байт и sinks_seen < 4096 — дополнительные ВАРИАНТОВЫЕ ключи: run_keys(base64(body)) + run_keys(hex(body)) + для каждого алфавита pid: decode_custom_alphabet → run_keys(decoded); все усечаются до остатка GRAPH_MAX_EDGES;
  - keys.truncate(8192), sort, dedup (1534-1538); total_keys += len; узел в nodes;
- CSR-представление (1543-1575): pairs (key, node_idx) со всех узлов (cap 8M, 1550-1552), sort_unstable; проход по группам одинаковых ключей → adj_keys (ключи), adj_off (CSR-смещения, замыкающий push 1572), adj_nodes (ноды по ключам); stats.graph_edges / graph_distinct_keys;
- BFS от sink'ов (1577-1619): dist=u32::MAX; все sink-узлы dist=0 в очередь (seed_count); обход: `du >= 6` → не расширять; для каждого ключа узла — бакет adj; **fanout-защита (1606-1609)**: если текущий узел НЕ sink и бакет > GRAPH_MAX_FANOUT(4096) — ключ пропускается, fanout_dropped += размер бакета (общие байты типа JSON-обёртки не создают фейковых рёбер); соседи с dist==MAX получают du+1;
- итоги (1621-1645): tainted_nodes, graph_ts[(ts,hop)] sorted, tainted_positions[(pid,ts,hop)], hop_hist; stats.graph_nodes/sinks/tainted/hop1/deep(hop≥2); `content_ts` = ts узлов с hop ≤ 1 (dedup) — «мост контента»: байты, уже доказанно связанные с wire ≤1 хопом.

**Этап 9. Entry-join атрибуции (1647-1793).**
- canon_name (1647-1658): 160 chars, не-ASCII-graphic (кроме пробела) → '?';
- entry_index (1660) = build_entry_index;
- name_to_chain (1662-1669): (pid, canon_name) → первый индекс цепи с таким именем;
- graph_entry_hops (1670-1681): для каждой tainted-позиции (pid,ts,hop): script_at(pid,ts) → имя скрипта → цепь; минимум hop на цепь. Смысл: tainted-запись вне окна цепи, но entry-join говорит, что в этот момент исполнялся скрипт этой цепи → «graph-entry@N»;
- скан fetch/fingerprint/dom-api/error-stack (1683-1748): для каждой записи entry-join → idx цепи:
  - `fetch` → send_init (цепь сама инициировала отправку);
  - `fingerprint json-stringify ...` → assembler_chains (сборка payload'а);
  - `fingerprint taint-sink ...` → taint_sink_set (C++-ядро 0027/0032 прямо сказало «тут течь»);
  - `fingerprint cookie-get|cookie-set|storage-get|storage-set` → tok_access (цепь трогала хранилище токена);
  - `dom-api` с иглой → fp_entry (FP-чтения, атрибутированные entry-join'ом, а не окном);
  - `error-stack` → stack_chains + ≤4 образца по 240ch;
  - `fingerprint gopd ` → gopd_chains (GetOwnPropertyDescriptor-интроспекция, 0025);
- проставление полей и stats (1749-1793): send_initiator/token_access/taint_sink/fp_entry(≥2 иглы, ≤32)/gopd_check/stack_inspect(+stack_samples)/payload_assembler.

**Этап 10. Исполнение функций (1795-1826).** call-completed `lazy-compile name=... script=<имя>:<line>` (эмиттер 0022:119) → lazy_funcs++ и lazy_per_name[имя без :line]++. Для цепей: executed_funcs = max(lazy_per_name[name], exec_per_name[name]) (совпадение по ПОЛНОМУ имени цепи — без canon/iso-нормализации, в отличие от entry-join).

**Этап 11. graph_hops / graph_entry / proven (1828-1848).** Каждой цепи graph_hops = graph_hops_for (минимальный hop tainted-записи в окне `[first−200мс, last+50мс+200мс]`). graph_entry_hops → c.graph_entry (минимум сохраняется, 1834-1837). `proven = graph_hops | graph_entry | send_initiator | token_access | taint_sink` (1842-1848).

**Этап 12. fetched_url (1850-1867).** Множество URL (после NUL, http/https) из net-request; имя цепи точно равно URL → fetched_url=true (цепь — это загруженный скрипт).

**Этап 13. Провенанс (1869-1903).** Для proven-цепей с именем: parent = script_at(pid, first_ts) — скрипт, исполнявшийся в момент рождения цепи; parent ≠ self и есть в name_to_chain → parents[pidx].push(child name) (≤16). Родителям: spawned_proven = children; provenance_parents++. «Цепь скомпилировала proven-код» → родитель тоже proven (1919-1921).

**Этап 14. Вердикты (1905-1943).** `strict_graph = AF_STRICT_GRAPH==1` (1905-1907). Для каждой цепи: chain_signals → signals/net_adjacent/content_sink; счётчики; `if spawned_proven непуст → proven=true` (1919-1921); proven → proven_chains++; `token_forming = !signals.is_empty() || proven` (1925-1927) → token_chains++; token_forming без proven → heuristic_chains++; иначе dead_end_chains++ и: `drops_witnessed(drop_events, pid, last_ts)==false` → dead_end_proven (полнота захвата подтверждена нулём drop'ов — «мёртвая ветвь ПО ФАКТУ»), иначе unresolved (захват мог потерять доказательства). c.signals/net_adjacent/content_sink сохраняются (1940-1942).

Иерархия вердиктов (строки 1975-1983 и 2046-2054): **proven → heuristic → dead-end-proven → unresolved**.

**Этап 15. Keep/prune (1945-1987).** keep = hot | token_forming | keep_cold | (AF_KEEP_BIG==1 && bytes ≥ 96KiB) (1951); hot/cold счётчики; каждый файл цепи sync_all (1957-1959); chain_bytes. ВАЖНО: «cold» цепи НЕ удаляются здесь — все .js остаются на диске, список на удаление формируется в prune_report. prune_report (1966-1986): цепи с непустым path, для которых (strict_graph ? !proven : !token_forming) → `{path, bytes, verdict}`; prune_paths = len. Фактическое удаление делает main.rs:625-644 при сборке filtered-архива (remove_file по каждому path из prune; fallback — chains без token_forming).

**Этап 16. chain_report (1989-2091).** ≤4000 цепей (take(4000) — молчаливое усечение, счётчики stats при этом полные). Ключи entry: `name`(printable 200), `frags`, `bytes`, `hot`, `token_forming`, `ts0`, `ts1`, `path`; условные: `signals[]`, `content_sink`, `send_initiator`, `token_access`, `fp_entry[]`, `gopd_check`, `taint_sink`, `stack_inspect` + `stack_samples[]`, `payload_assembler`, `executed_funcs`, `graph_hops`, `graph_entry`, `spawned_proven[]` + `provenance:"entry"`, `fetched_url`, `verdict` ("proven"|"heuristic"|"dead-end-proven"|"unresolved"), для !token_forming — `dead_end_witness:{ring_drops_in_pid:<bool>}` (имя врёт про pid, см. drops_witnessed), `trigger:{kind,ts,delta_ms,what}`, `isolate`, `worker`, `fp_reads[]`, `integrity_checks` + `integrity_samples[]`, `clock_reads`, при nav_start и ts0≥nav_start — `ts0_rel_ms`, `ts1_rel_ms`.

**Этап 17. input cadence + net_chains (2093-2176).** cadence = build_input_cadence. Для каждого net-request: курсорный проход по recs ≤ r.ts держит `best` = индекс последнего триггер-рекорда (с теми же input/event фильтрами, 2098-2110); если `r.ts − best.ts ≤ 250мс` → entry c `trigger{kind,ts,delta_ms,what(120ch)}`, иначе `trigger: null`. Окно 5с назад (NET_FP_WINDOW_NS): `fp_reads_5s` (≤64 уникальных), `integrity_5s`, `clock_5s`, `input_5s{n, moves, keys, median_delta_us}` (по cadence.events). `t_net_rel_ms` от nav_start. cap 4000 (2172). stats.net_chains.

**Этап 18. per_kind + report.json (2178-2278).** per_kind[<layer>/<kind>]. Полный набор ключей `filtered/report.json` (pretty-JSON, 2273-2276):
```
records, records_indexed, nav_start_ts, per_kind{},
scripts{fragments, chains, hot, cold_dropped, keep_cold, chain_bytes},
dead_end{token_forming, dead_end, net_adjacent, content_sink, send_initiator,
         token_access, fp_entry, gopd, stack_inspect, payload_assembler, rule(str)},
graph{fanout_dropped, nodes, edges, sink_seeds, tainted_nodes, hop1, hop2_plus,
      chains_linked, chains_entry_linked, max_hops, rule(str)},
classification{strict_graph, proven, heuristic, dead_end_proven, unresolved,
      provenance_parents, fetched_url_chains, taint_sink_chains,
      taint_swept_union, taint_deadend_union, rule(str)},
v8_depth{lazy_funcs, exec_compiles, exec_jit, exec_byte, exec_wasm_code,
      wasm_firstcalls, wasm_traps, wasm_cached, wasm_mem_grows,
      automation_tells{marker:count}, note(str)},
taint{fp_reads, fp_chains, integrity_checks, integrity_chains, clock_reads},
input_cadence{total, per_type{}, median_delta_us, p90_delta_us, path_px, span_ms},
wasm{modules, instantiated, imports, exports, index[]},
chains[], prune[], net_chains[]
```
Тексты `rule` (2206, 2219, 2232) — самодокументация формул token-forming/графа/вердиктов (полные строки в коде; в classification.rule перечисление proven факторов: graph-sink | graph-entry | send-initiator | token-access | spawned-proven).
Возврат Ok(stats) (2278).

### fn worker_name_for(workers, ts, iso) -> Option<String> (строки 2281-2293)
iso обязателен; среди workers с тем же iso и `w.ts <= ts` берётся ПОСЛЕДНИЙ (max ts) → его имя. (Линейный скан на каждую цепь.)

### fn sanitize(s) -> String (строки 2295-2307)
`[A-Za-z0-9._-]` проходят, остальное → `_`; break ПОСЛЕ push при len>120 → фактически до 121 символа (мелкий off-by-one).

### fn printable(s, n) -> String (строки 2309-2314)
Первые n chars, байты вне 0x20..0x7e → '?'.

### mod tests (строки 2316-2874) — 13 #[test]
- `wasm_import_export_walk` (2320-2329): синтетический wasm-модуль (секции 2 и 7) → imports=[f], exports=[g].
- `name_split_and_hot` (2331-2338): name_of по NUL; is_hot на fetch-теле и на холодном.
- `iso_split_and_worker_join` (2340-2362): split_iso, worker_of, worker_name_for (совпадение iso+ts, несовпадение).
- `fp_needle_match` (2364-2375): иглы Navigator/WebGL, отсутствие совпадения.
- `batched_payload_slice` (2377-2410): read_payload по off/len из общего part-файла (2 записи в одном bin).
- `trigger_correlation_window` (2412-2431): latest_trigger_before — попадание/промах по окну 250мс, mousemove-событие не триггер.
- `net_window_overlap` (2433-2441): границы overlaps_net_window (5с+50мс).
- `dead_end_classification` (2493-2524, helper chain_with 2443-2491): chain_signals по каждому базовому сигналу (sink-call/handler-born/fp-probes≥2/integrity/net-window), пустая цепь → ноль сигналов.
- `e2e_token_chain_verdicts` (2526-2632): полный пайплайн (записи → Collector::spawn_dirs → sinkfilter::run): collector.js (fetch+cookie-set+req-body с тем же fp-head) получает proven/token_forming; lodash — мёртвая библиотека присутствует в отчёте; graph_sinks≥2, graph_tainted≥1, proven≥1; проверяет report.json chains и наличие файлов в filtered/scripts.
- `e2e_custom_alphabet_bridge` (2634-2713): скрипт с кастомным 64-символьным алфавитом, encrypt(plaintext) + req-body(перекодированное тем же алфавитом) → carrier tainted через decode_custom_alphabet (graph_tainted≥1).
- `dtt_taint_sink_verdict` (2715-2779): fingerprint `taint-sink socket-write ...` + entry-join → цепь proven, verdict=="proven", taint_sink==true, сигнал "taint-sink".
- `req_body_stream_is_graph_sink` (2781-2827): net-request с tag `req-body-stream` признаётся sink (graph_sinks≥1), text-encoder carrier tainted.
- `gc_taint_unions_are_runlevel` (2829-2873): taint-swept tag=1 + tag=4 → union 0x5; taint-deadend → 0x1; значения доезжают до classification в report.json.

## Взаимодействия (sinkfilter.rs)
- Вызывается из main.rs:561 (`sinkfilter::run(&stage_run/collect)`); main.rs:563-577 печатает статистику и вердикты; main.rs:578-580 при `sf.records>0` удаляет `collect/raw`; main.rs:625-644 использует `prune`/`chains` из report.json для физического удаления dead-end .js из filtered-архива; main.rs:721-724 кладёт chains/hot/cold/wasm в MRun-метаданные.
- Вход: `collect/index.jsonl` + `collect/raw/*.bin` (продукт collect.rs). Форматы txt-полей, которые он парсит, задаются C++-эмиттерами: 0003 (`call argc=`), 0004 (`fnts name=... script=...:N`), 0005/0007/0012-0019 (dom-api/fingerprint/css/fonts/media/canvas/perm), 0011/0017 (net-request `METHOD\0URL`, req-body, ws-frame-out), 0022 (`lazy-compile name=... script=...:N`), 0023 (`sink-drop layer=... dropped=N`), 0025 (`exec <tier> <fn> script=...:N len=`, `gopd `), 0026 (wasm-memory), 0027/0032 (`taint-sink`, `taint-swept tag=<hex>`, `taint-deadend tag=<hex>`), 0033/0034 не потребляются напрямую.
- Выход: `collect/filtered/scripts/*.js`, `collect/filtered/wasm/*.wasm`, `collect/filtered/report.json`.
- Использует крейты: serde_json, blake3 (run_keys), base64 (вариантовые ключи); env: `AF_SINK_KEEP_COLD`, `AF_SCRIPT_TRIGGER_MS` (дефолт 250), `AF_STRICT_GRAPH`, `AF_KEEP_BIG` (все — сравнение со строкой "1").
- В тестах использует crate::collect (интеграция через реальный .rec-поток).

---

## src/bctrace.rs — декодер wire-формата v3 патча 0033 (Ignition bytecode trace): статический CFG, мёртвые блоки по факту исполнения, семантический поток sem/*.jsonl

Заголовочный комментарий (строки 7-19): источник правды — `v8/src/afeye/bcrec.h` из патча 0033; `tests/bcrec_roundtrip.rs` доказывает байт-в-байт согласие C++-билдеров и этого парсера без сборки chromium. Принципы: без лимитов и угадывания длин — тип значения ВСЕГДА из тега; значения операндов декодированы движком (BytecodeDecoder) и едут в kTagOperand-блоках; func-def/meta blobs, превышающие одну sink-запись, приходят kFlagCont-частями и склеиваются по (opcode, func_id) в порядке offset'ов.

### Wire-формат v3 (bcrec.h, патч 0033:36-83; payload — внутри .rec-записи collect)
Sink-запись kind=40 (`kBytecodeTrace`, 0033 sink.h hunk): payload = `Hdr(72 байта) + payload-блоки`.
```
Hdr (72 B, static_assert 0033:57):
[0]   u8  opcode    — 0xff func-def part, 0xfe meta part, иначе opcode инструкции
[1]   u8  scale     — OperandScale enum (1/2/4)
[2]   u8  n_payload — число блоков (сатурация 255; парсер его ИГНОРИРУЕТ, парсит структурно)
[3]   u8  flags     — bit0 kFlagFuncDef, bit1 kFlagCont (есть ещё части), bit2 kFlagAccPayload
[4..8)   u32 offset — инструкция: логический bytecode offset (одинаков на всех частях —
                      ключ склейки); func-def/meta: байтовая позиция части в blob
[8..12)  u32 func_id — MakeFuncId(script_id, literal_id, start_pos, iso_tag), FNV-1a>>16
                      (0033:120-134) — GC-стабилен
[12..16) u32 line   — инструкция: ISO-ТЕГ ((isolate_ptr>>3) as u32, 0033:526-529);
                      func-def: стартовая строка функции; meta: 0
[16..24) u64 acc    — инструкция: сырое tagged-слово аккумулятора; func-def/meta: полная
                      длина blob в байтах
[24..72) u64 regs[6] — сырые tagged-слова первых шести input-регистров
```
Payload-блоки: `[u8 tag][u32 LE len][len байт]` до конца части. Теги (0033:67-83, Rust-константы bctrace.rs:27-36):
```
0  TAG_ACC_STR    — acc String, 8-bit байты
1  TAG_ACC_F64    — acc HeapNumber, 8 байт f64 bits   (len==8)
2  TAG_ACC_SMI    — acc Smi, 4 байта i32              (len==4)
3  TAG_REG        — [u16 reg][u64 raw word]           (len==10)
4  TAG_REG_STR    — [u16 reg][8-bit string bytes]     (len>=2)
5  TAG_REG_F64    — [u16 reg][f64 bits]               (len==10)
6  TAG_REG_SMI    — [u16 reg][i32]                    (len==6)
7  TAG_OPERAND    — [u8 operand_index][u64 engine-decoded value] (len==9)
11 TAG_ACC_STR16  — acc String UTF-16LE
12 TAG_REG_STR16  — [u16 reg][UTF-16LE bytes]
Только в func-def blob (cp-блоки): 8 CpStr, 9 CpF64, 10 CpRaw, 13 CpStr16 (0033:244-247)
```
Константы Rust: `HDR_LEN=72` (21), `OP_META=0xfe` (22), `OP_FUNC_DEF=0xff` (23), `FLAG_CONT=2` (24), `FLAG_ACC_PAYLOAD=4` (25).

### struct OpScaleMeta (pub, строки 38-42)
`size: u8` — полный размер инструкции в этом масштабе; `ops: Vec<(u8,u8)>` — (operand_type, operand_offset). **`ops` мёртв**: заполняется в parse_meta (207-215), не читается нигде — decode_func использует только `size`.

### struct OpMeta (pub, строки 44-50)
`name: String` (имя bytecode'а), `n_ops: u8` (используется только при парсинге), `flags: u8` (bit0 jump, bit1 returns, bit2 calls, биты 3-4 subtype, bit5 conditional — комментарий строка 47; реально используется только `flags & 3` в block_starts_of), `acc_use: u8` (1 reads acc, 2 writes acc, 4 clobbers, 8 short-star; реально используется только бит 2 — «пишет acc», строка 668), `scales: [OpScaleMeta; 3]` (Single/Double/Quadruple).

### enum CpEntry (pub, строки 52-58)
`Raw(u64)` (сырое слово — heap-указатель или нечисло), `Str(Vec<u8>)` (8-bit), `Str16(Vec<u8>)` (UTF-16LE), `F64(f64)`.

### struct FuncDef (pub, строки 60-68)
`func_id: u32, line: u32, frame_size: i32, param_count: u32, name: String` (имя СКРИПТА из Script::name, не имя функции!), `bytecode: Vec<u8>` (сырой массив байткода), `cp: Vec<CpEntry>` (constant pool).

### enum Pv (pub, строки 71-83)
Типизированное значение payload-блока: `Str, Str16, F64, Smi(i32), RegWord(u16,u64), RegStr(u16,Vec<u8>), RegStr16(u16,Vec<u8>), RegF64(u16,f64), RegSmi(u16,i32), Operand(u8 idx, i64 value)`.

### struct InstrRec (pub, строки 85-96)
`ts, pid` (из index.jsonl), `func_id, offset, opcode, scale, flags, iso, acc, payloads: Vec<Pv>`. **Мёртвые поля**: `scale` (присвоен в parse_instr:305, не читается) и `acc` (сырое слово, присвоено :308, не читается — семантика использует только typed acc-payload через FLAG_ACC_PAYLOAD).

### struct Stats (pub, строки 98-107)
`records` (строк bytecode-trace в индексе), `instructions` (успешно распарсенных инструкций), `funcs` (func-def'ов), `dead_blocks, live_blocks, dead_bytes, live_bytes`.

### fn rd_u16/rd_u32/rd_i32/rd_u64 (строки 109-122)
LE-чтения без проверок границ (вызывающий код проверяет длины).

### fn utf16le_to_string(b) -> String (строки 124-130)
chunks_exact(2) → u16 LE → String::from_utf16_lossy (нечётный хвостовой байт отбрасывается).

### fn parse_blocks(rec) -> Vec<Pv> (строки 133-167)
От HDR_LEN до конца части: tag=rec[i], len=rd_u32(i+1); не влезает → break. Match по тегам с точными длинами (см. таблицу тегов); неизвестный тег/несовпавшая длина → `continue` (блок молча пропускается, курсор уже сдвинут — структура не ломается).

### fn parse_meta(p) -> Option<(Vec<OpMeta>, Vec<String>, i32)> (строки 172-239)
Вход — ПОЛНАЯ запись (72-байтный Hdr + blob); проверяет `p[0]==OP_META`, начинает с i=HDR_LEN. Формат blob (комментарий 170-171, билдер MetaBuilder 0033:289-330):
```
[u16 n_bc][i32 reg_start]
n_bc × { name\0  [u8 n_ops][u8 flags][u8 acc_use]
         3 × ( [u8 total_size]  n_ops × ([u8 type][u8 offset]) ) }
[u16 n_rt]  n_rt × { name\0 }
```
Любая нехватка байт → None. Возвращает также reg_start (смещение r0 в регистровом файле) — в run() ОТБРАСЫВАЕТСЯ (`_rs`, строка 477): мёртвый возврат.

### fn parse_func_def_blob(func_id, line, blob) -> Option<FuncDef> (строки 244-293)
Формат (комментарий 241-243, билдер FuncDefBuilder 0033:255-283):
```
[0..4)   u32 bc_len
[4..8)   u32 name_len
[8..12)  u32 cp_bytes   (суммарный размер cp-блоков)
[12..16) i32 frame_size
[16..20) u32 param_count
[20..24) — не используется (C++ head=24, байты 20-23 нули)
[24..)   bc_len байт байткода | name_len байт имени | cp_bytes байт cp-блоков
```
cp-блоки: `[tag][u32 len][bytes]`; tag 8→Str, 13→Str16, 9(len==8)→F64(from_bits), любой другой len==8→Raw(u64), иначе→Raw(0). Проверка `24+bc_len+name_len+cp_bytes ≤ blob.len()` (258-260).

### fn parse_instr(rec, ts, pid) -> Option<InstrRec> (строки 295-311)
Отказ при len<72 или opcode ∈ {OP_FUNC_DEF, OP_META}. Поля: func_id=u32@8, offset=u32@4, opcode=rec[0], scale=rec[1], flags=rec[3], iso=u32@12, acc=u64@16, payloads=parse_blocks(rec).

### struct DecodedInstr (строки 313-316)
`offset: usize, opcode: u8` — результат статического прохода.

### fn decode_func(bc, meta) -> Option<Vec<DecodedInstr>> (строки 320-356)
Статический проход по массиву байткода БЕЗ вывода операндов — только размеры из meta:
- `Wide`/`DebugBreakWide`: реальный opcode = bc[off+1], scale_i=1, base=off+1;
- `ExtraWide`/`DebugBreakExtraWide`: opcode = bc[off+1], scale_i=2, base=off+1;
- иначе: opcode=bc[off], scale_i=0, base=off;
- opcode ≥ meta.len() → None (битый массив);
- `total = meta[rop].scales[scale_i].size + (base − off)` — размер инструкции вместе с префиксом;
- push DecodedInstr{offset: base (ЛОГИЧЕСКИЙ offset реальной инструкции, совпадает с offset'ами executed-записей), opcode: rop}; off += total.

### fn cp_json(cp, idx) -> Option<Value> (строки 358-365)
Str → lossy UTF-8; Str16 → utf16le_to_string; F64 → число; Raw → u64. Вне диапазона → None.

### fn block_starts_of(instrs, meta) -> Vec<usize> (строки 374-388)
Старты базовых блоков: offset первой инструкции + offset инструкции, СЛЕДУЮЩЕЙ за любой с `meta.flags & 3 != 0` (jump или returns). Сортировка. Комментарий 367-373 описывает семантику jump-subtype 1-4 (target = offset ± imm / cp[imm] / switch) и «cfg_edges» — но ФУНКЦИЯ ЦЕЛЕЙ ПЕРЕХОДОВ НЕ ВЫЧИСЛЯЕТ и рёбра не строит; subtype-биты (3-4) нигде в Rust не читаются. SERIES.md:82 обещает «per-function JSON (cfg_edges, live/dead блоки...)» — в report'е cfg_edges НЕТ (расхождение документации и кода).

### pub fn run(collect_dir) -> Result<Stats, String> (строки 390-783) — ПОШАГОВО
1. **(391-397)** index.jsonl; ошибка чтения → Ok(Stats::default()). raw_dir = collect_dir.
2. **(399-423)** Отбор записей `k=="bytecode-trace"` → (ts, pid, path, off, len); stats.records; пусто → Ok.
3. **(425-434)** Состояние: meta, rt_names, funcs: HashMap<func_id,FuncDef>, stream: Vec<InstrRec>, executed: HashMap<func_id, HashSet<offset>>, exec_count, first_ts, `parts: BTreeMap<(opcode,func_id), BTreeMap<u32 pos, Vec<u8>>>` — буфер cont-частей.
4. **(436-440)** Группировка записей по part-файлу (by_file), чтобы читать каждый bin один раз.
5. **(442-521)** Для каждого файла: blob целиком; для каждой записи срез `[off, off+len)` (границы/длина проверяются, 450-456); opcode=rec[0], flags=rec[3], func_id=u32@8:
   - **OP_META/OP_FUNC_DEF (461-490)**: payload rec[72..] аппендится в `parts[(opcode,func_id)][u32@4]` (позиция в blob = ключ порядка). Если `flags & FLAG_CONT == 0` — пришла последняя часть: весь map конкатенируется В ПОРЯДКЕ POSITIONS (BTreeMap), пересобирается «одночастевая» запись `rec[0..72] + full` и парсится: OP_META → parse_meta (meta, rt_names; reg_start выброшен); OP_FUNC_DEF → parse_func_def_blob(func_id, u32@12 = line, full) → funcs.insert; stats.funcs.
   - **Инструкция с FLAG_CONT (493-501)**: части копятся в parts[(opcode,func_id)][offset]; ПЕРВАЯ часть сохраняет ЦЕЛЫЙ 72-байтный заголовок перед payload'ем (`if e.is_empty() { e.extend(rec[0..72]) }`) — заголовок первой части задаёт семантику.
   - **Финальная инструкция (503-519)**: если для (opcode,func_id) есть накопленные части — склеить все (заголовок первой + payload'и всех) и parse_instr от склейки; иначе parse_instr от rec. Успех → instructions++, executed[func_id].insert(offset), exec_count++, first_ts (ПЕРВЫЙ встреченный ts, не минимум — файлы обходятся в порядке имён), stream.push.
   - Квирк: ключ склейки (opcode, func_id) без offset в parts.remove — если бы два разных cont-набора одного опкода/функции шли вперемешку, склейка смешалась бы; на практике поток последователен (один эмиттер на поток).
6. **(522-524)** meta пуста → `Err("bctrace: no meta record (0033 patch not active?)")` — единственная ошибка функции.
7. **(526-529)** Создать `filtered/bctrace/` и `filtered/bctrace/sem/`.
8. **(531-590) Per-function отчёты.** Для каждой FuncDef: decode_func (отказ → skip функции целиком, без лога), block_starts_of; блоки = [start_i, start_{i+1}) , последний — до bc_len. Блок LIVE если ЛЮБАЯ декодированная инструкция блока имеет offset ∈ executed[fid]; иначе DEAD + dead_ranges.push((bs,be)). live/dead_bytes = размеры блоков. stats.dead_blocks/live_blocks. Файл `filtered/bctrace/{func_id:08x}.json` (pretty):
   `{func_id, name, line, frame_size, param_count, bc_len, instructions, blocks, executions, live_blocks, dead_blocks, dead_ranges[[start,end]...], first_ts}`.
9. **(592-605) Поток результатов.** stream.sort_by_key(ts) (глобальная сортировка — ПОСЛЕ per-function отчётов, executed не зависит от порядка); next_same[(pid,iso)] = индексы по порядку; result_at[n] = следующий индекс того же (pid,iso). «Результат инструкции, пишущей acc = acc СЛЕДУЮЩЕЙ записи того же pid+isolate» — движковый dataflow без окон (комментарий 593-594, tools/bcrec_main.cc:8-10).
10. **(607-622)** api_calls: BTreeMap<String,u64>; api_values ≤8 уникальных на ключ; sem_files: File на func_id; closure `acc_of(r)`: только при `flags & FLAG_ACC_PAYLOAD` — первый payload из {Str, Str16, F64, Smi} → JSON.
11. **(624-750) Семантический проход** по stream:
    - meta[opcode] (нет → continue), def = funcs[func_id];
    - **args (632-665)**: из каждого `Pv::Operand(idx, v)`: для списка cp-опкод-имён (LdaConstant, LdaGlobal, LdaGlobalInsideTypeof, StaGlobal, LdaContextSlot, StaContextSlot, GetNamedProperty, SetNamedProperty, DefineNamedOwnProperty, AddNamedProperty, CallProperty{,0,1,2}, CallUndefinedReceiver{0,1,2}, CallWithSpread, Construct, ConstructWithSpread, TestReferenceEqual, JumpIfTrueConstant, JumpIfFalseConstant, LdaLookupGlobalSlot) при idx==0 → `cp_json(def.cp, v)` (буквальная строка из constant pool — «LdaGlobal cp[i] → буквально "navigator"»); для CallRuntime/CallRuntimeForPair при idx==0 → rt_names[v]; иначе/не резолвится → сырое число v;
    - **result (667-674)**: если `meta.acc_use & 2` (пишет acc) → acc_of(следующая запись того же (pid,iso));
    - **api-ключ (676-709)**: LdaGlobal*/StaGlobal → `"global <name>"`; GetNamedProperty*/SetNamedProperty/DefineNamedOwnProperty/AddNamedProperty → `"prop <name>"`; CallProperty*/CallWithSpread → `"call <name>"`; CallRuntime* → `"runtime <fn>"`. Счётчик ++; при наличии result — до ≤8 уникальных значений в api_values;
    - **sem-строка (711-749)**: файл `sem/{func_id:08x}.jsonl` (создаётся лениво, expect — паника при ошибке создания, единственная паника модуля); строка `{ts, off, op}` + условно `args[]`, `acc` (входное значение из FLAG_ACC_PAYLOAD), `res`, `regs[]` — все RegWord/RegStr/RegStr16/RegF64/RegSmi payload'и как `{reg, word|v}`.
12. **(752-761)** api_list = [{what, times, values?}] по api_calls (BTreeMap → сортировка по ключу).
13. **(763-781)** `filtered/bctrace.json` (pretty):
```
records, instructions, funcs, dead_blocks, live_blocks, dead_bytes, live_bytes,
funcs_reported, api_calls[{what,times,values?}],
rule: "dead = basic block whose offsets NEVER appear in the executed stream.
       Operand values engine-decoded at emit time. Result of a write-acc
       instruction = acc of the next same-(pid,iso) record. Facts only.",
functions[ <per-function json из шага 8> ]
```
14. **(782)** Ok(stats).

Модуля тестов в файле НЕТ — round-trip доказательство живёт в `tests/bcrec_roundtrip.rs` (g++ компилирует sink.cc из 0001 + bcrec.h из 0033 + tools/bcrec_main.cc, эмитит meta+func-def+3 инструкции, прогоняет через scan_once и bctrace::run; проверяет funcs=1, instructions=3, dead_blocks=1/dead_bytes=2, и sem-поток: LdaConstant args[0]=="secret-key" (cp-резолв), acc==7, res=="Mozilla/5.0" (аккумулятор следующей записи), Star0 regs содержит строку, Return без res).

## Взаимодействия (bctrace.rs)
- Вызывается из main.rs:552 (до sinkfilter — иначе raw-партии удалит main.rs:578-580) и из `src/bin/bcrec-dump.rs:8` (standalone: run + печать bctrace.json).
- Вход: `collect/index.jsonl` (kind bytecode-trace) + part-файлы `collect/raw/*-bytecode-trace-pNNNN.bin` (collect.rs BATCHED_KINDS).
- Производитель wire-данных: патч 0033 (v8/src/afeye/bcrec.h + runtime-trace.cc `Runtime_AfeyeTraceBytecodeEntry`, kind 40) через sink 0001.
- Выход: `collect/filtered/bctrace.json`, `collect/filtered/bctrace/<fid8>.json`, `collect/filtered/bctrace/sem/<fid8>.jsonl`.
- Крейты: serde_json; std collections. Env-переменных не читает (C++-гейты: AFEYE_SINK, AFEYE_TRACE_BYTECODE=0 выключает трейс, AFEYE_VIRTUAL_CLOCK, AFEYE_VCLOCK_NS_PER_INSTR — по умолчанию 10 нс/инструкция, 0033:502-523).

---

## АУДИТ СООТВЕТСТВИЯ ЭТАЛОНУ

Эталон: «тотальный инспектор JS-движка» из 4 слоёв + формат лога. Сравнение только с фактическим кодом репо.

### 1. JIT-отключение (`--jitless --no-opt --no-sparkplug`)
Факт — `src/browser.rs`, fn `chrome_flags`:
- `--jitless`: ЕСТЬ, browser.rs:98. Гейт: env `AF_JITLESS == "1"` (browser.rs:93), по умолчанию ВЫКЛЮЧЕН (opt-in).
- `--no-opt` и `--no-sparkplug`: ЕСТЬ, browser.rs:102 — одним argv-элементом `--js-flags=--no-opt --no-sparkplug` (chrome трактует остаток строки как v8-флаги), внутри того же гейта AF_JITLESS, добавлены незакоммиченным диффом (git: `M src/browser.rs`, HEAD dc1e253 не содержит строку 102).
- Соответствует эталону по составу флагов: browser.rs:93-103.
- Чего НЕ ХВАТАЕТ:
  1. `AF_JITLESS` НИГДЕ в репо не выставляется автоматически: grep по src/, scripts/, queue/, tools/ — только чтение (browser.rs:93) и упоминание в patches/SERIES.md:85 и .doc-parts. Дефолтный прогон идёт С JIT — трейс 0033 в таком режиме видит только интерпретируемые инструкции, hot-циклы после оптимизации слепы (это прямо противоречит цели «100% покрытие каждого шага» эталона). Требуется: включать AF_JITLESS=1 по умолчанию для прогонов с трейсом либо сетовать его в launch-обвязке.
  2. `--no-liftoff` (Wasm baseline) не выставляется нигде — Wasm-исполнение не покрыто байткод-трейсом (0033 — только Ignition); для полноты «тотального инспектора» Wasm остаётся на отдельных kinds (wasm-instance/wasm-memory, патчи 0020/0026/0028).
  3. `--jitless` уже запрещает генерацию кода, так что `--no-opt --no-sparkplug` избыточны (комментарий browser.rs:99-101 это признаёт — «контракт буквально»), это не дырка, а belt-and-suspenders.

### 2. Патч диспетчера Ignition
Эталон: хук в `GENERATE_BYTECODE_HANDLER` в `src/interpreter/interpreter-generator.cc`; фиксировать BytecodeOffset, опкод, аргументы (имя свойства из constant pool, регистры источника/приёмника), SharedFunctionInfo, имя скрипта.

Факт — `patches/0033-v8-ignition-bytecode-trace.patch`:
- Точка хука: НЕ interpreter-generator.cc и НЕ макрос GENERATE_BYTECODE_HANDLER. Хук стоит в `v8/src/interpreter/interpreter-assembler.cc` в КОНСТРУКТОРЕ `InterpreterAssembler::InterpreterAssembler` (hunk `@@ -48,6 +48,18 @@`, 0033:419-437): `CallRuntime(Runtime::kAfeyeTraceBytecodeEntry, GetContext(), BytecodeArrayTaggedPointer(), SmiTag(BytecodeOffset()), GetAccumulatorUnchecked(), SmiTag(operand_scale_))` (0033:430-433). Конструктор выполняется на этапе КОДГЕНА каждого handler'а, поэтому CallRuntime вкомпилирован в каждый bytecode-handler — функциональный эквивалент хука в генераторе, но в другом файле/другой точке. РАСХОЖДЕНИЕ с буквой эталона (interpreter-generator.cc не тронут), СООТВЕТСТВИЕ по покрытию (каждый dispatch → запись; комментарий 0033:420-428).
- Второй хук: `InlineShortStar` (hunk `@@ -1381,6 +1393,16 @@`, 0033:438-454) — Star0-Star15 инлайнятся в предыдущий handler и через конструктор не проходят; без второго хука самые частые инструкции были бы слепы (0033:440-443; SERIES.md:86). Эталон эту дыру не упоминает — фактическая реализация ПОЛНЕЕ.
- Регистрация runtime-функции: `v8/src/runtime/runtime.h` `FOR_EACH_INTRINSIC_AFEYE → F(AfeyeTraceBytecodeEntry, 4, 1, kCannotTriggerGC)` (0033:909-915), включён в FOR_EACH_INTRINSIC_TRACE (0033:920-926).
- Что фиксируется (RUNTIME_FUNCTION(Runtime_AfeyeTraceBytecodeEntry), v8/src/runtime/runtime-trace.cc, 0033:750-895):
  - BytecodeOffset: ДА — SmiTag(BytecodeOffset()) из хука, в Hdr.offset; логический offset пересчитан на 758-761.
  - Опкод: ДА — реальный байт по pc (0033:786-787), Hdr.opcode + scale из codegen-константы (Wide/ExtraWide точные, 0033:784-785).
  - Аргументы: ДА и глубже эталона — каждый операнд декодируется САМИМ ДВИЖКОМ (`BytecodeDecoder::DecodeRegisterOperand/DecodeSignedOperand`, 0033:817-866) и эмитится значением (kTagOperand); register-операнды дополнительно дампят сырое слово регистра И полное значение (String 8/16-bit, HeapNumber, Smi — 0033:830-849). Имя свойства из constant pool в самой записи НЕ эмитится — оно резолвится на Rust-стороне через cp-блоки func-def (bctrace.rs:637-653). Соответствует по сути, разбиение другое (pool едет один раз в func-def, не на каждую инструкцию).
  - SharedFunctionInfo: ДА, но НЕ указателем — `func_id = MakeFuncId(script_id, sfi->function_literal_id(), sfi->StartPosition(), iso_tag)` (0033:794-798), FNV-1a хэш GC-неподвижных фактов (bcrec.h 0033:117-134). Сильнее эталона: идентификатор переживает GC/перемещение SFI.
  - Имя скрипта: ДА — в func-def blob (Script::name, 0033:664-680), + номер строки функции (Hdr.line для func-def).
  - Аккумулялятор: сырое слово (Hdr.acc) + типизированный payload при String/HeapNumber/Smi (0033:872-884) — эталон не требует, факт полнее.
  - Dedup func-def: `thread_local unordered_set<(func_id, bc_len)>` без лимитов (0033:531-548, 800-803) — перекомпиляция с новой длиной массива переэмитит def.
  - Мета движка: один раз на процесс — ВСЕ bytecode'и (имена, n_ops, flags, acc_use, размеры по трём масштабам, операнд-таблицы) + ВСЕ runtime-имена (AfeyeEmitMeta, 0033:589-651).
  - Split: EmitSplit режет >983024-байтные записи на kFlagCont-части (bcrec.h 0033:333-362).
- РАСХОЖДЕНИЯ по пунктам: (а) файл/точка хука — interpreter-assembler.cc ctor + InlineShortStar вместо interpreter-generator.cc/GENERATE_BYTECODE_HANDLER; (б) «DispatchTable» эталона в modern V8 — это код-генерируемые handlers, реальный хук компилируется в сами handlers (эквивалент); (в) имя свойства не в каждой записи, а через cp func-def (резолвится в bctrace.rs). Всё остальное соответствует или превосходит.

### 3. Виртуализация таймингов
Эталон: `src/base/platform/time.cc` ИЛИ blink `Performance::now`; `virtual_time += kBaseInstructionCost * instruction_count`.

Факт — `patches/0034-v8-blink-virtual-clock.patch` (2 файла):
- `third_party/blink/renderer/core/timing/performance.cc` (hunk `@@ -1373,6 +1380,25 @@`, 0034:19-44): в `Performance::now()` при `AFEYE_VIRTUAL_CLOCK` (не "0") возвращается `g_afeye_origin_ms + afeye_vclock_ns()/1e6`, origin фиксируется один раз через `base::TimeTicks::Now().since_origin()` (0034:35-39). СООТВЕТСТВУЕТ ветке «Performance::now в blink».
- `v8/src/objects/js-objects.cc` (hunk `@@ -5914,6 +5918,25 @@`, 0034:60-82): `JSDate::CurrentTimeValue` (Date.now) → `epoch_ms + afeye_vclock_ns()/1e6`, эпоха-база один раз через `CurrentClockTimeMilliseconds()`.сверх эталона (Date.now тоже виртуализован).
- Счётчик: `g_vclock_ns` (std::atomic<u64>) в v8 sink.cc (0033:375-383), инкремент `VclockTick(AfeyeVclockNsPerInstr())` ВНУТРИ runtime-функции трейса на каждой инструкции (0033:768-770); шаг = env `AFEYE_VCLOCK_NS_PER_INSTR`, дефолт 10 нс (0033:517-523). Формула эталона `virtual_time += kBaseInstructionCost * instruction_count` реализована как `+= ns_per_instr` на каждую инструкцию (count накапливается имплицитно) — СООТВЕТСТВУЕТ, kBaseInstructionCost = AFEYE_VCLOCK_NS_PER_INSTR.
- Чего НЕ ХВАТАЕТ / расхождения:
  1. `src/base/platform/time.cc` НЕ тронут ни одним патчем (grep по patches/*.patch — 0 вхождений). Следствие: `base::TimeTicks::Now()` остаётся реальным для ВСЕХ прочих потребителей — планировщик setTimeout/задач blink, рафты, network-таймауты, `MonotonicTimeToDOMHighResTimeStamp` вне afeye-ветки. Виртуальное время видят только JS-поверхности performance.now/Date.now. Эталон допускает «ИЛИ», так что формально соответствует, но «таймауты не ломаются от замедления» (цель эталона) выполнено ЧАСТИЧНО: внутренние таймеры страницы тикают реальным временем.
  2. Счётчик глобальный на процесс, не на isolate (SERIES.md:87 признаёт: несколько вкладок делят счётчик).
  3. `performance.timeOrigin`, `Date` конструктор от системных часов, `Intl`, worker-часы не виртуализованы.
  4. Гранулярность Date.now — мс: при 10нс/инструкцию ~100k инструкций на тик (SERIES.md:87) — суб-мс дельта-атаки видят ступеньки.
  5. Тик происходит ТОЛЬКО когда трейс включён (VclockTick внутри Runtime_AfeyeTraceBytecodeEntry после гейтов Enabled()/AfeyeBcOff(), 0033:751-770): `AFEYE_TRACE_BYTECODE=0` + `AFEYE_VIRTUAL_CLOCK=1` → часы стоят на месте (виртуальное время не двигается вовсе) — неявная связка гейтов, в коде не оговорена.
  6. `AF_JITLESS`/`AFEYE_VIRTUAL_CLOCK` харнессом по умолчанию не выставляются (см. п.1) — виртуальные часы opt-in и в src/ никто их не включает (только комментарий browser.rs:97).

### 4. Перехват WebIDL/DOM-биндингов
Эталон: патч `src/bindings/core/v8/` (V8DOMConfiguration), логировать геттер/сеттер интерфейса с АРГУМЕНТАМИ и ТИПОМ возвращаемого значения.

Факт:
- Точка: НЕ `core/v8/`, а `platform/bindings/idl_member_installer.cc` (0008:1-4; 0024:1-4). Это уровень, где blink ставит ВСЕ IDL-атрибуты и операции в v8-шаблоны (`CreateFunctionTemplate`/`InstallAttribute`/`InstallOperation`) — покрытие ШИРЕ, чем V8DOMConfiguration (которая тоже зовёт idl_member_installer). РАСХОЖДЕНИЕ по файлу, соответствие/превосходство по охвату.
- Механика (0008): оригинальный callback оборачивается в `AfeyeDomApiThunk` через data-slot `v8::External` (0008:94-112), идентичность хранится в пуле 64K ячеек `AfeyeApiCell{orig, prop, what[104]}` (0008:24-32), строка `what` = `"dom <Interface>.<get|set|call> <property>"` (0008:68-69). Эмитит kind 29 (kDomApi) текстом. Гейт: общий `Enabled()` + лимит 8 000 000 вызовов на процесс (0008:41-42, 0024:71-72).
- Возвращаемое значение (0024): `AfeyeCaptureValue` (0024:25-58) — тип-дифференцированный рендер: `undefined`, `null`, bool → `0|1`, number → `%.17g`, string → до 150 байт UTF-8 с санитизацией не-printable в '?', Array → `[array len=N]`, прочее → `[object]`. Запись: `"<what> val=%.150s"` (0024:80-89). Гейт значений: `AFEYE_TRACE_DOM_VALUES=0` выключает захват значения (0024:20-23) — по умолчанию ЗНАЧИНИЯ ВКЛЮЧЕНЫ. Порядок: значение снимается ПОСЛЕ вызова оригинала (0024:73-82).
  - ТИП возвращаемого значения: ЧАСТИЧНО — явного поля типа нет; тип различим по форме рендера (число/строка/[object]/[array len]/null/undefined/bool). Не соответствует буквально «тип возвращаемого значения» как отдельное поле, но информация о типе сохраняема.
  - АРГУМЕНТЫ вызова: НЕ логируются в kDomApi-записи (thunk пишет только what+val; `info` аргументы не снимаются). НЕ соответствует эталону; частично компенсируется: (а) 0019 эмитит аргументы конкретных FP-поверхностей вручную — `css/get-computed prop=<имя> val=<CssText>` (0019:40-44), `fonts/check font=... text=...` (0019:90-94), `media/matches q=... m=...` (0019:139-142), `media/query q=...` (0019:187-190), `canvas/draw-text op=... text=... font=... xy=...` (0019:229-233), `perm/notification value=...` (0019:299-302), `perm/query name=...` (0019:333-336) — все kind 16 (kFingerprint); (б) 0013 (cookie/storage) и 0014 (readback) эмитят значения своих операций; (в) для JS-вызовов DOM аргументы восстанавливаются из байткод-трейса (0033 → bctrace sem: CallProperty args через cp). Требуется, если нужен полный контракт эталона: снимать `info[i]` в AfeyeDomApiThunk тем же AfeyeCaptureValue.
- 0019 к `src/bindings/core/v8/` отношения не имеет — это ручные хуки 7 конкретных .cc (css_computed_style_declaration, font_face_set, media_query_list, local_dom_window, base_rendering_context_2d, notification, permissions).

### 5. Финальный формат лога
Эталон: для каждой операции — `timestamp_virtual, script_id, function_name, bytecode_op, target_property, arguments_hash`; JSONL/protobuf.
Реальная цепочка: бинарный wire 0033 (Hdr 72B + тегированные блоки) → collect.rs (index.jsonl + raw-партии) → bctrace.rs (`sem/<func_id:08x>.jsonl` + per-function JSON + bctrace.json).

| Поле эталона | Есть реально | Где именно | Что делать, если нет |
|---|---|---|---|
| timestamp_virtual | ЧАСТИЧНО — `ts` в sem-строках = РЕАЛЬНЫЙ CLOCK_MONOTONIC (sink `NowNs()=MonoNs()`, 0001:92-97,235), не vclock | bctrace.rs:716 (`"ts": r.ts`), источник ts — index.jsonl (collect.rs:347); эмиттер: 0033:584 (`v8::afeye::NowNs()`) | Если нужен именно виртуальный ts: писать в Hdr/reserved поле `afeye_vclock_ns()` на эмите (есть regs/line-слоты заняты; потребуется новая версия wire) либо на Rust-стороне пересчитывать ts через калибровку (инструкции × ns_per_instr от nav_start) — в коде не сделано НИ того ни другого |
| script_id | ЧАСТИЧНО — в wire участвует только ВНУТРИ MakeFuncId (хэш), отдельным полем не эмитится; в func-def есть имя скрипта и line | 0033:794-798 (MakeFuncId(script_id,...)), 0033:664-680 (script name/line → FuncDef); Rust: bctrace.rs:60-68 (FuncDef.line/name), per-function json `"line"` (bctrace.rs:571) | Добавить script_id u32 в func-def blob (свободны байты 20..24 заголовка blob, parse_func_def_blob:249-257 их не читает) и вывести в report |
| function_name | ЧАСТИЧНО — FuncDef.name = ИМЯ СКРИПТА (Script::name), не имя функции; имя функции в wire отсутствует | 0033:664-680 (name из `sc->name()`); Rust: bctrace.rs:570 (`"name": def.name`) | Эмитить `sfi->Name()` отдельным блоком в func-def; сейчас «function_name» эталона покрыт только script-level |
| bytecode_op | ДА | sem-строка `"op": m.name` — bctrace.rs:718 (имя из meta-таблицы движка, 0033:624-627 `Bytecodes::ToString(bc)`) | — |
| target_property | ДА | sem `"args"` — bctrace.rs:632-665 (cp-резолв имён для GetNamedProperty/CallProperty/LdaGlobal/...), api-ключи `"prop X"/"call X"/"global X"/"runtime X"` — bctrace.rs:676-700; подтверждено roundtrip-тестом (tests/bcrec_roundtrip.rs:168-171: args[0]=="secret-key") | — |
| arguments_hash | НЕТ как хэш — вместо него ПОЛНЫЕ значения операндов (сильнее хэша, но другое поле) | значения: Pv::Operand — bctrace.rs:159-161 (engine-decoded), regs/acc payloads — 0033:817-884; в sem: `"args"`, `"acc"`, `"res"`, `"regs"` — bctrace.rs:715-749 | Если хэш нужен для компактности — считать blake3 от args на Rust-стороне при генерации sem (1 строка), в wire не нужно |
| Формат JSONL | ДА | sem/*.jsonl (bctrace.rs:711-749), index.jsonl (collect.rs:344-390) | protobuf не используется нигде — эталон допускает JSONL |

Дополнительно сверх эталона в логе есть: `off` (bytecode offset), `acc` (входной аккумулятор), `res` (результат write-acc инструкции = acc следующей записи того же pid+iso, bctrace.rs:592-605, 667-674), `regs` (значения регистров), `executions`/`first_ts` на функцию, live/dead блоки ПО ФАКТУ (offset никогда не встречен в executed-потоке, bctrace.rs:544-563), api_calls-сводка (bctrace.rs:752-761).

### Сводные дырки и несоответствия, найденные при чтении (не эталон)
1. `drops_witnessed` игнорирует pid (sinkfilter.rs:405-410), ключ отчёта `ring_drops_in_pid` (2057) вводит в заблуждение — свидетель глобальный.
2. `Chain.net_adjacent` — write-only поле (1941), в отчёт не попадает (в отличие от content_sink:2003).
3. `run()` sinkfilter никогда не возвращает Err — сигнатура `Result<_, String>` фиктивна (1019-1022).
4. `stats.records` считает sink-hello (1030 до skip 1032) — `records ≥ records_indexed` всегда.
5. Строка `graph.rule` (2219) перечисляет 5 payload_kinds, в коде их 7 (+wasm-memory, +fingerprint, 1413-1421).
6. collect.rs MAX_RECORD=16+1MiB против C++ kMaxRecord=1MiB (16 байт запаса); plausible-проверка `flags <= 1` (collect.rs:284,297) отвергнет любые будущие флаги sink-заголовка как corrupt.
7. collect.rs text_preview (408-410) отбрасывает последний символ валидного превью при payload>4096 (cut = индекс последнего char, а не len).
8. PartWriter::push при ошибке открытия следующего part молча продолжает в старый файл без сброса written (133-140) — вечные попытки ролла; при write_all-ошибке запись теряется без счёта ошибок (нет счётчика в Stats).
9. part_writer открывает существующий part в append, но written=0 — offset'ы корректны только для свежего out_dir.
10. chain_report/net_chains обрезаются take(4000)/<4000 (1989, 2172) молча — stats полные, отчёт нет.
11. sanitize даёт до 121 символа (2302-2304, проверка после push).
12. executed_funcs-join по точному имени цепи (1815-1825) не использует canon_name/iso-нормализацию, в отличие от entry-join (1666, 1674) — имена с iso-префиксом уже сняты split_iso, но «:line» хвосты lazy-compile срезаются (1805-1810), а exec_per_name нормализован через split_iso (1129) — разные пути нормализации могут не совпасть.
13. bctrace: `OpScaleMeta.ops` парсится и не используется (207-215); `InstrRec.scale`/`InstrRec.acc` присваиваются и не читаются (305,308); reg_start из parse_meta выбрасывается (477); `first_ts` = первый встреченный ts в порядке обхода ФАЙЛОВ, не минимум (517).
14. bctrace: комментарий 367-373 и SERIES.md:82 обещают CFG-рёбра/цели переходов (subtype 1-4) — `block_starts_of` (374-388) считает только старты блоков по flags&3, `cfg_edges` в per-function JSON (568-582) отсутствует.
15. decode_func-отказ (битый/незнакомый opcode) молча выбрасывает функцию из отчётов (534-537) — funcs_reported < funcs без диагностики.
16. FP_API_NEEDLES содержит дубль `Navigator.get userAgent` (98 и 109) — второй недостижим.
17. sem-файл создаётся через `.expect("sem file")` (bctrace.rs:713) — паника вместо graceful error при исчерпании fd/permissions.
18. `--js-flags=--no-opt --no-sparkplug` (browser.rs:102) — незакоммиченное изменение рабочего дерева (git status: M src/browser.rs).
