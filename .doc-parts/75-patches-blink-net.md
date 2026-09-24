# Патчи blink/net-стороны (0005–0019, 0023–0025, 0029, 0030, 0032)

Все патчи применяются к дереву Chromium. В репозитории `/home/xarle/afeye` самого дерева Chromium НЕТ — только `patches/*.patch`, поэтому все утверждения ниже вычитаны из текста патчей и из Rust-кода `src/`. Утверждения о том, как устроен немодифицированный Chromium/V8 (например, что `interpreter-generator.cc` использует `InterpreterAssembler`), помечены как `[INFERENCE]`.

Общий принцип всей серии: каждый слой (v8, blink, net) имеет СВОЙ sink — отдельная копия одного и того же ring-буфера, свой `kLayer`, свой файл `<layer>-<pid>.rec` в `AFEYE_RAW_DIR`. Слои не разделяют состояние. Номер kind общий на все три слоя и расшифровывается таблицей `KINDS` в `src/collect.rs:16-57`.

---

## Wire-формат записи (общий для всех трёх sink'ов)

Задаётся в `EmitFlags`. Раскладка 16-байтного заголовка (little-endian), одинаковая в v8/blink/net:

| смещение | тип | значение |
|---|---|---|
| 0..4 | u32 LE | `total` — полная длина записи ВКЛЮЧАЯ 16-байтный заголовок |
| 4 | u8 | `kind` — номер события из `EventKind` |
| 5 | u8 | `flags` — bit0 = payload был усечён |
| 6..8 | u8 | зарезервировано, всегда 0 |
| 8..16 | u64 LE | `ts_ns` — `CLOCK_MONOTONIC`, НЕ epoch, НЕ виртуальные часы |
| 16.. | bytes | payload |

Валидация на стороне Rust: `src/collect.rs:294-299` требует `total>=16`, `total<=MAX_RECORD` (= `16 + (1<<20)`, `collect.rs:11`), `kind<=MAX_KIND` (= `KINDS.len()-1` = 40, `collect.rs:71`), `flags<=1`, байты 6 и 7 равны 0. При нарушении — `stats.corrupt += 1` и побайтовый сдвиг на 1 с поиском следующего правдоподобного заголовка (`collect.rs:300-321`).

Два формата payload:
- **prose** (`EmitStr`) — просто C-строка без NUL внутри. `name_of` (`sinkfilter.rs:282-290`) не находит NUL → возвращает `tag = ""`, `body = весь payload`.
- **span** (`EmitSpan`) — `tag \0 bytes`. Тег обрезается до 64 байт (`sink.cc:265-266` в blink / `afeye_sink.cc:255-256` в net).
- **two-str** (`EmitTwoStr`) — `a \0 b`, то есть частный случай span, где «тег» — первая строка.

---

## patches/0005-blink-sink.patch — blink-слой sink: ring-буфер, drain-поток, API эмиссии

Трогает 3 файла:
1. `third_party/blink/renderer/platform/BUILD.gn` — добавляет GN-аргумент `blink_enable_afeye = false` и `config("afeye_config") { defines = [ "BLINK_AFEYE" ] }`; при `blink_enable_afeye` в `component("platform")` добавляются `afeye/sink.cc`, `afeye/sink.h` и `public_configs = [ ":afeye_config" ]`.
2. `third_party/blink/renderer/platform/afeye/sink.cc` — новый файл, 323 строки.
3. `third_party/blink/renderer/platform/afeye/sink.h` — новый файл, 58 строк.

### enum EventKind : uint8_t  (sink.h, строки 13-36)
- назначение: номера kinds blink-стороны. Общий номерной пространство с v8 и net.
- что внутри: `kSinkHello=0`, `kCryptoOp=11`, `kTimer=12`, `kPerfEntry=13`, `kMessage=14`, `kStructuredClone=15`, `kFingerprint=16`, `kWebSocket=19`, `kClientHints=20`, `kSwCache=21`, `kScriptSource=22`, `kInput=23`, `kEventDispatch=24`, `kDomMetric=25`, `kAudio=26`, `kWebrtc=27`, `kFetch=28`, `kDomApi=29`, `kClock=33`, `kWorker=35`, `kNavStart=36`, `kTaintEdge=37`. Позже 0023 добавляет `kSinkDrop=39`.
- связи: номера совпадают с индексами `KINDS` в `src/collect.rs:16-57`, оттуда берутся строковые имена.

### Объявления sink.h (строки 38-51)
`Enabled()`, `NowNs()`, `EmitFlags()`, `Emit()`, `EmitStr()`, `EmitTwoStr()`, `EmitSpan()`, `SinkDropped()`, `extern std::atomic<uint64_t> g_afeye_taint` (строка 37 — единственный extern-счётчик, общий для всех blink-патчей), `Flush(uint32_t timeout_ms)`, `SetTag(const char*)`, `const char* Tag()`.

### Константы sink.cc (строки 33-36)
- `kRingBytes = 8u << 20` (8 MiB)
- `kMaxRecord = 1u << 20` (1 MiB) — потолок одной записи
- `kSpanCap = 64u * 1024u` (64 KiB) — потолок payload у `EmitSpan`
- `kLayer = "blink"` — префикс имени файла и метка в hello-записи

### Глобальное состояние sink.cc (строки 38-49, 71, 305)
- `g_on` (atomic bool) — включён ли sink; ставится только в `InitOnce` при `EnvOn()`.
- `g_dropped` (atomic u64) — счётчик записей, не влезших в ring.
- `g_init_once` (std::once_flag) — защита `InitOnce`.
- `g_pid` (atomic pid_t) — pid, которому принадлежит текущий drain-поток; используется для детекта fork.
- `g_write_err` (atomic u64) — счётчик ошибок `write(2)`.
- `struct Ring` (строки 43-48): `std::atomic_flag lock`, `size_t head`, `size_t tail`, `uint8_t data[kRingBytes + kMaxRecord]`. Размер массива `8 MiB + 1 MiB` — запас, чтобы запись длиной до `kMaxRecord` никогда не «переезжала» границу кольца: при нехватке места запись дропается, а не оборачивается.
- `g_ring` — единственный статический экземпляр Ring (строка 49).
- `static thread_local char g_afeye_tag[97]` (строка 305) — буфер контекстного тега, см. `SetTag`.

### fn MonoNs()  (sink.cc, строки 51-56)
- назначение: источник времени для всех записей.
- что внутри: `clock_gettime(CLOCK_MONOTONIC)` → `sec*1e9 + nsec`.
- связи: зовётся из `NowNs()` и из `EmitHello`.

### fn EnvOn()  (sink.cc, строки 58-61)
- назначение: env-гейт всего blink-слоя.
- что внутри: `getenv("AFEYE_SINK")`; true если переменная задана, непуста и первый символ не `'0'`. То есть `AFEYE_SINK=1` включает, `AFEYE_SINK=0` и отсутствие переменной — выключают.
- связи: единственный вызов — `InitOnce`.

### fn RawDir()  (sink.cc, строки 63-70)
- назначение: каталог для `.rec`-файлов.
- что внутри: `static const char*`, инициализируется один раз из `getenv("AFEYE_RAW_DIR")`; если не задан или пуст — `"/tmp/afeye-raw"`.
- связи: `DrainLoop` (путь файла), `InitOnce` (mkdir/chmod). Совпадает с `DEFAULT_RAW_DIR` в `src/collect.rs:10`.

### fn WriteAll(int fd, const uint8_t* p, size_t n)  (sink.cc, строки 73-85)
- назначение: неблокирующая по EINTR запись всех байт.
- что внутри: цикл `write(2)`; `errno==EINTR` → continue; любая другая ошибка → `g_write_err.fetch_add(1)` и return (запись теряется ЦЕЛИКОМ, частично записанный хвост остаётся в файле); `w==0` → return.
- связи: `EmitHello`, `DrainLoop`, `WriteDropReport` (0023).

### fn EmitHello(int fd)  (sink.cc, строки 87-103)
- назначение: маркер начала/переоткрытия файла.
- что внутри: формирует строку `"afeye-sink/blink v2 pid=<pid>"` (буфер 96 байт), пишет её как запись kind=0, flags=0, резервные байты 6-7 = 0, ts = `MonoNs()`.
- связи: вызывается из `DrainLoop` при каждом успешном `open`. Парсится в Rust как `kind == "sink-hello"` (`collect.rs:17`).

### fn DrainLoop()  (sink.cc, строки 105-155)
- назначение: единственный потребитель ring'а; отдельный detached-поток.
- что внутри: путь `<RawDir()>/blink-<pid>.rec`; `open(O_CREAT|O_APPEND|O_WRONLY, 0666)`; `thread_local std::vector<uint8_t> buf` размером `kMaxRecord`. Бесконечный цикл: спин-лок на `g_ring.lock.test_and_set(acquire)` с `std::this_thread::yield()` каждые 64 итерации; если `tail != head` — читает u32-длину, при `len<16 || len>kMaxRecord` СБРАСЫВАЕТ всё кольцо (`tail = head`, данные теряются молча, `g_dropped` не инкрементируется), иначе копирует запись в `buf` и продвигает `tail` с wrap-around по `kRingBytes`. После освобождения лока пишет запись; если `g_write_err` изменился — закрывает fd и переоткрывает (с новым `EmitHello`). Если записей не было — `sleep_for(500us)`.
- связи: стартует из `InitOnce` и из `ReinitAfterFork`. 0023 добавляет в конец тела цикла блок drop-репорта.

### fn InitOnce()  (sink.cc, строки 157-165)
- назначение: ленивая инициализация под `std::call_once`.
- что внутри: если `!EnvOn()` — немедленный return (sink остаётся выключенным навсегда для этого процесса). Иначе `mkdir(RawDir(), 0777)`, `chmod(RawDir(), 0777)`, `g_on.store(true)`, `g_pid.store(getpid())`, `std::thread(DrainLoop).detach()`, `std::atexit([]{ Flush(500); })`.
- связи: единственный вызов — `Enabled()`.

### fn ReinitAfterFork()  (sink.cc, строки 167-179)
- назначение: восстановление после `fork()` в потомке.
- что внутри: **guard**: если `!g_on` — только обновляет `g_pid` и возвращает управление (поток НЕ создаётся, файл НЕ открывается). Иначе сбрасывает lock, `tail=head=0`, `g_dropped=0`, `g_pid=getpid()`, запускает новый `DrainLoop`.
- связи: вызывается из `Enabled()` при смене pid. **Отличие от net-слоя**: в `services/network/afeye_sink.cc:151-158` этого guard'а НЕТ — см. раздел 0011.

### fn Enabled()  (sink.cc, строки 182-192)
- назначение: точка входа, которую вызывает КАЖДЫЙ хук во всех blink-патчах.
- что внутри: `std::call_once(g_init_once, InitOnce)`; затем сравнивает `g_pid` с `getpid()` и при несовпадении делает `compare_exchange_strong` → `ReinitAfterFork()`. Возвращает `g_on.load(acquire)`.
- связи: этот вызов стоит в начале буквально каждого `#ifdef BLINK_AFEYE`-блока во всех патчах 0006–0032.

### fn NowNs()  (sink.cc, строка 194)
Однострочник: `return MonoNs();`.

### fn EmitFlags(uint8_t kind, uint64_t ts_ns, uint8_t flags, const void* data, uint32_t len)  (sink.cc, строки 196-228)
- назначение: единственная функция, которая реально кладёт байты в ring.
- что внутри: ранние выходы — `!g_on`; `data==nullptr || len==0`. Усечение: если `len > kMaxRecord - 16` → `len = kMaxRecord-16`, `flags |= 1`. `need = 16 + len`. Бесконечный спин на `g_ring.lock` БЕЗ yield (в отличие от DrainLoop). Вычисляет `used = (h>=t) ? h-t : kRingBytes-t+h`; если `kRingBytes - used < need + 8` → освобождает лок, `g_dropped.fetch_add(1)`, return (запись дропается). Иначе пишет заголовок (`total`, `kind` в байт 4, `flags` в байт 5, нули в 6-7, `ts_ns` в 8..16) и `memcpy` payload; продвигает `head` с wrap-around.
- связи: все остальные Emit*-обёртки.

### fn Emit / EmitStr / EmitTwoStr / EmitSpan  (sink.cc, строки 230-282)
- `Emit(kind, ts, data, len)` — прямой вызов `EmitFlags` с `flags=0`. В blink-патчах НЕ используется ни разу (проверено grep'ом по всем патчам).
- `EmitStr(kind, ts, s)` — `strlen(s)`, `flags=0`. NULL → return.
- `EmitTwoStr(kind, ts, a, b)` — склеивает `a \0 b` в `thread_local std::string`; `kCap = kMaxRecord - 17 = 1048559`; если `la > kCap` или `lb > kCap - la` — обрезает и ставит `flags=1`.
- `EmitSpan(kind, ts, tag, bytes, n)` — склеивает `tag \0 bytes` в `thread_local std::vector<char>`; тег обрезается до 64 байт; если `n > kSpanCap` (64 KiB) → `n = kSpanCap`, `flags=1`. Любой из `tag/bytes == nullptr` или `n==0` → return (запись НЕ создаётся).
- связи: `EmitStr` — основной способ для prose-записей; `EmitSpan` — для бинарных payload с тегом.

### fn SinkDropped()  (sink.cc, строки 284-287)
Возвращает `g_dropped + g_write_err`. В blink-патчах никто не вызывает (внешний消费者 — 0023 через drop-репорт, который читает `g_dropped` напрямую, БЕЗ `g_write_err`).

### fn Flush(uint32_t timeout_ms)  (sink.cc, строки 289-303)
- назначение: дожидаться опустошения ring'а.
- что внутри: если `!g_on` → сразу `true`. До дедлайна крутит: спин-лок, проверка `tail == head`, освобождение лока, `sleep_for(200us)`. Возвращает `true` если ring пуст, `false` если истёк таймаут.
- связи: `std::atexit` в `InitOnce` с `timeout_ms=500`.

### fn SetTag(const char* s) / const char* Tag()  (sink.cc, строки 305-320)
- назначение: thread_local «контекст» — какой event/timer сейчас исполняется.
- что внутри: `SetTag` копирует до 96 байт в `g_afeye_tag[97]`, NULL → очистка. `Tag()` возвращает указатель (никогда не NULL, минимум пустая строка).
- связи: **пишут** только 0006 (`event_dispatcher.cc` — `"evt:<type>"`, `dom_timer.cc` — `"timer:<id>"`). **Читают** 0006 (`resource_fetcher.cc` — поле `ctx=` в fetch-записи) и 0007 (все `dom/*`-записи — поле `ctx=`). Это единственный механизм атрибуции DOM-метрик к событию/таймеру. Поскольку буфер thread_local и никто его не очищает после завершения обработчика, `ctx=` может содержать УСТАРЕВШИЙ тег предыдущего события того же потока.

### Отличия blink sink от v8 sink (0001)
| аспект | v8 (`v8/src/afeye/sink.cc`) | blink (`platform/afeye/sink.cc`) | net (`services/network/afeye_sink.cc`) |
|---|---|---|---|
| `kLayer` | `"v8"` | `"blink"` | `"net"` |
| `kRingBytes` | 8 MiB | 8 MiB | 8 MiB |
| `kMaxRecord` | 1 MiB | 1 MiB | 1 MiB |
| `kSpanCap` | 64 KiB | 64 KiB | **256 KiB** |
| `SetTag`/`Tag()` | НЕТ | **ЕСТЬ** (строки 305-320) | НЕТ |
| `g_afeye_taint` | НЕТ | **ЕСТЬ** (строка 7, extern в sink.h:37) | НЕТ |
| `EmitWasmMemGrow` | ЕСТЬ | НЕТ | НЕТ |
| `afeye_vclock_ns`/`VclockTick` | ЕСТЬ (добавлено 0033) | НЕТ (blink читает через `extern "C"`, 0034) | НЕТ |
| guard в `ReinitAfterFork` | — | **ЕСТЬ** (`if (!g_on) { …; return; }`) | **НЕТ** |
| `thread_local pid_t t_pid` | ЕСТЬ | НЕТ | НЕТ |
| порядок `InitOnce`/`ReinitAfterFork` | — | InitOnce(157), Reinit(167) | Reinit(151), InitOnce(160) |

---

## patches/0011-net-wire.patch — net-слой sink + перехват HTTP/WS в network service

Трогает 5 файлов: `services/network/BUILD.gn`, `services/network/afeye_sink.cc` (новый, 300 строк), `services/network/afeye_sink.h` (новый, 38 строк), `services/network/url_loader.cc`, `services/network/websocket.cc`.

### BUILD.gn
Добавляет `declare_args() { network_enable_afeye = false }` и в `component("network_service")` при включённом аргументе — `sources += [ "afeye_sink.cc", "afeye_sink.h" ]`, `defines += [ "NET_AFEYE" ]`. В отличие от blink, здесь `defines` добавляются в сам target, а не через отдельный `public_config`.

### enum EventKind (afeye_sink.h, строки 12-17)
`kSinkHello=0`, `kNetReq=17`, `kNetRespBody=18`, `kWebSocket=19`. Позже 0023 добавляет `kSinkDrop=39`.
Это МИНИМАЛЬНЫЙ enum из трёх слоёв: net-слой эмитит всего 3 осмысленных kind'а.

### Объявления afeye_sink.h (строки 19-29)
`Enabled`, `NowNs`, `EmitFlags`, `Emit`, `EmitStr`, `EmitTwoStr`, `EmitSpan`, `SinkDropped`, `Flush`. **НЕТ** `SetTag`/`Tag()` и **НЕТ** `g_afeye_taint`.

### Реализация afeye_sink.cc (строки 27-300)
Побайтово повторяет blink-версию, кроме:
- `kSpanCap = 256u * 1024u` (строка 29) — вчетверо больше blink'овского; нужно потому, что тела HTTP-ответов крупные.
- `kLayer = "net"` (строка 30) → файл `net-<pid>.rec`.
- `ReinitAfterFork` (строки 151-158) **НЕ имеет guard'а** `if (!g_on) return;`.

> **НАЙДЕННЫЙ БАГ (net-слой).** `Enabled()` (строки 172-183) при первом вызове делает `call_once(InitOnce)`; если `AFEYE_SINK` не задан, `InitOnce` возвращает управление, не трогая `g_pid` (остаётся 0) и `g_on` (остаётся false). Далее `if (g_pid.load() != me)` → `0 != <pid>` → true → `compare_exchange_strong(0, me)` succeeds → `ReinitAfterFork()`, который БЕЗО ВСЯКИХ ПРОВЕРОК сбрасывает ring, ставит `g_pid` и **запускает `std::thread(DrainLoop).detach()`**. `DrainLoop` открывает `<RawDir()>/net-<pid>.rec` и пишет hello-запись kind=0 (вызов `EmitHello` не гейтирован по `g_on`). Дальше поток вечно крутится с `sleep_for(500us)`, потому что `EmitFlags` при `!g_on` возвращает управление сразу и ring всегда пуст.
> Итог: net-слой **создаёт файл и вешает вечный поток даже при полностью выключенном sink**. В blink-слое тот же сценарий отрабатывает корректно благодаря guard'у в `ReinitAfterFork` (`blink sink.cc:167-171`). Если `/tmp/afeye-raw` не существует, `open` падает, `fd=-1`, файл не создаётся — но поток всё равно висит.

### Хук: URLLoader::SetUpUpload (url_loader.cc, hunk `@@ -633,6 +637,31 @@`)
- почему здесь: это единственная точка, где тело запроса уже полностью материализовано в `request.request_body` как вектор `DataElement`, но ещё не ушло в сокет.
- что делает: обходит `*request.request_body->elements()`; элементы с `type() != DataElement::Tag::kBytes` пропускаются (то есть file-элементы multipart-загрузки НЕ перехватываются — только inline-байты). Для каждого bytes-элемента: `EmitSpan(kNetReq, NowNs(), "req-body", bytes.data(), bytes.size())`. Накапливает `afeye_total`; если > 0 — дополнительно `EmitStr(kNetReq, …, "req-body-total=<N>")`.
- kind/tag: **17 `net-request`, tag `req-body`** (+ prose `req-body-total=N`).
- лимиты: НЕТ ни счётчика, ни явного клампа. Действует только `kSpanCap=256KiB` внутри `EmitSpan`.
- Rust: **это sink-seed.** `sinkfilter.rs:1487-1488`: `is_upload = r.kind == "net-request" && (tag == "req-body" || tag == "req-body-stream")`.

### Хук: URLLoader::ScheduleStart (url_loader.cc, hunk `@@ -739,6 +768,20 @@`)
- почему здесь: последняя точка перед реальной отправкой; `url_request_` уже содержит финальные method/URL/заголовки.
- что делает: `EmitTwoStr(kNetReq, NowNs(), url_request_->method().c_str(), url_request_->url().spec().c_str())` → payload `METHOD \0 URL`. Затем, если `extra_request_headers().ToString()` непуста — `EmitTwoStr(kNetReq, …, "req-headers", headers)`.
- kind/tag: **17 `net-request`**, tag = HTTP-метод (`GET`/`POST`/…) или `req-headers`.
- лимиты: НЕТ.
- Rust: `is_query_sink` (`sinkfilter.rs:1494-1497`) = `kind=="net-request" && HTTP_METHODS.contains(tag) && (query_len >= QUERY_SINK_MIN_BYTES(96) || af_vendor_of_url(body).is_some())`. То есть method-запись становится sink'ом только при длинном query (≥96 байт) или при совпадении хоста со списком антифрод-вендоров `AF_VENDORS` (`sinkfilter.rs:212-230`: cloudflare, datadome, kasada, human/perimeterx, akamai, fpjs, seon, arkose, hcaptcha, imperva, threatmetrix). Запись `req-headers` — НЕ sink, только carrier-узел.
- Также `sinkfilter.rs:1399-1410` separately собирает `net_ts` (окна сетевой активности) по тем же method-записям: `non_get || vendor`.

### Хук: URLLoader::ContinueOnResponseStarted (url_loader.cc, hunk `@@ -1195,6 +1238,28 @@`)
- что делает: из `url_request_->response_info().headers` берёт `raw_headers()` → `EmitTwoStr(kNetRespBody, …, "resp-headers", raw)`; затем `GetMimeType(&mime)` → `EmitStr(kNetRespBody, …, "resp-mime=<mime> code=<code>")`.
- kind/tag: **18 `net-resp-body`**, tag `resp-headers` / prose `resp-mime=… code=…`.
- лимиты: НЕТ.
- Rust: **полностью мёртвый kind.** `"net-resp-body"` встречается в `src/` РОВНО ОДИН раз — `collect.rs:34` (таблица имён). В `sinkfilter.rs` его нет ни в `payload_kinds` (строки 1413-1421), ни в диспетчере kind'ов (1076-1168), ни в `interest`-фильтре (1692-1695). Записи индексируются и попадают в `raw/`, но в анализе не участвуют вообще.

### Хук: URLLoader::DidRead (url_loader.cc, hunk `@@ -1647,6 +1712,18 @@`)
- почему здесь: точка, где прочитанные из сокета байты уже лежат в `pending_write_->buffer()` и вот-отк поедут в mojo-пайп клиенту.
- что делает: условие `pending_write_ && num_bytes > 0 && !into_slop_bucket`; `EmitSpan(kNetRespBody, …, "resp-body", buffer+new_data_offset, min(num_bytes, 0x40000))`.
- kind/tag: **18 `net-resp-body`**, tag `resp-body`. Кламп 0x40000 = 262144 = ровно `kSpanCap` net-слоя, то есть избыточен (EmitSpan всё равно обрежет до 262144).
- лимиты: НЕТ счётчика. Каждый чанк тела ответа пишется отдельной записью.
- Rust: мёртвый kind, см. выше.

### Хук: URLLoader::NotifyCompleted (url_loader.cc, hunk `@@ -1941,6 +2018,21 @@`)
- что делает: `EmitStr(kNetRespBody, …, "complete url=<spec> err=<code> recv=<bytes>")`, буфер 512 байт.
- kind/tag: **18 `net-resp-body`**, prose.
- Rust: мёртвый kind.

### Хук: WebSocket::WebSocketEventHandler::OnDataFrame (websocket.cc, hunk `@@ -411,6 +414,16 @@`)
- почему здесь: входящий кадр WS уже распарсен, `payload` — чистые данные без заголовка кадра.
- что делает: `EmitSpan(kWebSocket, …, fin ? "ws-frame-fin" : "ws-frame", payload.data(), min(payload.size(), 0x40000))`.
- kind/tag: **19 `websocket`**, tag `ws-frame` или `ws-frame-fin` — **ВХОДЯЩЕЕ направление**.
- Rust: НЕ sink (`is_ws_sink` требует ровно `"ws-frame-out"`), только carrier-узел в графе.

### Взаимодействия 0011
`afeye_sink.h` включается в `url_loader.cc` и `websocket.cc`; 0017 и 0032 достраивают те же два kind'а. Rust-сторона: `collect.rs` (декод заголовка, имя kind'а), `sinkfilter.rs` (seeds/граф/окна).

---

## patches/0006-blink-flow.patch — события, слушатели, таймеры, fetch (kind 24, 12, 28)

Трогает 4 файла. Капсов/счётчиков НЕТ ни в одном хуке — патч безусловно самый «дорогой» по объёму записей.

### EventDispatcher::DispatchEvent (event_dispatcher.cc, hunk `@@ -72,6 +79,49 @@`)
- почему здесь: единая воронка диспетчеризации ВСЕХ DOM-событий, до вызова слушателей.
- что делает, 3 записи + SetTag:
  1. всегда: `EmitStr(kEventDispatch, …, "evt <type> trusted=<0|1> target=<nodeName, до 48 симв.>")`, буфер 256.
  2. если `DynamicTo<MouseEvent>` успешен: `"evt-mouse <type> x=%.1f y=%.1f sx=%.0f sy=%.0f btn=%d"` (clientX/clientY/screenX/screenY/button), буфер 192.
  3. иначе если `DynamicTo<KeyboardEvent>`: `"evt-key <type> key=<до 24> code=<до 24>"`, буфер 128.
  4. `SetTag("evt:<type, до 48>")` — устанавливает контекст для последующих DOM-метрик.
- kind/tag: **24 `event-dispatch`**, prose-префиксы `evt `/`evt-mouse `/`evt-key `.
- Rust: `event-dispatch` входит в `TRIGGER_KINDS` (`sinkfilter.rs:91-95`) — используется как «триггер» для атрибуции цепочки. Фильтр `is_trigger_event` (`sinkfilter.rs:781-789`) отбрасывает типы из `AMBIENT_EVENT_TYPES`; **распознаются префиксы `evt `, `evt-mouse `, `evt-key `, `evt-pointer `** — но патч 0006 `evt-pointer ` НЕ эмитит (это делает только 0015 как `input/raw type=Pointer*`, другой kind). `is_trigger_event` возвращает `true` для любого текста без этих префиксов, поэтому `lis …`-записи из event_target.cc проходят как триггеры.

### EventTarget::FireEventListeners (event_target.cc, hunk `@@ -975,6 +980,21 @@`)
- почему здесь: сразу после `Find(event.type())`, то есть известно точное число слушателей.
- что делает: `EmitStr(kEventDispatch, …, "lis evt=<type> n=<size> legacy=<0|1> trusted=<0|1>")`. `n` — `listeners_vector->size()` или 0 если вектора нет; `legacy` — наличие `legacy_listeners_vector`.
- kind/tag: **24 `event-dispatch`**, prose `lis `.
- назначение: детектор «сколько обработчиков навешано на событие» — признак автоматизации/фреймворка.
- Rust: в `payload_kinds` не входит, в диспетчере не обрабатывается отдельно; участвует только как trigger (см. выше).

### DOMTimer::DOMTimer (конструктор, dom_timer.cc, hunk `@@ -300,6 +304,18 @@`)
- что делает: `EmitStr(kTimer, …, "timer-install id=<timeout_id_> timeout_ms=<InMilliseconds> single=<0|1>")`, буфер 128.
- kind/tag: **12 `timer`**, prose `timer-install`.
- Rust: `timer` ∈ `TRIGGER_KINDS`. `timer` также ∈ `BATCHED_KINDS` (`collect.rs:59-68`) → payload уезжает в общий part-файл `<layer>-timer-pNNNN.bin` с полями `p`/`o` в индексе вместо отдельного `.bin`.

### DOMTimer::Fired (dom_timer.cc, hunk `@@ -400,6 +416,21 @@`)
- что делает: `EmitStr(kTimer, …, "timer-fire id=<id> nesting=<nesting_level_>")`, затем `SetTag("timer:<id>")`.
- kind/tag: **12 `timer`**, prose `timer-fire`.

### ResourceFetcher::RequestResource (resource_fetcher.cc, hunk `@@ -1387,6 +1392,21 @@`)
- почему здесь: воронка всех подгрузок ресурсов blink'ом (скрипты, стили, изображения, fetch).
- что делает: `EmitStr(kFetch, …, "fetch url=<до 440> type=<int factory.GetType()> ctx=<Tag(), до 60>")`, буфер 640.
- kind/tag: **28 `fetch`**, prose `fetch url=`.
- Rust: `fetch` входит в `interest` (`sinkfilter.rs:1692-1695`) → `send_init.insert(idx)` (строка 1710-1712) → флаг `send_initiator` у цепочки. Поле `ctx=` при этом НЕ парсится — связка «какое событие инициировало fetch» на Rust-стороне теряется, хотя в C++ она передаётся.

---

## patches/0007-blink-probes.patch — DOM-метрики, structured clone, crypto-входы, WebGL/аудио/медиа-устройства (kinds 15, 25, 11, 16, 27, 26)

Самый большой патч blink-стороны: 774 строки, 9 файлов. Капсов НЕТ ни в одном хуке.

### SerializedScriptValue::SerializedScriptValue(DataBufferPtr) (serialized_script_value.cc, hunk `@@ -239,7 +242,19 @@`)
- почему здесь: конструктор из готового буфера — момент, когда сериализованные данные postMessage/IndexedDB уже существуют в памяти.
- что делает: `data_buffer_.as_span()`; если непуст — `EmitSpan(kStructuredClone, …, "ssv", span.data(), span.size())`.
- kind/tag: **15 `structured-clone`**, tag `ssv`.
- лимиты: НЕТ; действует `kSpanCap=64KiB`.
- Rust: `structured-clone` ∈ `payload_kinds` (`sinkfilter.rs:1415`) → carrier-узел графа. Не sink.

### Element::clientWidth / clientHeight / scrollWidth / scrollHeight / getClientRects (element.cc, hunks `@@ -2527`, `@@ -2570`, `@@ -2828`, `@@ -2852`, `@@ -3359`)
- что делает: каждый — `EmitStr(kDomMetric, …, "dom/<имя> tag=<tagName, до 48> ctx=<Tag(), до 48>")`, буфер 128. Теги: `dom/client-w`, `dom/client-h`, `dom/scroll-w`, `dom/scroll-h`, `dom/client-rects`.
- kind/tag: **25 `dom-metric`**.
- значение: эти геттеры вызывают forced layout — классический сигнал fingerprinting'а.
- Rust: `"dom-metric"` НЕ входит ни в `payload_kinds`, ни в диспетчер kind'ов, ни в `interest`. **Полностью мёртвый kind**: индексируется, в анализе не участвует. `dom-metric` ∉ `BATCHED_KINDS` → каждая запись отдельным `.bin`.

### Element::GetBoundingClientRectForBinding (element.cc, hunk `@@ -3465,7 +3524,29 @@`)
- что делает: ПЕРЕД вычислением — `"dom/bounding-rect tag=… ctx=…"`. Затем результат сохраняется в `afeye_rect` (исходный `return GetBoundingClientRect();` переписан) и ПОСЛЕ — `"dom/bounding-rect-r tag=… x=%.2f y=%.2f w=%.2f h=%.2f"`, буфер 192.
- kind/tag: **25 `dom-metric`**, два prose-тега.
- Rust: мёртвый kind.

### HTMLElement::offsetLeftForBinding / offsetTopForBinding / offsetWidthForBinding / offsetHeightForBinding (html_element.cc, hunks `@@ -4273,11 +4277,35 @@` и `@@ -4287`/`@@ -4298`)
- что делает: `offsetLeft/Top` — однострочные `return OffsetTopOrLeft(…)` переписаны на `int afeye_v = …;` + лог + `return afeye_v;`. Теги `dom/offset-left`, `dom/offset-top` (буфер 160, печатают `v=%d`), `dom/offset-w`, `dom/offset-h` (пишут уже вычисленный `result`).
- kind/tag: **25 `dom-metric`**.
- **дефект форматирования**: строки `int afeye_v = OffsetTopOrLeft(/*top=*/false);` вставлены БЕЗ отступа (в колонку 0) внутри тела функции — видно в диффе. На компиляцию не влияет, на clang-format — да.
- Rust: мёртвый kind.

### BaseRenderingContext2D::getImageDataInternal (base_rendering_context_2d.cc, hunk `@@ -360,6 +364,16 @@`)
- что делает: `EmitStr(kDomMetric, …, "canvas/get-image-data rect=<sx>,<sy> <sw>x<sh> ctx=<Tag()>")`, буфер 160. Хук стоит ДО проверки `CheckMul(sw,sh)`.
- kind/tag: **25 `dom-metric`**. Это ВХОД (запрос), не результат.
- Rust: мёртвый kind. Результат ловится отдельно в 0014 как `canvas/get-image-data-r` под kind 16.

### BaseRenderingContext2D::measureText (base_rendering_context_2d.cc, hunk `@@ -1167,11 +1181,53 @@`)
- что делает: входная запись `"canvas/measure text=<до 64> font=<UnparsedFont, до 64> ctx=<Tag()>"` (буфер 224). Затем ВЕСЬ оригинальный код функции переписан с переименованием локальных переменных (`canvas`→`afeye_canvas`, `font`→`afeye_font`, `state`→`afeye_state`, `computed_style`→`afeye_style`, `host`→`afeye_host`, `direction`→`afeye_dir`, результат в `afeye_tm`) — чтобы можно было залогировать результат перед return. Выходная запись: `"canvas/measure-r text=<до 64> w=%.6f"`.
- kind/tag: **25 `dom-metric`**, prose `canvas/measure` и `canvas/measure-r`.
- Rust: `canvas/measure-r` ЕСТЬ в `VALUE_TAGS` (`sinkfilter.rs:1437`) и обрабатывается `value_of_prose` (`sinkfilter.rs:340-348`, ищет `" w="`) — НО только для kind `fingerprint`. Здесь kind = `dom-metric`, поэтому **запись не попадает в граф**: `value_of_prose` вызывается лишь при `r.kind == "fingerprint" && tag.is_empty()` (`sinkfilter.rs:1473`). Это несоответствие: тег объявлен как «ценный», но эмитится под kind'ом, который граф не читает.

### Crypto::getRandomValues (crypto.cc, hunk `@@ -74,6 +77,17 @@`)
- почему здесь: сразу ПОСЛЕ `crypto::RandBytes(array->ByteSpan())` — то есть перехватываются уже сгенерированные случайные байты.
- что делает: `EmitSpan(kCryptoOp, …, "getRandomValues", span.data(), span.size())`.
- kind/tag: **11 `crypto-op`**, tag `getRandomValues`.
- Rust: `crypto-op` ∈ `payload_kinds`. `is_crypto_sink` = `tag.contains(o)` для `o ∈ SINK_CRYPTO_OPS = ["encrypt","sign","deriveBits","digest","crypto-out"]` (`sinkfilter.rs:180-186`). `getRandomValues` НЕ содержит ни одного → carrier-узел, не sink. Корректно: это источник энтропии, а не выход.

### static void AfeyeDumpSubtleOp(const char* op, const V8BufferSource* raw_data) (subtle_crypto.cc, новый, hunk `@@ -234,6 +238,35 @@`)
- назначение: единая воронка для всех входов SubtleCrypto.
- что внутри: `!Enabled() || !raw_data` → return. Ветвление: `raw_data->IsArrayBuffer()` → `GetAsArrayBuffer()`, берёт `Data()`/`ByteLength()`; иначе `IsArrayBufferView()` → `GetAsArrayBufferView()` (обёртка `NotShared<DOMArrayBufferView>`), берёт `ByteSpan()`. При `p && n` — `EmitSpan(kCryptoOp, NowNs(), op, p, n)`.
- **что НЕ перехватывается**: сам `op` — это только имя метода; `CryptoKey* key` и `V8AlgorithmIdentifier* raw_algorithm` НЕ логируются. То есть алгоритм (AES-GCM vs RSA-OAEP), длина ключа, IV — всё мимо.
- связи: вызывается из 4 мест.

### Хуки SubtleCrypto::encrypt / decrypt / sign / digest (subtle_crypto.cc, hunks `@@ -242,6 +275,10 @@`, `@@ -292,6 +329,10 @@`, `@@ -342,6 +383,10 @@`, `@@ -447,6 +492,10 @@`)
- что делает: каждый — одна строка `AfeyeDumpSubtleOp("<имя>", raw_data);` в самом начале тела, ДО валидации аргументов.
- kind/tag: **11 `crypto-op`**, tag = `encrypt` / `decrypt` / `sign` / `digest`.
- Rust: `encrypt`, `sign`, `digest` ∈ `SINK_CRYPTO_OPS` → **sink-seeds**. `decrypt` НЕ входит в список — корректно, это вход, а не выход.

### SubtleCrypto::deriveBits (subtle_crypto.cc, hunk `@@ -823,6 +872,7 @@`)
- что делает: **добавляет ровно одну ПУСТУЮ строку** после открывающей скобки сигнатуры. Никакого `AfeyeDumpSubtleOp` здесь нет.
- **НАЙДЕННАЯ ДЫРКА.** `SINK_CRYPTO_OPS` в `sinkfilter.rs:183` содержит `"deriveBits"` — то есть Rust-сторона ГОТОВА принимать такие записи как sink-seed, но C++-сторона их НЕ ЭМИТИРУЕТ. Хук забыт/потерян: в патче остался только след в виде пустой строки. Также не перехватываются `deriveKey`, `importKey`, `generateKey`, `wrapKey`, `unwrapKey` (grep по всем патчам: совпадений нет). Для схемы HKDF/PBKDF2 → deriveBits весь вывод ключей невидим.

### MediaDeviceInfo::MediaDeviceInfo (конструктор, media_device_info.cc, hunk `@@ -40,7 +44,17 @@`)
- что делает: склеивает `std::string` `"device id=<device_id> group=<group_id> label=<label> type=<unsigned device_type>"` → `EmitStr(kFingerprint, …)`.
- kind/tag: **16 `fingerprint`**, prose `device id=`.
- Rust: `fingerprint` ∈ `payload_kinds`, но строка 1482 требует `tag.starts_with(VALUE_TAGS)`; `value_of_prose` (строки 292-350) `device id=` не знает → tag остаётся пустым → `continue`. **Не участвует в графе.** В `interest`-ветке (1692) kind `fingerprint` обрабатывается только по префиксам `json-stringify `, `taint-sink `, `cookie-get/set`, `storage-get/set`, `gopd ` — `device id=` не совпадает ни с одним. Запись остаётся только в `raw/` и в `stats.per`.

### RTCPeerConnection::createOffer / setLocalDescription / addIceCandidate (rtc_peer_connection.cc, hunks `@@ -828,6 +831,12 @@`, `@@ -1101,6 +1110,12 @@`, `@@ -1679,6 +1694,13 @@`)
- что делает: `"webrtc create-offer"`; `"webrtc sdp-local <весь SDP>"` (конкатенация `std::string`, БЕЗ ограничения длины — длинный SDP упрётся в `kMaxRecord` и будет обрезан с `flags=1`); `"webrtc ice <candidate>"`.
- kind/tag: **27 `webrtc`**, prose.
- Rust: `"webrtc"` НЕ входит в `payload_kinds`, нет в диспетчере kind'ов, нет в `interest`. **Мёртвый kind.** При этом `FP_API_NEEDLES` содержит `"createOffer"` и `"createDataChannel"` (`sinkfilter.rs:129-130`) — но они матчат kind `dom-api` (0008/0024), а не `webrtc`.

### OfflineAudioDestinationHandler::FinishOfflineRendering (offline_audio_destination_handler.cc, hunk `@@ -226,6 +229,19 @@`)
- почему здесь: рендер завершён, `shared_render_target_` содержит готовые сэмплы. `DCHECK(!IsMainThread())` — хук работает на аудиопотоке.
- что делает: берёт канал 0, `ByteSpan()`, **явный кламп 16384 байта**, `EmitSpan(kAudio, …, "audio/offline-ch0", data, n)`.
- kind/tag: **26 `audio`**, tag `audio/offline-ch0`.
- Rust: `"audio"` НЕ входит в `payload_kinds` → **мёртвый kind**. `VALUE_TAGS` содержит `audio/float-frequency`, `audio/byte-frequency`, `audio/float-timedomain`, `audio/byte-timedomain` — это теги из 0014, которые эмитятся под kind **16 `fingerprint`**, а не 26. То есть kind 26 не читается никем.

### WebGLRenderingContextBase::getExtension (webgl_rendering_context_base.cc, hunk `@@ -3874,6 +3879,15 @@`)
- что делает: `"webgl/get-extension name=<до 64>"` → `EmitStr(kFingerprint, …)`.
- kind/tag: **16 `fingerprint`**, prose.
- Rust: `value_of_prose` не знает префикс → не попадает в граф. Но `FP_API_NEEDLES` содержит `"getExtension"` → ловится через kind `dom-api`.

### WebGLRenderingContextBase::getParameter (webgl_rendering_context_base.cc, hunk `@@ -3989,6 +4003,76 @@`)
- почему здесь: единственный вход для всех WebGL-параметров; здесь же живёт `WEBGL_debug_renderer_info`.
- что делает, switch по `pname`, 3 ветки:
  1. `0x9245` (`UNMASKED_VENDOR_WEBGL`), `0x9246` (`UNMASKED_RENDERER_WEBGL`), `GL_VERSION`, `GL_RENDERER`, `GL_VENDOR`, `GL_SHADING_LANGUAGE_VERSION`: выбирает `afeye_what` = `webgl/unmasked-vendor` / `webgl/unmasked-renderer` / `webgl/param`; для unmasked-констант ПОДМЕНЯЕТ `afeye_p` на `GL_VENDOR`/`GL_RENDERER` (иначе ANGLE вернул бы пусто); при `ContextGL() && !isContextLost()` читает значение через `ContextGL()->GetString(afeye_p)`; пишет `"<what> pname=<pname> val=<до 120>"`, буфер 192.
  2. 16 целочисленных констант (`GL_MAX_TEXTURE_SIZE`, `GL_MAX_RENDERBUFFER_SIZE`, `GL_MAX_VIEWPORT_DIMS`, `GL_MAX_VERTEX_ATTRIBS`, `GL_MAX_VARYING_VECTORS`, `GL_MAX_VERTEX_UNIFORM_VECTORS`, `GL_MAX_FRAGMENT_UNIFORM_VECTORS`, `GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS`, `GL_MAX_TEXTURE_IMAGE_UNITS`, `GL_MAX_VERTEX_TEXTURE_IMAGE_UNITS`, `GL_ALIASED_LINE_WIDTH_RANGE`, `GL_ALIASED_POINT_SIZE_RANGE`, `GL_SAMPLE_BUFFERS`, `GL_SAMPLES`, `GL_DEPTH_BITS`, `GL_STENCIL_BITS`): `ContextGL()->GetIntegerv(pname, GLint[2])` → `"webgl/param-int pname=<p> v0=<a> v1=<b>"`, буфер 128. Чтение происходит ДО оригинального кода функции — это **дополнительный GL-вызов на каждый getParameter**.
  3. default: `"webgl/get-parameter pname=<p>"`, буфер 96.
- kind/tag: **16 `fingerprint`**, prose.
- Rust: `webgl/unmasked-vendor`, `webgl/unmasked-renderer`, `webgl/param` ЕСТЬ в `VALUE_TAGS` (строки 1434-1436) и обрабатываются `value_of_prose` (строки 329-339, ищут `" val="`) → **попадают в граф как carrier-узлы**. Ветки `webgl/param-int` и `webgl/get-parameter` НЕ обрабатываются: `param-int` не входит в VALUE_TAGS (а `starts_with("webgl/param")` сработало бы, но `value_of_prose` ищет `" val="`, которого в `param-int` нет — там `" v0="`). Итог: 16 числовых параметров GPU в граф не попадают.

### WebGLRenderingContextBase::getShaderPrecisionFormat (hunk `@@ -4487,6 +4571,17 @@`)
- что делает: `"webgl/shader-precision sh=<shader_type> pr=<precision_type>"` → kind 16.
- Rust: не в VALUE_TAGS, не в value_of_prose → вне графа. `FP_API_NEEDLES` содержит `"getShaderPrecisionFormat"` → ловится через `dom-api`.

### WebGLRenderingContextBase::getSupportedExtensions (hunk `@@ -4533,6 +4628,22 @@`)
- что делает: ПОСЛЕ формирования `result` склеивает список расширений через запятую с обрывом при `afeye_list.size() > 380`, пишет `"webgl/supported-extensions n=<count> list=<до 384>"`, буфер 448.
- kind/tag: **16 `fingerprint`**.
- Rust: вне графа (нет в VALUE_TAGS).

---

## patches/0008-blink-dom-api.patch + 0024-blink-dom-api-values.patch — IDL-thunk на все WebIDL-геттеры/сеттеры/методы (kind 29)

Оба патча правят ОДИН файл: `third_party/blink/renderer/platform/bindings/idl_member_installer.cc`. 0024 достраивает 0008.

### Почему именно idl_member_installer.cc
Это единственное место, через которое blink устанавливает ВСЕ WebIDL-атрибуты и операции на V8-шаблоны: `InstallAttribute` и `InstallOperation` (по две перегрузки каждая — для FunctionTemplate и для Function) зовут `CreateFunctionTemplate<kind>` / `CreateFunction<kind>`, которые получают `v8::FunctionCallback callback = GetConfigCallback<kind>(config)`. Подменив `callback` на свой thunk и передав идентичность через data-слот, патч ловит каждый вызов любого IDL-члена без правки сгенерированных `v8_*.cc` binding'ов. Эталонное `src/bindings/core/v8/` при этом НЕ трогается.

### struct AfeyeApiCell (0008, hunk `@@ -15,6 +22,63 @@`)
- поля: `v8::FunctionCallback orig` — оригинальный callback; `const char* prop` — имя свойства (для dedupe); `char what[104]` — готовая строка `"dom <Interface>.<accessor> <property>"`.
- связи: хранится в глобальном статическом массиве, адрес ячейки уезжает в JS как `v8::External`.

### Глобальные переменные (0008, тот же hunk)
- `constexpr size_t kAfeyeApiCells = 1u << 16` — 65536 ячеек.
- `AfeyeApiCell g_afeye_api_cells[kAfeyeApiCells] = {}` — статический массив; `sizeof(AfeyeApiCell)` ≈ 8 + 8 + 104 = 120 байт → **≈ 7.5 MiB BSS на процесс**, выделяется безусловно при `BLINK_AFEYE`, даже если sink выключен.
- `std::mutex g_afeye_api_mu` — защита линейного probing'а.
- `std::atomic<uint64_t> g_afeye_api_calls{0}` — глобальный счётчик вызовов.
- `bool g_afeye_api_values_off` (0024, hunk `@@ -32,6 +34,45 @@`) — инициализируется лямбдой из `getenv("AFEYE_TRACE_DOM_VALUES")`; **true если переменная задана, непуста и первый символ `'0'`**. То есть `AFEYE_TRACE_DOM_VALUES=0` ВЫКЛЮЧАЕТ захват значений; по умолчанию значения захватываются.

### fn AfeyeDomApiThunk(const v8::FunctionCallbackInfo<v8::Value>& info)  (0008; переписана в 0024)
- назначение: обёртка, которая замещает оригинальный `FunctionCallback` в V8.
- что внутри (версия 0024, финальная):
  1. `info.Data()`; если `data->IsExternal()` — `cell = static_cast<AfeyeApiCell*>(data.As<v8::External>()->Value(v8::kExternalPointerTypeTagDefault))`.
  2. `afeye_record = g_afeye_api_calls.fetch_add(1, relaxed) < 8000000` — **кап 8 000 000 вызовов на процесс**; после превышения вызовы идут без записи (счётчик продолжает расти).
  3. **СНАЧАЛА** вызывается оригинал: `if (cell->orig) cell->orig(info);` — в 0008 порядок был обратный (сначала Emit, потом orig); 0024 переставил, чтобы иметь доступ к возвращённому значению.
  4. если `afeye_record`: при `g_afeye_api_values_off` — `EmitStr(kDomApi, NowNs(), cell->what)`; иначе `AfeyeCaptureValue(isolate, info.GetReturnValue().Get(), afeye_val[160], 160)` и `snprintf(afeye_buf[320], "%s val=%.150s", cell->what, afeye_val)` → `EmitStr(kDomApi, …)`.
- kind/tag: **29 `dom-api`**, prose вида `dom Navigator.get userAgent val=Mozilla/5.0…`.
- связи: подставляется как `callback` в `CreateFunctionTemplate`.

### fn AfeyeCaptureValue(v8::Isolate*, v8::Local<v8::Value> rv, char* buf, size_t buf_sz)  (0024, hunk `@@ -32,6 +34,45 @@`)
- назначение: привести произвольное JS-возвращаемое значение к короткой printable-строке.
- ветки: `IsEmpty()||IsUndefined()` → `"undefined"`; `IsNull()` → `"null"`; `IsBoolean()` → `"1"`/`"0"`; `IsNumber()` → `"%.17g"` от `NumberValue(GetCurrentContext()).FromMaybe(0)`; `IsString()` → `Utf8Length`, кламп до `buf_sz-1`, `WriteUtf8`, затем **побайтовая санитизация**: любой байт `< 0x20 || >= 0x7f` заменяется на `'?'` (то есть UTF-8 кириллица/эмодзи превращаются в `?`); `IsArray()` → `"[array len=<N>]"`; иначе → `"[object]"`.
- **что теряется**: объекты и DOM-узлы дают просто `[object]` — ни типа, ни `Symbol.toStringTag`, ни `constructor.name`. Массивы дают только длину, не содержимое. Аргументы вызова НЕ захватываются вообще (только `GetReturnValue`).
- связи: единственный вызов — из `AfeyeDomApiThunk`.
- **мёртвый include**: 0024 добавляет `#include "v8/include/v8-container.h"`, но ни один символ из него в патче не используется (`v8::Array::Length()` comes from `v8-array`/`v8-value`; grep по патчу — других употреблений нет).

### fn AfeyeWrapDomApi(isolate, orig, interface_name, accessor, property_name) → v8::Local<v8::Value>  (0008)
- назначение: зарегистрировать оригинальный callback в таблице и вернуть `v8::External` на ячейку.
- что внутри: `!orig || !Enabled()` → пустой `Local` (тогда подмены callback'а не происходит и поведение побитово совпадает со стоковым). `slot = (reinterpret_cast<uintptr_t>(orig) >> 4) & (kAfeyeApiCells - 1)` — хеш от адреса функции. Под `std::lock_guard` — **линейный probing по всем 65536 ячейкам**: первая свободная (`orig == nullptr`) заполняется (`orig`, `prop = property_name`, `what` = `snprintf("dom %s.%s %s", interface_name, accessor, property_name)`) и возвращается External; если найдена ячейка с тем же `orig` И тем же `prop` — возвращается она (dedupe). Если все 65536 заняты и совпадения нет — пустой `Local`, **хук для этого члена молча теряется**.
- **дефект**: ячейки никогда не освобождаются, ключ dedupe — пара `(orig, prop)`. Разные миры/контексты с одним `property_name` и одним callback'ом разделят одну ячейку — это корректно, но `what` фиксирует только ПЕРВЫЙ увиденный `interface_name`.
- связи: вызывается из `CreateFunctionTemplate`.

### Изменение CreateFunctionTemplate / CreateFunction (0008, hunks `@@ -134,12 +198,33 @@`, `@@ -186,6 +271,7 @@`)
- в обе функции добавлен параметр `const char* afeye_interface_name = nullptr` **перед** `v8_cfunction_table_data` — то есть вставлен в середину списка параметров со значением по умолчанию.
- в `CreateFunctionTemplate`: `afeye_access` = `"get"` для `kAttributeGet`, `"set"` для `kAttributeSet`, иначе `"call"` (через `if constexpr` по шаблонному `kind`). Затем `afeye_data = AfeyeWrapDomApi(...)`; если не пусто — `callback = &AfeyeDomApiThunk`.
- оба места, где раньше передавался пустой `v8::Local<v8::Value>()` как data-слот (`NewWithCFunctionOverloads` и ветка с `GetCachedAccessor`), теперь передают `afeye_data`.
- **побочный эффект**: когда afeye-ячейка выдана, `callback` подменяется на `&AfeyeDomApiThunk`, но `v8_cfunction_table_data`/`v8_cfunction_table_size` продолжают передаваться в `NewWithCFunctionOverloads`. CFunction-таблица описывает fast-call ABI ОРИГИНАЛЬНОЙ функции; при подменённом callback V8 может выбрать fast-path и обойти thunk. Патч это никак не обрабатывает. `[INFERENCE]` — проверить без сборки нельзя.

### Изменение InstallAttribute / InstallOperation (0008, hunks `@@ -233,11 +320,12 @@`, `@@ -293,11 +381,12 @@`, `@@ -347,8 +436,8 @@`, `@@ -398,8 +487,8 @@`)
Во все 6 вызовов `CreateFunctionTemplate`/`CreateFunction` добавлен аргумент `interface_name_ptr` — существующая локальная переменная стокового кода (патч её не объявляет). Именно она даёт `<Interface>` в строке `dom Navigator.get userAgent`.

### Rust-сторона kind 29
- `dom-api` ∈ `BATCHED_KINDS` (`collect.rs:60`) → payload'ы складируются в part-файлы `<layer>-dom-api-pNNNN.bin` с роллом по `PART_ROLL_BYTES = 8<<20`.
- `sinkfilter.rs:1077-1081`: для каждой записи `fp_needle_of(txt)` ищет первое вхождение любого из `FP_API_NEEDLES` (`sinkfilter.rs:97-134`, 36 игл: `Navigator.get userAgent`/`appVersion`/`platform`/`vendor`/`oscpu`/`languages`/`hardwareConcurrency`/`deviceMemory`/`plugins`/`mimeTypes`/`connection`, `Screen.get width`/`height`/`colorDepth`/`pixelDepth`/`availLeft`/`availTop`/`availWidth`/`availHeight`, `Document.get cookie`, `getParameter`, `getExtension`, `getShaderPrecisionFormat`, `toDataURL`, `toBlob`, `getImageData`, `measureText`, `getBoundingClientRect`, `getClientRects`, `getChannelData`, `createOffer`, `createDataChannel`, `enumerateDevices`, `getGamepads`, `getBattery`) → `fp_reads`.
- `sinkfilter.rs:1692-1695` + `1728-1735`: те же иглы дают флаг `fp_entry` у цепочки (через `entry_index.script_at` — привязку к скрипту).
- **дубли**: `"Navigator.get userAgent"` и `"Navigator.get userAgent"` — одна и та же игла перечислена дважды (строки 98 и 109). Безвредно (find возвращает первое), но мусор.
- **следствие формата**: иглы вида `Navigator.get userAgent` матчатся только если `accessor == "get"` и `interface_name == "Navigator"`. Для setter'ов (`set`) и для методов (`call`) иглы не сработают — кроме тех, что заданы как голое имя метода (`getParameter`, `toDataURL`, …), которые матчат любую форму.

---

## patches/0009-blink-input.patch и 0015-blink-input-master.patch — ввод (kind 23)

### 0009: KeyboardEventManager::KeyEvent (keyboard_event_manager.cc, hunk `@@ -226,6 +230,20 @@`)
- почему здесь: воронка всех клавиатурных событий blink'а, до `HandleAccessKey`/распределения.
- что делает: `EmitStr(kInput, …, "input/key type=<int GetType()> vk=<windows_key_code> code=<dom_code> key=<unsigned dom_key> mods=<GetModifiers()>")`, буфер 160.
- kind/tag: **23 `input`**, prose `input/key`.
- лимиты: НЕТ.

### 0009: MouseEventManager::DispatchMouseEvent (mouse_event_manager.cc, hunk `@@ -219,6 +223,24 @@`)
- что делает: `EmitStr(kInput, …, "input/mouse <type> x=%.1f y=%.1f sx=%.1f sy=%.1f btn=<button> clicks=<ClickCount> mods=<GetModifiers>")`, буфер 192. Координаты — `PositionInWidget()` и `PositionInScreen()`.
- kind/tag: **23 `input`**, prose `input/mouse`.
- Rust: `is_trigger_input` (`sinkfilter.rs:791-795`) — для `input/mouse ` отбрасывает `mousemove`, остальное считает триггером.

### 0015: static void AfeyeLogRawInput(const WebInputEvent& event) (widget_event_handler.cc, новый, hunk `@@ -17,10 +30,93 @@`)
- назначение: перехват ввода на САМОМ ВЕРХНЕМ уровне blink'а — до hit-test и до каких-либо менеджеров.
- что внутри:
  - `static std::atomic<uint64_t> g_afeye_rawin{0}` и `static bool g_afeye_rawin_off` из `getenv("AFEYE_TRACE_INPUT")` (off если первый символ `'0'`).
  - **кап 4 000 000** записей (`>= 4000000` → return).
  - общая часть: `"input/raw type=<WebInputEvent::GetName(GetType()), до 24> mods=<int> dbg=<0|1>"`, где `dbg` — бит `WebInputEvent::Modifiers::kFromDebugger`. Буфер 224, дописывание через `snprintf(afeye_buf + afeye_n, sizeof - afeye_n, …)`.
  - switch по `event.GetType()`, 4 группы:
    - `kMouseMove`/`kMouseDown`/`kMouseUp` → cast к `WebMouseEvent`, дописывает `" x=%.1f y=%.1f sx=%.1f sy=%.1f btn=%d clicks=%d"`.
    - `kMouseWheel` → `WebMouseWheelEvent`, `" dx=%.1f dy=%.1f phase=%d"`.
    - `kRawKeyDown`/`kKeyDown`/`kKeyUp`/`kChar` → `WebKeyboardEvent`, `" vk=%d code=%d key=%u"`.
    - `kPointerDown`/`kPointerUp`/`kPointerMove` → `WebPointerEvent`, `" id=%d ptype=%d x=%.1f y=%.1f force=%.2f"`.
    - default → ничего не дописывается.
  - `EmitStr(kInput, NowNs(), afeye_buf)`.
- kind/tag: **23 `input`**, prose `input/raw type=<Имя>`.
- хук: `WidgetEventHandler::HandleInputEvent(coalesced_event, root)` — `AfeyeLogRawInput(coalesced_event.Event())` в самом начале, до `if (root)`.
- Rust: `is_trigger_input` (`sinkfilter.rs:796-806`) для `input/raw type=` отбрасывает `MouseMove`, `PointerMove`, `PointerRawUpdate`, `PointerHoverMove`, `MouseLeave`, `MouseEnter`, `TouchMove`, `GestureScrollUpdate`. **Расхождение**: патч эмитит `GetName()`, который даёт `MouseWheel`, а фильтр такого имени не отбрасывает — колесо мыши считается триггером. И наоборот: фильтр знает `PointerRawUpdate`/`PointerHoverMove`/`TouchMove`/`GestureScrollUpdate`, но switch патча для них попадает в `default` (без координат) — запись всё равно создаётся, просто менее информативная.
- **`input` ∈ `BATCHED_KINDS`** (`collect.rs:63`) → part-файлы.

---

## patches/0010-blink-context.patch — навигация и worker'ы (kinds 36, 35)

### DocumentLoadTiming::SetNavigationStart (document_load_timing.cc, hunk `@@ -128,6 +132,17 @@`)
- что делает: `EmitStr(kNavStart, …, "nav-start mono_ns=<navigation_start.since_origin().InNanoseconds()>")`, буфер 96.
- kind/tag: **36 `nav-start`**, prose.
- Rust: `sinkfilter.rs:1157-1166` — парсит `mono_ns=`, берёт МИНИМУМ по всем записям как `nav_start` (точка отсчёта таймлайна страницы). Если парсинг не удался — fallback на `r.ts`.

### WorkerOrWorkletGlobalScope::WorkerOrWorkletGlobalScope (конструктор, worker_or_worklet_global_scope.cc, hunk `@@ -248,6 +252,17 @@`)
- что делает: `EmitStr(kWorker, …, "worker-scope iso=<void* isolate> name=<до 48> secure=<is_creator_secure_context 0|1>")`, буфер 160.
- kind/tag: **35 `worker`**, prose `worker-scope`.
- Rust: `sinkfilter.rs:1134-1138` → `worker_of(txt)` (`sinkfilter.rs:361-364`, требует префикс `worker-scope iso=`, затем до первого пробела — iso, дальше — name) → `workers.push((ts, iso, name))`. Используется для привязки записей к воркеру.
- **важно для 0033**: `iso` здесь — это РЕАЛЬНЫЙ указатель `v8::Isolate*`, напечатанный как `%p`. В 0033 isolate-тег считается иначе (`AfeyeIsoTag` = `(uintptr(isolate) >> 3) & 0xffffffff`). Два разных представления одного isolate'а в двух kind'ах; на Rust-стороне они не сопоставляются.

---

## patches/0012-blink-clock-canvas.patch — performance.now (ЛОГИРОВАНИЕ, не виртуализация) и экспорт canvas (kinds 33, 16)

### Performance::now() const (performance.cc, hunk `@@ -1352,6 +1360,20 @@`)
- что делает: `static std::atomic<uint64_t> g_afeye_pnow{0}`; `static bool g_afeye_pnow_off` из `getenv("AFEYE_TRACE_CLOCK")` (off если `'0'`); если не выключено и `fetch_add(1) < 2000000` → `EmitStr(kClock, NowNs(), "clock performance-now")`.
- kind/tag: **33 `clock`**, константная строка, никаких значений.
- **это НЕ виртуализация**: возвращаемое значение НЕ меняется — `return MonotonicTimeToDOMHighResTimeStamp(base::TimeTicks::Now());` остаётся как есть. Виртуализация добавлена отдельно в 0034 (`AFEYE_VIRTUAL_CLOCK`, `afeye_vclock_ns()`), где hunk `@@ -1373,6 +1380,25 @@` вставляет возврат виртуального времени ПОСЛЕ этого лога. Комментарий 0034 прямо говорит: «the 0012 trace above still logs real now() calls for telemetry».
- лимиты: **кап 2 000 000** вызовов. `clock` ∈ `BATCHED_KINDS`.
- Rust: `sinkfilter.rs:1087` — `"clock" => clock_ts.push(r.ts)`. Затем `sinkfilter.rs:1393-1395`: `c.clock_reads = (partition_point(<=hi) - partition_point(<lo))` — число чтений часов в окне цепочки. Значение самой записи не используется (его и нет).

### HTMLCanvasElement::ToDataURLInternal (html_canvas_element.cc, hunk `@@ -1305,6 +1311,16 @@`)
- что делает: ПОСЛЕ `data_buffer->ToDataURL(encoding_mime_type, quality)` → `EmitStr(kFingerprint, …, "canvas/to-data-url mime=<до 64> len=<data_url.length()>")`, буфер 160.
- kind/tag: **16 `fingerprint`**, prose.
- **сами данные data URL НЕ перехватываются** — только mime и длина. Для сравнения отпечатков canvas этого недостаточно.
- Rust: вне графа (`canvas/to-data-url` нет в VALUE_TAGS, `value_of_prose` его не знает). `FP_API_NEEDLES` содержит `"toDataURL"` → ловится через kind 29.

### HTMLCanvasElement::toBlob (html_canvas_element.cc, hunk `@@ -1364,6 +1380,16 @@`)
- что делает: В НАЧАЛЕ функции, ДО проверки `OriginClean()` → `"canvas/to-blob mime=<до 64> w=<Size().width()> h=<Size().height()>"`, kind 16.
- Rust: как выше; `"toBlob"` ∈ `FP_API_NEEDLES`.

---

## patches/0013-blink-cookie-storage.patch — cookie и Web Storage (kind 16, span)

Трогает 2 файла: `core/dom/document.cc` и `modules/storage/storage_area.cc`. В ОБА файла вставлен **один и тот же блок boilerplate** (hunk `@@ -29,6 +29,29 @@` и `@@ -25,6 +25,29 @@`):
```
std::atomic<uint64_t> g_afeye_storage{0};
constexpr uint64_t kAfeyeStorageCap = 2ull << 20;   // 2 097 152
inline bool AfeyeStorageOn() {
  static const bool off = [](){ const char* v = std::getenv("AFEYE_TRACE_STORAGE");
                                return v && *v && v[0]=='0'; }();
  return !off && g_afeye_storage.fetch_add(1, relaxed) < kAfeyeStorageCap;
}
```
Обе переменные — в анонимном namespace своего TU, поэтому **счётчики НЕЗависимы**: суммарный бюджет 2 × 2 097 152 записей, а не общий.

### Document::cookie (document.cc, hunk `@@ -6844,7 +6867,22 @@`)
- что делает: оригинальный `return cookie_jar_->Cookies();` переписан на `String afeye_cookies = …`; затем, если `AfeyeStorageOn() && !afeye_cookies.empty()`: тег `snprintf("cookie-get len=%u", afeye_cookies.length())` (буфер 64), значение `afeye_cookies.Utf8()` **обрезается до 960 байт**, `EmitSpan(kFingerprint, …, afeye_tag, data, size)`.
- kind/tag: **16 `fingerprint`**, span-тег `cookie-get len=<N>`, body = байты cookie-строки.
- **потеря данных**: 960 байт — жёсткий обрез. Реальный cookie-jar антифрод-вендора легко превышает 2-4 KiB; хвост теряется БЕЗ установки `flags=1` (обрез происходит до `EmitSpan`, поэтому sink о нём не знает).

### Document::setCookie (document.cc, hunk `@@ -6869,6 +6907,20 @@`)
- то же, тег `cookie-set len=<N>`, обрез значения до 960 байт, ДО вызова `cookie_jar_->SetCookie(value)`.

### StorageArea::getItem (storage_area.cc, hunk `@@ -116,7 +139,22 @@`)
- что делает: `String afeye_item = cached_area_->GetItem(key);` (вместо прямого return); тег `"storage-get key=<до 128> vlen=<N>"` (буфер 192); значение обрезается до **800 байт**; `EmitSpan(kFingerprint, …)`.
- kind/tag: **16 `fingerprint`**, span.
- Условие — `!key.empty()`, а НЕ `!afeye_item.empty()`: запись создаётся и для отсутствующего ключа (с `vlen=0` и пустым body → `EmitSpan` при `n==0` вернёт управление, записи НЕ будет). То есть пустые значения молча теряются.

### StorageArea::setItem (storage_area.cc, hunk `@@ -127,6 +165,20 @@`)
- то же, тег `storage-set key=<до 128> vlen=<N>`, обрез до 800 байт, ДО `cached_area_->SetItem`.

### Rust-сторона kind 16 + cookie/storage
- `fingerprint` ∈ `payload_kinds`. Строка `sinkfilter.rs:1473`: если `tag.is_empty()` → `value_of_prose`. Здесь tag НЕ пуст (span), поэтому prose-путь не используется.
- Строка `sinkfilter.rs:1482`: `VALUE_TAGS.iter().any(|t| tag.starts_with(t))` — `"cookie-get len=42".starts_with("cookie-get")` → **true**. Аналогично для `cookie-set`, `storage-get`, `storage-set`. Все четыре тега ЕСТЬ в `VALUE_TAGS` (`sinkfilter.rs:1423-1426`). → записи становятся carrier-узлами графа, body (реальные байты cookie/значения) участвует в blake3-run'ах.
- `sinkfilter.rs:1719-1726`: для kind `fingerprint` с префиксами `cookie-get`/`cookie-set`/`storage-get`/`storage-set` ставится флаг `token_access` у цепочки.
- `value_of_prose` (строки 292-319) обрабатывает `cookie-get`/`cookie-set`/`storage-get`/`storage-set` как PROSE — это запасной путь на случай, если запись придёт через `EmitStr`. Патч 0013 так не делает, поэтому ветка мертва для blink-слоя (используется JS-инъекцией `src/inject.rs:60`, которая шлёт `cookie:get`/`cookie:set` — **другой формат с двоеточием**, который `value_of_prose` НЕ распознаёт).

---

## patches/0014-blink-readback-results.patch — РЕЗУЛЬТАТЫ readback'ов (kind 16, span)

Трогает 3 файла. Это парный патч к 0007: там входы, здесь выходы.

### BaseRenderingContext2D::getImageDataInternal (base_rendering_context_2d.cc, hunk `@@ -530,6 +530,16 @@`)
- что делает: перед `return image_data` — если `image_data` не null, берёт `RawByteSpan()` и `EmitSpan(kFingerprint, …, "canvas/get-image-data-r", px.data(), px.size())`.
- kind/tag: **16 `fingerprint`**, span-тег `canvas/get-image-data-r`.
- **лимит**: собственного клампа НЕТ, поэтому действует `kSpanCap = 64 KiB` blink-sink'а с установкой `flags=1`. Canvas 1000×1000 RGBA = 4 000 000 байт → в отчёт попадут первые 65 536. Для canvas-fingerprinting'а это означает, что хешируется только верхний левый фрагмент.
- Rust: тег ∈ `VALUE_TAGS` (строка 1427) → carrier-узел графа.

### AnalyserNode (analyser_node.cc)
Новый анонимный namespace (hunk `@@ -116,22 +122,80 @@`):
- `constexpr uint64_t kAfeyeAnalyserCap = 2000000;`
- `std::atomic<uint64_t> g_afeye_analyser{0};` — **ОДИН счётчик на все четыре метода**.
- `void AfeyeEmitAnalyserSpan(const char* tag, DOMUint8Array* array)` — `len = array->length()`, `EmitSpan(kFingerprint, …, tag, BaseAddressMaybeShared(), len)`.
- `void AfeyeEmitAnalyserSpanF32(const char* tag, DOMFloat32Array* array)` — то же, но размер `len * sizeof(float)`.

Четыре хука, каждый ПОСЛЕ вызова соответствующего `GetAnalyserHandler().Get…(...)`:
| метод | тег | kind |
|---|---|---|
| `getFloatFrequencyData` | `audio/float-frequency` | 16 |
| `getByteFrequencyData` | `audio/byte-frequency` | 16 |
| `getFloatTimeDomainData` | `audio/float-timedomain` | 16 |
| `getByteTimeDomainData` | `audio/byte-timedomain` | 16 |

Условие у всех: `Enabled() && g_afeye_analyser.fetch_add(1, relaxed) < 2000000`.
- Rust: все четыре тега ∈ `VALUE_TAGS` (`sinkfilter.rs:1429-1432`) → carrier-узлы. `"getChannelData"` ∈ `FP_API_NEEDLES` (для kind 29), но самого хука `getChannelData` в патчах НЕТ.

### WebGLRenderingContextBase::ReadPixelsHelper (webgl_rendering_context_base.cc, hunks `@@ -5400,6 +5400,17 @@` и `@@ -5466,6 +5477,15 @@`)
- вход: `"webgl/read-pixels rect=<x>,<y> <w>x<h> fmt=<format> type=<type>"` → `EmitStr(kFingerprint, …)`, буфер 160. Стоит ДО `if (isContextLost()) return;`.
- выход: ПОСЛЕ `ContextGL()->ReadPixels(x,y,width,height,format,type,data)` — `EmitSpan(kFingerprint, …, "webgl/read-pixels-r", data, buffer_size.ValueOrDie())`. Условие `data && buffer_size.IsValid()`.
- kind/tag: **16 `fingerprint`**; `webgl/read-pixels` (prose) и `webgl/read-pixels-r` (span).
- **лимит**: собственного клампа нет → `kSpanCap = 64 KiB`.
- Rust: `webgl/read-pixels-r` ∈ `VALUE_TAGS` (строка 1428) → carrier. `webgl/read-pixels` (вход) НЕ входит → вне графа.

---

## patches/0016-blink-taint-edges.patch — границы преобразования данных (kind 37)

Трогает 5 файлов: `core/frame/universal_global_scope.cc`, `core/html/forms/form_data.cc`, `core/url/url_search_params.cc`, `modules/encoding/text_decoder.cc`, `modules/encoding/text_encoder.cc`.

В КАЖДЫЙ из пяти файлов вставлен идентичный блок в анонимном namespace:
```
constexpr uint64_t kAfeyeTaintCap = 100000;
bool g_afeye_taint_off = [](){ const char* v = ::getenv("AFEYE_TRACE_TAINT");
                               return v && *v && v[0]=='0'; }();
inline bool AfeyeTaintOn() {
  return !g_afeye_taint_off &&
         afeye::g_afeye_taint.fetch_add(1, relaxed) < kAfeyeTaintCap;
}
```
Ключевое отличие от 0013: счётчик здесь НЕ локальный, а **общий глобальный `blink::afeye::g_afeye_taint`**, определённый в `platform/afeye/sink.cc:7` и объявленный `extern` в `sink.h:37`. То есть **100 000 записей — это ОБЩИЙ бюджет на все пять API**, а не на каждое. `g_afeye_taint_off` при этом продублирована 5 раз (5 отдельных static-переменных, каждая читает одну и ту же env).

### UniversalGlobalScope::btoa (hunk `@@ -34,6 +55,16 @@`)
- что делает: ДО `return Base64Encode(...)` — `base::as_byte_span(string_to_encode.Latin1())` → `EmitSpan(kTaintEdge, …, "btoa", data, size)`.
- перехватывается **ВХОД** (исходная строка), а не результат base64.
- kind/tag: **37 `taint-edge`**, tag `btoa`.

### UniversalGlobalScope::atob (hunk `@@ -58,6 +89,13 @@`)
- что делает: `EmitSpan(kTaintEdge, …, "atob", out.data(), out.size())` — здесь уже **ВЫХОД** (декодированные байты), перед `return String(out)`.
- асимметрия с btoa намеренная: цель — видеть ОБЕ стороны base64-границы, чтобы run-ключи совпали и с исходными, и с декодированными байтами.

### FormData::Entry::Entry(const String& name, const String& value) (hunk `@@ -364,12 +388,48 @@`)
- что делает: вручную, БЕЗ `EmitTwoStr`, собирает `name \0 value` в `Vector<char>`. `afeye_ln = name.size() + value.size() + 1`, **кламп 65536**. Два цикла побайтового копирования (не `memcpy`), с условиями `*q && afeye_i + 1 < afeye_ln` и `*q && afeye_i < afeye_ln` — то есть копирование останавливается на первом NUL внутри строки. Затем `EmitSpan(kTaintEdge, …, "form-data", buf, afeye_i)`.
- kind/tag: **37 `taint-edge`**, tag `form-data`, body = `name \0 value`.
- **дефект**: `Vector<char> afeye_buf(afeye_ln)` — если `afeye_ln` было урезано до 65536, а строки длиннее, второй цикл может записать `afeye_p[afeye_i]` при `afeye_i == afeye_ln`? Нет: условие `afeye_i < afeye_ln` защищает. Но NUL-разделитель пишется как `afeye_p[afeye_i++] = '\0'` с условием только в ПЕРВОМ цикле; если `afeye_i` уже равно `afeye_ln`, запись разделителя выйдет за границы. Проверка `afeye_i + 1 < afeye_ln` в первом цикле гарантирует `afeye_i <= afeye_ln - 2` на выходе из него, поэтому `afeye_p[afeye_i++] = '\0'` безопасно. **[INFERENCE]** — вывод по тексту патча, без сборки.

### FormData::Entry::Entry(const String& name, Blob* blob, const String& filename) (hunk ниже)
- что делает: `EmitStr(kTaintEdge, …, "fd-blob name=<до 96> file=<до 96> size=<blob->size() или 0>")`, буфер 320. Содержимое Blob НЕ перехватывается.
- kind/tag: **37 `taint-edge`**, prose `fd-blob`.

### URLSearchParams::toString() const (hunk `@@ -171,6 +192,14 @@`)
- что делает: ПОСЛЕ `EncodeAsFormData(encoded_data)` — `EmitSpan(kTaintEdge, …, "url-search-params", encoded_data.data(), encoded_data.size())`.
- kind/tag: **37 `taint-edge`**, tag `url-search-params`. Перехватывается готовая percent-encoded строка запроса.

### TextDecoder::Decode (hunk `@@ -118,6 +139,13 @@`)
- что делает: ПОСЛЕ `codec_->Decode(input, flush, fatal_, saw_error)`, но условие по `input.empty()` — эмитит **ВХОДНЫЕ байты**, а не декодированную строку: `EmitSpan(kTaintEdge, …, "text-decoder", input.data(), input.size())`.
- kind/tag: **37 `taint-edge`**, tag `text-decoder`.

### TextEncoder::encode (hunk `@@ -74,6 +95,14 @@`)
- что делает: ПОСЛЕ `VisitCharacters(...)` — `EmitSpan(kTaintEdge, …, "text-encoder", result.data(), result.size())`. Здесь перехватывается **РЕЗУЛЬТАТ** (UTF-8 байты).
- kind/tag: **37 `taint-edge`**, tag `text-encoder`.

### TextEncoder::encodeInto (hunk `@@ -99,6 +128,18 @@`)
- что делает: после `setRead`/`setWritten` — если `bytes_written > 0`, берёт `destination->ByteSpan()`, `afeye_n = bytes_written`, проверка `afeye_n <= afeye_out.size()`, `EmitSpan(kTaintEdge, …, "text-encoder-into", out.data(), afeye_n)`.
- kind/tag: **37 `taint-edge`**, tag `text-encoder-into`.

### Rust-сторона kind 37
- `taint-edge` ∈ `payload_kinds` (`sinkfilter.rs:1417`) → **carrier-узлы графа**, body участвует в blake3-run'ах (stride 16, 32-байтные ключи).
- НЕ sink: ни одно из условий `is_crypto_sink`/`is_upload`/`is_ws_sink`/`is_query_sink` (строки 1485-1499) не покрывает kind `taint-edge`.
- Документировано в `sinkfilter.rs:2219`: «nodes = payload records (crypto-op/structured-clone/net-request/taint-edge/websocket)».
- Смысл: taint-edge-записи — это ПРОМЕЖУТОЧНЫЕ рёбра. Цепочка «сырые байты → text-encoder → form-data → req-body» строится через совпадение 32-байтных blake3-ключей между соседними записями, а seed'ом служит `req-body`.

---

## patches/0017-net-ws-outbound.patch — ИСХОДЯЩИЕ кадры WebSocket (kind 19, tag `ws-frame-out`)

Один файл: `services/network/websocket.cc`, функция `WebSocket::ReadAndSendFrameFromDataPipe(DataFrame* data_frame)`, два хука.

### Хук 1: полная реассемблированная запись (hunk `@@ -1001,6 +1001,17 @@`)
- условие: `bytes_reassembled_ == data_frame->data_length` (весь кадр собран), сразу после `blocked_on_websocket_channel_ = true` и ДО `channel_->SendFrame(/*fin=*/true, …)`.
- что делает: `EmitSpan(kWebSocket, …, "ws-frame-out", message_under_reassembly_->bytes(), min(data_frame->data_length, 0x40000))`.
- kind/tag: **19 `websocket`**, tag `ws-frame-out`.

### Хук 2: потоковая отправка части (hunk `@@ -1020,6 +1031,15 @@`)
- условие: путь, где кадр режется на части; `data_to_pass` уже заполнен через `copy_prefix_from(buffer.first(size_to_send))`.
- что делает: `EmitSpan(kWebSocket, …, "ws-frame-out", data_to_pass->bytes(), min(size_to_send, 0x40000))`.
- kind/tag: **19 `websocket`**, tag `ws-frame-out` — ТОТ ЖЕ тег, что и в хуке 1.

### Почему это самый важный net-патч
`ws-frame-out` — **единственный тег kind'а 19, который Rust считает sink'ом**: `sinkfilter.rs:1498` `let is_ws_sink = r.kind == "websocket" && tag == "ws-frame-out";`. Sink'и становятся seed'ами обратного BFS (`sinkfilter.rs:1582-1588`: `dist[ni]=0; queue.push(ni)`), и только sink'и получают дополнительные variant-run'ы (base64/hex/кастомные алфавиты, строки 1512-1532, лимит `VARIANT_MAX_SINKS = 4096`, `VARIANT_MIN_BYTES = 64`).

- лимиты: НЕТ счётчика. Кламп 0x40000 = 262144 = ровно `kSpanCap` net-слоя.
- **последствие двух хуков с одним тегом**: одна логическая отправка может дать несколько записей `ws-frame-out` (по одной на часть). Это не баг для графа (больше seed'ов), но завышает `stats.graph_sinks`.

---

## patches/0018-blink-crypto-out.patch — ВЫХОД криптоопераций (kind 11, tag `crypto-out`)

Один файл: `third_party/blink/renderer/modules/crypto/crypto_result_impl.cc`, функция `CryptoResultImpl::CompleteWithBuffer(base::span<const uint8_t> bytes)`, hunk `@@ -134,6 +140,16 @@`.

- почему здесь: `CompleteWithBuffer` — единая воронка, через которую SubtleCrypto возвращает JS готовый ArrayBuffer (результат encrypt/sign/digest/deriveBits). Перехват здесь ловит выход НЕЗАВИСИМО от того, какой метод его породил, и без правки каждого метода.
- что делает: условие `Enabled() && !bytes.empty()`; `static std::atomic<uint64_t> g_afeye_cout{0}`; **кап 200 000**; `EmitSpan(kCryptoOp, NowNs(), "crypto-out", bytes.data(), bytes.size())`.
- kind/tag: **11 `crypto-op`**, tag `crypto-out`.
- Хук стоит ПОСЛЕ `if (!resolver_) return;` и ДО `DOMArrayBuffer::Create(bytes)`.
- limity: собственного клампа нет → `kSpanCap = 64 KiB`.
- Rust: `"crypto-out"` ∈ `SINK_CRYPTO_OPS` (`sinkfilter.rs:185`) → **sink-seed**, плюс variant-run'ы. Документировано в `sinkfilter.rs:2206`: «content-sink crosses the encryption boundary via crypto-out/ws-frame-out byte identity».
- **связка с 0007**: 0007 ловит ВХОД (`encrypt`/`sign`/`digest` — тоже sink-seeds), 0018 ловит ВЫХОД. Вместе они дают полную пару «что зашифровали → что получили». `decrypt` на входе логируется, но его выход тоже попадёт в `crypto-out` — различить, какому методу принадлежит данный `crypto-out`, по записи НЕВОЗМОЖНО (в теге нет имени операции).

---

## patches/0019-blink-fp-values.patch — значения fingerprinting-API (kind 16, prose)

Трогает 7 файлов. Все записи — `EmitStr` под kind 16, у каждого файла свой независимый счётчик.

| файл | функция / hunk | запись | счётчик | кап |
|---|---|---|---|---|
| `core/css/css_computed_style_declaration.cc` | `GetPropertyCSSValue`, `@@ -383,6 +396,18 @@` | `css/get-computed prop=<до 64> val=<CssText, до 96>` | `g_afeye_css` | 2 000 000 |
| `core/css/font_face_set.cc` | `check`, `@@ -232,6 +245,17 @@` | `fonts/check font=<до 96> text=<до 40>` | `g_afeye_c19` | 200 000 |
| `core/css/media_query_list.cc` | `matches`, `@@ -118,6 +131,16 @@` | `media/matches q=<до 128> m=<0\|1>` | `g_afeye_mqm` | 200 000 |
| `core/frame/local_dom_window.cc` | `matchMedia`, `@@ -1106,6 +1119,16 @@` | `media/query q=<до 128>` | `g_afeye_mm` | 200 000 |
| `modules/canvas/canvas2d/base_rendering_context_2d.cc` | `DrawTextInternal`, `@@ -1025,6 +1032,21 @@` | `canvas/draw-text op=<stroke\|fill> text=<до 64> font=<до 64> xy=%.1f,%.1f` | `g_afeye_drawtext` | 2 000 000 |
| `modules/notifications/notification.cc` | `permission`, `@@ -421`/`@@ -429`/`@@ -448` | `perm/notification value=denied ctx=insecure` / `value=default ctx=prerender` / `value=<granted\|denied\|prompt>` | НЕТ | ∞ |
| `modules/permissions/permissions.cc` | `query`, `@@ -113,6 +120,15 @@` | `perm/query name=<PermissionNameToString, до 40>` | НЕТ | ∞ |

- kind/tag: **16 `fingerprint`**, все — prose (без NUL).
- Хук `GetPropertyCSSValue` стоит ВНУТРИ `if (value)` перед `return value` — то есть логируются только успешно вычисленные свойства.
- Хук `MediaQueryList::matches` стоит ПОСЛЕ `UpdateMatches()`, поэтому `m=` отражает актуальное состояние.
- Три ветки в `Notification::permission` покрывают все три точки возврата: insecure-context, prerendering, нормальный путь.
- Rust: **НИ ОДИН из этих семи тегов не обрабатывается.** Проверено grep'ом по `src/`: `css/get-computed`, `fonts/check`, `media/matches`, `media/query`, `canvas/draw-text`, `perm/notification`, `perm/query` — **ноль совпадений**. В `VALUE_TAGS` их нет, `value_of_prose` их не знает → строка `sinkfilter.rs:1482-1484` даёт `continue`. Записи индексируются (`stats.per["blink/fingerprint"]`) и складываются в `raw/`, но в анализ не идут. Единственный косвенный потребитель — `Notification.permission`/`Permissions.query` не имеют игол в `FP_API_NEEDLES` тоже.

---

## patches/0023-sink-drop-witness.patch — свидетель потерь (kind 39)

Трогает 6 файлов: по паре `.cc`/`.h` для каждого из трёх слоёв (`services/network/afeye_sink.*`, `third_party/blink/renderer/platform/afeye/sink.*`, `v8/src/afeye/sink.*`). Изменения в трёх слоях ТЕКСТОВО ИДЕНТИЧНЫ.

### enum: добавлен `kSinkDrop = 39`
- `services/network/afeye_sink.h`, hunk `@@ -14,6 +14,7 @@` — после `kWebSocket = 19`.
- `platform/afeye/sink.h`, hunk `@@ -33,6 +33,7 @@` — после `kTaintEdge = 37`.
- `v8/src/afeye/sink.h`, hunk `@@ -28,6 +28,7 @@` — после `kErrorStack = 38`.
- Rust: `KINDS[39] = "sink-drop"` (`collect.rs:55`).

### fn WriteDropReport(int fd, uint64_t dropped)  (новый, во всех трёх .cc)
- назначение: записать сам факт потерь отдельной записью.
- что внутри: `fd < 0` → return. `snprintf("sink-drop layer=<kLayer> dropped=<N>")`, буфер 96. Ручная сборка 16-байтного заголовка: `total = 16 + n`, `rec[4] = kSinkDrop`, `rec[5..8] = 0`, `ts = MonoNs()` в `rec+8`, сообщение в `rec+16`. Затем `WriteAll(fd, rec, total)`.
- **пишет напрямую в fd, МИНУЯ ring** — иначе репорт о переполнении ring'а сам бы в него не влез.
- связи: единственный вызов — из `DrainLoop`.

### Изменение DrainLoop (hunk `@@ -104,6 +123,8 @@` в net, `@@ -110,6 +129,8 @@` в blink, `@@ -105,6 +124,8 @@` в v8)
Добавлены две локальные переменные перед циклом: `uint64_t reported_drops = 0;` и `uint64_t last_report_ns = 0;`.

### Изменение DrainLoop, конец тела цикла (hunk `@@ -145,6 +166,17 @@` / `@@ -151,6 +172,17 @@` / `@@ -146,6 +167,17 @@`)
```
const uint64_t now_dropped = g_dropped.load(relaxed);
if (now_dropped != reported_drops) {
  const uint64_t now_ns = MonoNs();
  if (now_ns - last_report_ns >= 100ull * 1000ull * 1000ull) {   // 100 мс
    WriteDropReport(fd, now_dropped);
    if (fd >= 0) { reported_drops = now_dropped; last_report_ns = now_ns; }
  }
}
```
- логика: репорт пишется не чаще раза в **100 мс** на слой. Если `fd < 0` (файл не открылся), `reported_drops`/`last_report_ns` НЕ обновляются → при следующем успешном открытии будет записано актуальное значение, а не пропущено.
- **что НЕ учитывается**: читается только `g_dropped` (переполнение ring'а). `g_write_err` (ошибки `write(2)`) в репорт не входит, хотя `SinkDropped()` возвращает их сумму. Расхождение между `SinkDropped()` и тем, что видит Rust.
- **что НЕ учитывается №2**: случай в `DrainLoop`, когда длина записи вне диапазона `[16, kMaxRecord]` и кольцо сбрасывается целиком (`tail = head`), не инкрементирует `g_dropped`. Массовая потеря при повреждённой записи остаётся невидимой.
- Rust: `sinkfilter.rs:1088-1094` — парсит `dropped=`, собирает `drop_events: Vec<(ts, pid, n)>`. Функция `drops_witnessed` (`sinkfilter.rs:405-410`): горизонт `ts + 500_000_000` (500 мс), true если есть событие с `dts <= horizon && n > 0`. Используется в `sinkfilter.rs:1932-1936`: если цепочка — dead-end И потерь в этом pid НЕ было → `c.dead_end_proven = true`, `stats.dead_end_proven += 1`. Иначе dead-end считается недоказанным (возможно, данные просто потерялись). Выводится в отчёт как `entry["dead_end_witness"]["ring_drops_in_pid"]` (строки 2056-2058).
- **замечание**: `drops_witnessed` принимает `_pid` и НЕ фильтрует по нему — горизонт только временной. Потери в ЛЮБОМ процессе (например в network service) обесценивают dead-end'ы всех цепочек в этот момент. Имя параметра с подчёркиванием говорит о том, что так и задумано, но семантически это «потери где угодно».

---

## patches/0025-v12_2-total-capture.patch — net/blink часть: приаттаченные cookie (kind 17)

Патч трогает 5 файлов, из них blink/net-стороне принадлежит ОДИН: `services/network/url_loader.cc`. Остальные четыре — v8 (`api.cc`, `logging/log.cc`, `objects/js-objects.cc`, `wasm/wasm-objects.cc`) и относятся к разделу V8.

### URLLoader::SetRawRequestHeadersAndNotify (url_loader.cc, hunk `@@ -2256,6 +2258,38 @@`)
- почему здесь: это точка, где cookie-джар уже ПРИЛОЖЕН к запросу сетевым стеком (после `AttachCookies`), но запрос ещё не отправлен. Ни `ScheduleStart` (0011), ни JS-сторона этих cookie не видят — `document.cookie` не отдаёт HttpOnly.
- что делает: добавляет include'ы `<atomic>`, `<cstdlib>`. Внутри — `static std::atomic<uint64_t> g_afeye_catt{0}` и `static bool g_afeye_catt_off` из `getenv("AFEYE_TRACE_COOKIEATTACH")` (off при `'0'`); **кап 500 000**. Затем обход `headers.headers()`, `base::EqualsCaseInsensitiveASCII(key, "Cookie")`; при совпадении строится тег `"cookie-attach url=" + url.spec()[0..48]` (reserve 96), значение урезается до **640 байт**, `EmitSpan(kNetReq, NowNs(), tag.c_str(), line.data(), line.size())`, затем `break` — только ПЕРВЫЙ Cookie-заголовок.
- kind/tag: **17 `net-request`**, span-тег `cookie-attach url=<первые 48 символов URL>`.
- **потеря данных**: 640 байт на cookie-строку и 48 символов на URL.
- Rust: **не sink и не carrier.** `is_upload` требует `tag == "req-body" || tag == "req-body-stream"` — не совпадает. `is_query_sink` требует `HTTP_METHODS.contains(tag)` — `"cookie-attach url=…"` не метод. Тег остаётся только в `raw/` и в `stats.per["net/net-request"]`. При этом `cookie-attach` — единственный источник HttpOnly-cookie в дампе, и в граф тейнтов он не входит.

---

## patches/0029-blink-wt-rtc-wire.patch — WebTransport и RTCDataChannel (kind 19!)

Трогает 4 файла: `modules/peerconnection/rtc_data_channel.cc`, `modules/webtransport/incoming_stream.cc`, `modules/webtransport/outgoing_stream.cc`, `modules/webtransport/web_transport.cc`.

В КАЖДЫЙ файл вставлен одинаковый блок в анонимном namespace (свой счётчик на файл):
```
std::atomic<uint64_t> g_afeye_<X>{0};
inline bool AfeyeWireOn() {
  static const bool off = [](){ const char* v = ::getenv("AFEYE_TRACE_WT_RTC");
                                return v && *v && v[0]=='0'; }();
  return !off && g_afeye_<X>.fetch_add(1, relaxed) < 200000;
}
inline void AfeyeEmitWire(const char* tag, const uint8_t* data, size_t len) {
  if (len == 0 || !AfeyeWireOn()) return;
  afeye::EmitSpan(afeye::kWebSocket, afeye::NowNs(), tag, data, (uint32_t)len);
}
```
Счётчики: `g_afeye_rtc` (rtc_data_channel.cc), `g_afeye_wtin` (incoming_stream.cc), `g_afeye_wtout` (outgoing_stream.cc), `g_afeye_wtdg` (web_transport.cc). **Кап 200 000 НА ФАЙЛ**, то есть до 800 000 записей суммарно.

> **КЛЮЧЕВОЕ**: все шесть тегов эмитятся под `afeye::kWebSocket` = **19**, то есть в Rust попадают как kind `"websocket"` — тот же kind, что у настоящих WebSocket-кадров из 0011/0017. Слои различаются только по имени файла (`blink-<pid>.rec` vs `net-<pid>.rec` → `layer_of` в `collect.rs:76-83`).

### Таблица тегов 0029
| файл | функция | hunk | тег | направление |
|---|---|---|---|---|
| `rtc_data_channel.cc` | `RTCDataChannel::OnMessage(webrtc::DataBuffer)` | `@@ -757,6 +783,12 @@` | `rtc-datachannel-in` | вход |
| `rtc_data_channel.cc` | `RTCDataChannel::SendDataBuffer(webrtc::DataBuffer)` | `@@ -824,6 +856,12 @@` | `rtc-datachannel-out` | **выход** |
| `incoming_stream.cc` | `IncomingStream::ReadFromPipeAndEnqueue`, ветка `MOJO_RESULT_OK` | `@@ -234,6 +260,10 @@` | `wt-stream-in` | вход |
| `outgoing_stream.cc` | `OutgoingStream::WriteDataSynchronously(base::span<const uint8_t>)` | `@@ -437,6 +463,10 @@` | `wt-stream-out` | **выход** |
| `web_transport.cc` | `WebTransport::DatagramUnderlyingSink::SendDatagram(base::span<const uint8_t>)` | `@@ -256,6 +282,9 @@` | `wt-datagram-out` | **выход** |
| `web_transport.cc` | `WebTransport::OnDatagramReceived(base::span<const uint8_t>)` | `@@ -1194,6 +1223,9 @@` | `wt-datagram-in` | вход |

Детали размещения:
- `rtc-datachannel-in` стоит сразу после `DCHECK_CALLED_ON_VALID_SEQUENCE`, ДО ветвления по `buffer.binary` — перехватывает и бинарные, и текстовые сообщения.
- `rtc-datachannel-out` — после `CHECK(!was_transferred_)`, до комментария про SCTP. `RTCDataChannel::SendRawData` НЕ хукается напрямую, но он вызывает `SendDataBuffer`, поэтому покрыт.
- `wt-stream-in` — внутри `case MOJO_RESULT_OK:` после `in_two_phase_read_ = true`, до `RespondBYOBRequestOrEnqueueBytes`. Комментарий патча отмечает, что этот вызов может реентерантно вернуться в тот же метод через `pull()`.
- `wt-stream-out` — в `WriteDataSynchronously` перед `data_pipe_->WriteData`. Асинхронный путь записи (`write` через `UnderlyingSinkBase`) НЕ хукается — только синхронный. `[INFERENCE]` о наличии асинхронного пути — по структуре класса в патче не видно.
- `wt-datagram-out` — в приватном `SendDatagram` класса `DatagramUnderlyingSink`, в самом начале, до создания resolver'а.
- `wt-datagram-in` — в самом начале `OnDatagramReceived`, до передачи в `datagram_underlying_source_`.

### Limity
Собственного клампа длины в `AfeyeEmitWire` НЕТ — только `kSpanCap = 64 KiB` blink-sink'а (с установкой `flags=1`). Для датаграмм WebTransport это не важно (лимит MTU), но для stream-записей крупный блок урежется до 64 KiB.

---

## patches/0030-blink-webgpu-capture.patch — WebGPU (kinds 16 И 19!)

Трогает 3 файла: `modules/webgpu/gpu_buffer.cc`, `modules/webgpu/gpu_queue.cc`, `modules/webgpu/gpu_shader_module.cc`. В каждый вставлен одинаковый блок:
```
std::atomic<uint64_t> g_afeye_<X>{0};
inline bool AfeyeWebGpuOn() {
  static const bool off = [](){ const char* v = ::getenv("AFEYE_TRACE_WEBGPU");
                                return v && *v && v[0]=='0'; }();
  return !off && g_afeye_<X>.fetch_add(1, relaxed) < 200000;
}
```
Счётчики: `g_afeye_wgb` (gpu_buffer.cc), `g_afeye_wq` (gpu_queue.cc), `g_afeye_wgsl` (gpu_shader_module.cc). **Кап 200 000 на файл.**

| файл | функция | hunk | kind | тег | body |
|---|---|---|---|---|---|
| `gpu_buffer.cc` | `GPUBuffer::CreateArrayBufferForMappedData(isolate, data, data_length)` | `@@ -530,6 +554,16 @@` | **16 fingerprint** | `webgpu/map-readback len=<data_length>` | байты маппинга |
| `gpu_queue.cc` | `GPUQueue::WriteBufferImpl` | `@@ -248,6 +272,18 @@` | **19 websocket** | `webgpu/write-buffer off=<buffer_offset> len=<data_span.size()>` | `data_span` |
| `gpu_queue.cc` | `GPUQueue::WriteTextureImpl` | `@@ -318,6 +354,16 @@` | **19 websocket** | `webgpu/write-texture len=<required_copy_size>` | `data_span` |
| `gpu_shader_module.cc` | `GPUShaderModule::Create` (static) | `@@ -30,6 +54,17 @@` | **16 fingerprint** | `webgpu/wgsl len=<wgsl_code.size()>` | исходник WGSL |

Детали:
- `webgpu/map-readback` — это результат `mapAsync`/`getMappedRange`, то есть **вычисленные GPU данные**. Тег собирается через `snprintf` с `%zu`.
- `webgpu/write-buffer` — данные, которые JS закачивает в GPU-буфер. `data_span = data.subspan(data_byte_offset, write_byte_size)`; хук стоит ДО `GetHandle().WriteBuffer(...)`.
- `webgpu/write-texture` — данные для загрузки в текстуру; размер `required_copy_size = std::min(data_span.size(), data_size_upper_bound)`. Хук ДО `GetHandle().WriteTexture(...)`.
- `webgpu/wgsl` — **полный исходник шейдера** (`webgpu_desc->code().Utf8()`), хук сразу после `wgsl_desc.code = wgsl_code.c_str()`. Для аналитики это самый ценный из четырёх: по WGSL видно, что именно считается на GPU (в т.ч. canvas-fingerprinting через compute).
- limity: собственного клампа нет → `kSpanCap = 64 KiB`. WGSL-шейдер крупнее 64 KiB будет обрезан с `flags=1`.

---

## patches/0032-net-socket-sink-gc-proof.patch — три независимые части

Патч трогает 5 файлов в трёх слоях. Название («net socket sink gc proof») описывает только часть содержания.

### Часть A (net): ChunkedDataPipeUploadDataStream::ReadInternal — `services/network/chunked_data_pipe_upload_data_stream.cc`, hunk `@@ -123,6 +127,15 @@`
- почему здесь: 0011 перехватывает тело запроса в `SetUpUpload` только для `DataElement::Tag::kBytes`. Chunked-загрузка (`fetch` с `ReadableStream`-телом) идёт через data pipe и никаких `DataElementBytes` не имеет — без этого хука такие тела невидимы полностью.
- что делает: после `data_pipe_->ReadData(...)` при `rv == MOJO_RESULT_OK` и `num_bytes > 0` — `EmitSpan(kNetReq, NowNs(), "req-body-stream", buf->data(), min(num_bytes, 0x40000))`.
- kind/tag: **17 `net-request`**, tag `req-body-stream`.
- лимиты: НЕТ счётчика; кламп 0x40000 = `kSpanCap` net-слоя.
- Rust: **полностью wired.** `sinkfilter.rs:1487-1488`: `is_upload = kind=="net-request" && (tag=="req-body" || tag=="req-body-stream")` → sink-seed. Есть регрессионный тест `sinkfilter.rs:2810-2827`: кладёт запись `req-body-stream\0<wire>`, kind 17, и проверяет `sf.graph_sinks >= 1` и `sf.graph_tainted >= 1`.

### Часть B (blink): MessagePort::postMessage — `core/messaging/message_port.cc`, hunks `@@ -61,6 +61,16 @@` и `@@ -117,6 +127,32 @@`
- добавляет include'ы и два `extern "C"`-объявления: `uint32_t afeye_taint_get_string(uint64_t key)` и `void afeye_taint_emit_sink(const char* sink, uint8_t space, uint64_t key, uint32_t tag)`. Оба определены в `v8/src/afeye/taint_abi.cc` (патч 0027, строки 320 и 334).
- что делает внутри `if (Enabled() && msg.message)`:
  1. **taint-часть**: `message.V8Value()`; если `IsString()` → `afeye_key = reinterpret_cast<uint64_t>(*afeye_str)` (адрес внутреннего представления V8-строки как ключ тейнта); `afeye_tag = afeye_taint_get_string(afeye_key)`; если тег ненулевой → `afeye_taint_emit_sink("post-message", 0 /* kKeyHeap */, afeye_key, afeye_tag)`.
  2. **wire-часть**: `msg.message->GetWireData()` → если непуст, `snprintf("post-message len=%u")` и `EmitSpan(kMessage, NowNs(), tag, wire.data(), min(wire.size(), 0x40000))`.
- kind/tag: **14 `message`**, span-тег `post-message len=<N>`.
- куда уходит taint-sink: `afeye_taint_emit_sink` → `TaintEmitSink` (0027, строки 193-203) → `EmitStr(kFingerprint, NowNs(), "taint-sink post-message space=0 key=<hex> tag=<hex>")` в **v8-слое** и `g_sunk_union.fetch_or(tag)`. Rust ловит это в `sinkfilter.rs:1716-1718` (`txt.starts_with("taint-sink ")` → `taint_sink_set` → флаг `taint_sink` у цепочки).
- **заметка о клампе**: `0x40000` = 262144, но это BLINK-слой, где `kSpanCap = 65536`. Реальный предел — 64 KiB; кламп 0x40000 мёртв и вводит в заблуждение.
- **смысл «gc proof»**: ключ тейнта — сырой адрес строки. Если GC переместит строку между тегированием и `postMessage`, ключ станет другим и тейнт потеряется. Патч это НЕ решает — он лишь фиксирует факт sink'а, если ключ ещё совпадает. Название относится скорее к части C.

### Часть C (v8): GC-свидетель — новые файлы `v8/src/afeye/gc_witness.cc` (44 строки) и `.h` (22 строки), плюс `v8/src/heap/heap.cc`
- `void GCEpilogueWitness(v8::Isolate*, v8::GCType gc_type, v8::GCCallbackFlags flags, void* data)` (gc_witness.cc, строки 12-38):
  - `!TaintEnabled()` → return.
  - `compacting = (gc_type & (kGCTypeScavenge | kGCTypeMinorMarkSweep | kGCTypeMarkSweepCompact)) != 0`; если не compacting → return.
  - `live = TaintLiveHeapTagUnion()`, `sunk = TaintSunkUnion()`.
  - если `live != kSrcNone` → `EmitStr(kFingerprint, NowNs(), "taint-swept tag=<hex>")`; `dead = live & ~sunk`; если `dead != kSrcNone` → `EmitStr(kFingerprint, …, "taint-deadend tag=<hex>")`.
  - в конце `TaintOnGCEpilogue(compacting)`.
- kind/tag: **16 `fingerprint`** в v8-слое, prose `taint-swept tag=` / `taint-deadend tag=`.
- регистрация: `v8/src/heap/heap.cc`, `Heap::SetUp(LocalHeap*)`, hunk `@@ -5874,6 +5877,10 @@` — `AddGCEpilogueCallback(afeye::GCEpilogueWitness, v8::kGCTypeAll, nullptr)` под `#ifdef V8_AFEYE`. Include `src/afeye/gc_witness.h` добавлен в hunk `@@ -17,6 +17,9 @@`.
- **смысл**: compacting-GC перемещает объекты, поэтому тейнт-таблица по адресам после него неполна. `taint-swept` фиксирует, какие теги были живы ДО уборки; `dead = live & ~sunk` — теги, которые так и не дошли до sink'а. Это доказательство того, что цепочка оборвалась не из-за отсутствия данных, а из-за сборщика.
- Rust: `sinkfilter.rs:1095-1108` — `taint-swept tag=` → `taint_swept_union |= hex`, `taint-deadend tag=` → `taint_deadend_union |= hex`. Оба парсятся как u64 из hex.
- **эта часть НЕ является ни net-, ни blink-** — она в v8. Отнесена в мой раздел только потому, что патч перечислен в задании; детально её должен разбирать раздел V8.

---

## Сводная таблица kind'ов: номер → имя → кто эмитит → кто парсит

Номера и имена — из `src/collect.rs:16-57` (массив `KINDS`, 41 элемент, индекс = номер). «Мёртвый» = kind не встречается ни в `payload_kinds` (`sinkfilter.rs:1413-1421`), ни в диспетчере kind'ов (`sinkfilter.rs:1076-1168`), ни в `interest` (`sinkfilter.rs:1692-1695`).

| # | имя KINDS | слой-эмитент | патч-эмитент | теги / формат | парсится в Rust |
|---|---|---|---|---|---|
| 0 | `sink-hello` | v8+blink+net | 0001/0005/0011 | prose `afeye-sink/<layer> v2 pid=N` | только `stats.per` |
| 11 | `crypto-op` | blink | 0007, 0018 | span: `getRandomValues`, `encrypt`, `decrypt`, `sign`, `digest`, `crypto-out` | **ДА**: payload_kinds; sink-seeds = `encrypt`/`sign`/`digest`/`crypto-out` (∈ `SINK_CRYPTO_OPS`) |
| 12 | `timer` | blink | 0006 | prose `timer-install id= timeout_ms= single=`, `timer-fire id= nesting=` | **ДА**: `TRIGGER_KINDS`, `BATCHED_KINDS` |
| 13 | `perf-entry` | — | — | **НЕ ЭМИТИРУЕТСЯ** | мёртвый (подтверждено `SERIES.md:6`) |
| 14 | `message` | blink | 0032-B | span `post-message len=N` | **частично**: нет в payload_kinds, нет в диспетчере → только `stats.per` |
| 15 | `structured-clone` | blink | 0007 | span `ssv` | **ДА**: payload_kinds → carrier |
| 16 | `fingerprint` | blink + v8 | 0007, 0012, 0013, 0014, 0019, 0030, 0032-C | span/prose, см. ниже | **ЧАСТИЧНО**: только теги из `VALUE_TAGS` + `value_of_prose` + префиксы `json-stringify`/`taint-sink`/`taint-swept`/`taint-deadend`/`gopd`/`cookie-*`/`storage-*` |
| 17 | `net-request` | net | 0011, 0025, 0032-A | span `req-body`, `req-body-stream`, `cookie-attach url=`; two-str `METHOD\0URL`, `req-headers\0…`; prose `req-body-total=N` | **ДА**: payload_kinds; sink-seeds = `req-body`, `req-body-stream`, `METHOD` (при query≥96 или af-вендоре) |
| 18 | `net-resp-body` | net | 0011 | span `resp-body`; two-str `resp-headers\0…`; prose `resp-mime= code=`, `complete url= err= recv=` | **НЕТ — мёртвый kind** (упомянут только в `collect.rs:34`) |
| 19 | `websocket` | net + **blink** | 0011, 0017 (net); 0029, 0030 (blink) | net: `ws-frame`, `ws-frame-fin`, `ws-frame-out`. blink: `wt-stream-in/out`, `wt-datagram-in/out`, `rtc-datachannel-in/out`, `webgpu/write-buffer`, `webgpu/write-texture` | **ДА, но только `ws-frame-out`** → sink. Остальные → carrier (см. раздел о дырке) |
| 20 | `client-hints` | — | — | **НЕ ЭМИТИРУЕТСЯ** | мёртвый (`SERIES.md:6`) |
| 21 | `sw-cache` | — | — | **НЕ ЭМИТИРУЕТСЯ** | мёртвый (`SERIES.md:6`) |
| 22 | `script-source` | blink | — | **НЕ ЭМИТИРУЕТСЯ в blink** (v8 эмитит kind 1) | `KINDS[22]` = `"script-source"` — дубль `KINDS[1]`; blink-записей нет |
| 23 | `input` | blink | 0009, 0015 | prose `input/key`, `input/mouse`, `input/raw type=` | **ДА**: `TRIGGER_KINDS` + `is_trigger_input`, `BATCHED_KINDS`, `sinkfilter.rs:953-957` |
| 24 | `event-dispatch` | blink | 0006 | prose `evt `, `evt-mouse `, `evt-key `, `lis ` | **ДА**: `TRIGGER_KINDS` + `is_trigger_event`, `BATCHED_KINDS` |
| 25 | `dom-metric` | blink | 0007 | prose `dom/client-w`, `dom/client-h`, `dom/scroll-w`, `dom/scroll-h`, `dom/client-rects`, `dom/bounding-rect`, `dom/bounding-rect-r`, `dom/offset-left/top/w/h`, `canvas/get-image-data`, `canvas/measure`, `canvas/measure-r` | **НЕТ — мёртвый kind** |
| 26 | `audio` | blink | 0007 | span `audio/offline-ch0` | **НЕТ — мёртвый kind** |
| 27 | `webrtc` | blink | 0007 | prose `webrtc create-offer`, `webrtc sdp-local <sdp>`, `webrtc ice <cand>` | **НЕТ — мёртвый kind** |
| 28 | `fetch` | blink | 0006 | prose `fetch url= type= ctx=` | **ДА**: `interest` → `send_initiator` |
| 29 | `dom-api` | blink | 0008, 0024 | prose `dom <Interface>.<get\|set\|call> <prop>` [+ ` val=<…>`] | **ДА**: `FP_API_NEEDLES` → `fp_reads`/`fp_entry`; `BATCHED_KINDS` |
| 33 | `clock` | blink (+v8) | 0012 | prose `clock performance-now` | **ДА**: `clock_ts` → `c.clock_reads`; `BATCHED_KINDS` |
| 35 | `worker` | blink | 0010 | prose `worker-scope iso= name= secure=` | **ДА**: `worker_of` → `workers` |
| 36 | `nav-start` | blink | 0010 | prose `nav-start mono_ns=` | **ДА**: минимум `mono_ns` → `nav_start` |
| 37 | `taint-edge` | blink | 0016 | span `btoa`, `atob`, `form-data`, `url-search-params`, `text-decoder`, `text-encoder`, `text-encoder-into`; prose `fd-blob` | **ДА**: payload_kinds → carrier (не sink) |
| 39 | `sink-drop` | v8+blink+net | 0023 | prose `sink-drop layer=<L> dropped=<N>` | **ДА**: `drop_events` → `drops_witnessed` → `dead_end_proven` |

### kind 16 `fingerprint`: какие теги реально читаются
| тег | патч | формат | читается в Rust | где |
|---|---|---|---|---|
| `cookie-get len=N` | 0013 | span | **ДА** (VALUE_TAGS + `token_access`) | `sinkfilter.rs:1423`, `1720-1726` |
| `cookie-set len=N` | 0013 | span | **ДА** | `sinkfilter.rs:1424` |
| `storage-get key=… vlen=N` | 0013 | span | **ДА** | `sinkfilter.rs:1425` |
| `storage-set key=… vlen=N` | 0013 | span | **ДА** | `sinkfilter.rs:1426` |
| `canvas/get-image-data-r` | 0014 | span | **ДА** | `sinkfilter.rs:1427` |
| `webgl/read-pixels-r` | 0014 | span | **ДА** | `sinkfilter.rs:1428` |
| `audio/float-frequency` | 0014 | span | **ДА** | `sinkfilter.rs:1429` |
| `audio/byte-frequency` | 0014 | span | **ДА** | `sinkfilter.rs:1430` |
| `audio/float-timedomain` | 0014 | span | **ДА** | `sinkfilter.rs:1431` |
| `audio/byte-timedomain` | 0014 | span | **ДА** | `sinkfilter.rs:1432` |
| `webgl/unmasked-vendor pname= val=` | 0007 | prose | **ДА** через `value_of_prose` | `sinkfilter.rs:329-339`, `1434` |
| `webgl/unmasked-renderer pname= val=` | 0007 | prose | **ДА** | `sinkfilter.rs:1435` |
| `webgl/param pname= val=` | 0007 | prose | **ДА** | `sinkfilter.rs:1436` |
| `canvas/measure-r text= w=` | 0007 | prose | **ДА** | `sinkfilter.rs:340-348`, `1437` |
| `json-stringify head=` | 0021 (v8) | prose | **ДА** (`payload_assembler`) | `sinkfilter.rs:1713-1715` |
| `taint-sink <name> space= key= tag=` | 0027/0032-B (v8) | prose | **ДА** (`taint_sink`) | `sinkfilter.rs:1716-1718` |
| `taint-swept tag=<hex>` | 0032-C (v8) | prose | **ДА** | `sinkfilter.rs:1095-1101` |
| `taint-deadend tag=<hex>` | 0032-C (v8) | prose | **ДА** | `sinkfilter.rs:1102-1108` |
| `gopd holder=proxy key=` | 0025 (v8) | prose | **ДА** (`gopd_chains`) | `sinkfilter.rs:1745-1747` |
| `webgl/param-int pname= v0= v1=` | 0007 | prose | **НЕТ** | — |
| `webgl/get-parameter pname=` | 0007 | prose | **НЕТ** | — |
| `webgl/get-extension name=` | 0007 | prose | **НЕТ** (но `getExtension` ∈ FP_API_NEEDLES через kind 29) | — |
| `webgl/supported-extensions n= list=` | 0007 | prose | **НЕТ** | — |
| `webgl/read-pixels rect=` | 0014 | prose | **НЕТ** | — |
| `webgl/shader-precision sh= pr=` | 0007 | prose | **НЕТ** | — |
| `canvas/to-data-url mime= len=` | 0012 | prose | **НЕТ** | — |
| `canvas/to-blob mime= w= h=` | 0012 | prose | **НЕТ** | — |
| `device id= group= label= type=` | 0007 | prose | **НЕТ** | — |
| `css/get-computed prop= val=` | 0019 | prose | **НЕТ** | — |
| `fonts/check font= text=` | 0019 | prose | **НЕТ** | — |
| `media/matches q= m=` | 0019 | prose | **НЕТ** | — |
| `media/query q=` | 0019 | prose | **НЕТ** | — |
| `canvas/draw-text op= text= font= xy=` | 0019 | prose | **НЕТ** | — |
| `perm/notification value=…` | 0019 | prose | **НЕТ** | — |
| `perm/query name=` | 0019 | prose | **НЕТ** | — |
| `webgpu/map-readback len=N` | 0030 | span | **НЕТ** | — |
| `webgpu/wgsl len=N` | 0030 | span | **НЕТ** | — |

---

## ДЫРКА: теги 0029/0030 под kind 19 vs `is_ws_sink`

Это главная найденная проблема. Формулировка точная, по строкам.

**C++-сторона.** 0029 и 0030 эмитят ДЕСЯТЬ тегов под `afeye::kWebSocket` (= 19):
- `wt-stream-in`, `wt-stream-out` (outgoing_stream.cc, hunk `@@ -437,6 +463,10 @@`)
- `wt-datagram-in`, `wt-datagram-out` (web_transport.cc, hunks `@@ -256,6 +282,9 @@` и `@@ -1194,6 +1223,9 @@`)
- `rtc-datachannel-in`, `rtc-datachannel-out` (rtc_data_channel.cc, hunks `@@ -757,6 +783,12 @@` и `@@ -824,6 +856,12 @@`)
- `webgpu/write-buffer`, `webgpu/write-texture` (gpu_queue.cc, hunks `@@ -248,6 +272,18 @@` и `@@ -318,6 +354,16 @@`)

**Rust-сторона.** `src/sinkfilter.rs:1498`:
```rust
let is_ws_sink = r.kind == "websocket" && tag == "ws-frame-out";
```
Сравнение с **точным** строковым литералом. Ни один из десяти тегов выше не равен `"ws-frame-out"`. Единственный эмитент `ws-frame-out` — 0017 (`services/network/websocket.cc`, два хука).

**Последствия по цепочке:**
1. `sinkfilter.rs:1499`: `let sink = is_crypto_sink || is_upload || is_ws_sink || is_query_sink;` → для всех десяти тегов `sink == false`.
2. `sinkfilter.rs:1501-1505`: не-sink идёт как carrier, под лимитами `CONTENT_MAX_RECORDS = 50_000` (строка 170) и `GRAPH_MAX_EDGES = 8_000_000` (строка 172). При превышении — `continue`, запись ВООБЩЕ не становится узлом графа.
3. `sinkfilter.rs:1512`: `if sink && body.len() >= VARIANT_MIN_BYTES && sinks_seen < VARIANT_MAX_SINKS` → **variant-run'ы (base64 / hex / кастомные алфавиты из `extract_alphabets`) для этих записей НЕ строятся.** То есть если страница отправила токен по WebTransport в base64 — совпадение не найдётся.
4. `sinkfilter.rs:1582-1588`: `for (ni, n) in nodes.iter().enumerate() { if n.sink { dist[ni] = 0; queue.push(ni); seed_count += 1; } }` → **эти записи никогда не становятся seed'ами обратного BFS.** `stats.graph_sinks` их не считает.
5. `sinkfilter.rs:1640-1644`: `content_ts` берётся из `graph_ts` с `hop <= 1`, а `graph_ts` — только из узлов с `dist != u32::MAX`. Узел, до которого не дошёл BFS от настоящего sink'а, в `content_ts` не попадает → флаг `content_sink` (`sinkfilter.rs:561-564`, `1913-1915`) не ставится.

**Практический итог:** канал exfiltration, идущий ТОЛЬКО через WebTransport (stream или datagram), ТОЛЬКО через RTCDataChannel или ТОЛЬКО через `GPUQueue.writeBuffer`, даёт `graph_sinks == 0` и ни одной цепочки. Данные при этом физически захвачены (записи есть в `.rec`, есть в `index.jsonl`, есть в `raw/`, `stats.per["blink/websocket"]` их считает) — но анализатор их sink'ом не считает.

**Проверка grep'ом:** строки `webgpu`, `wt-stream`, `wt-datagram`, `rtc-datachannel` в `src/`, `tests/`, `tools/` — **ноль совпадений**. Ни в одном Rust-файле, ни в одном тесте эти теги не упоминаются.

**Отсутствие guard'а по слою.** `is_ws_sink` проверяет только `r.kind`, не `r.layer`. Kind 19 эмитят И net (`ws-frame*`), И blink (`wt-*`, `rtc-*`, `webgpu/*`). Сегодня ложных срабатываний нет, потому что blink не эмитит литерал `ws-frame-out`. Но если бы какой-нибудь blink-патч начал эмитить тег `ws-frame-out`, он был бы засчитан как sink без всякой проверки слоя. `Rec.layer` при этом доступен (`sinkfilter.rs:192`).

**Документация расходится с кодом.** `sinkfilter.rs:2219` (строка `"rule"` в JSON-отчёте) утверждает: «seeds = req-body + ws-frame-out + payload-forming crypto raw_data + crypto-out». Это описание соответствует коду — но оно молчит о том, что wt/rtc/webgpu под тем же kind'ом seed'ами НЕ являются. `SERIES.md` слова `webgpu`/`wt-stream`/`rtc-datachannel` не содержит вообще (grep — ноль совпадений), то есть дырка нигде не задокументирована.

**Минимальная правка** (для справки, не применялась): в `sinkfilter.rs:1498` заменить точное равенство на набор исходящих тегов, например
`matches!(tag.as_str(), "ws-frame-out" | "wt-stream-out" | "wt-datagram-out" | "rtc-datachannel-out" | "webgpu/write-buffer" | "webgpu/write-texture")`,
и добавить `r.layer` в условие там, где семантика слоёв различается.

---

## Прочие найденные несоответствия и дырки

1. **`deriveBits` — sink объявлен, но не эмитится.** `SINK_CRYPTO_OPS` содержит `"deriveBits"` (`sinkfilter.rs:183`), но в `subtle_crypto.cc` хук отсутствует: 0007 добавляет в `SubtleCrypto::deriveBits` (hunk `@@ -823,6 +872,7 @@`) ровно одну ПУСТУЮ строку. Также не хукаются `deriveKey`, `importKey`, `generateKey`, `wrapKey`, `unwrapKey`. Вывод ключей через deriveBits для анализа невидим.

2. **`net-resp-body` (kind 18) — весь kind мёртв в анализе.** Четыре хука 0011 (`resp-headers`, `resp-mime`, `resp-body`, `complete`) пишут данные, которые Rust не читает вообще: `"net-resp-body"` встречается в `src/` только в таблице имён `collect.rs:34`. Тела HTTP-ответов захватываются в `raw/`, но не влияют ни на граф, ни на флаги цепочек.

3. **`dom-metric` (kind 25), `audio` (26), `webrtc` (27) — мёртвые kind'ы.** 0007 эмитит под ними ~20 различных записей (все DOM-метрики layout, `audio/offline-ch0`, весь SDP/ICE). Ни одна не читается. При этом `SERIES.md:6` перечисляет как мёртвые только `kPerfEntry 13`, `kClientHints 20`, `kAtomics 9`, `kSabBacking 10`, `kSwCache 21` — то есть 25/26/27 в списке мёртвых НЕ значатся, хотя эмитируются и не потребляются.

4. **`blink kScriptSource = 22` объявлен, но в blink не эмитится.** Grep по всем патчам: `kScriptSource` встречается в 0001 (v8 enum), 0002 (v8 эмитент), 0005 (blink enum). Blink-эмитента нет. `SERIES.md:6` этот kind как мёртвый не упоминает. Побочный эффект: `KINDS[1]` и `KINDS[22]` — обе `"script-source"` (`collect.rs:17` и `collect.rs:38`), поэтому `stats.per` для двух layer'ов сливается в одно имя; `sinkfilter.rs:1448` (`filter(|r| r.kind == "script-source")` для извлечения кастомных алфавитов base-N) читает обе.

5. **0019 полностью не потребляется.** Семь тегов (`css/get-computed`, `fonts/check`, `media/matches`, `media/query`, `canvas/draw-text`, `perm/notification`, `perm/query`) — ноль упоминаний в `src/`. Патч генерирует до 4.6 млн записей на процесс (2M + 200k + 200k + 200k + 2M) плюс неограниченные `perm/*`, и ни одна не влияет на результат.

6. **`canvas/measure-r` эмитится под kind 25, но объявлен в VALUE_TAGS для kind 16.** `VALUE_TAGS` (`sinkfilter.rs:1437`) и `value_of_prose` (строки 340-348) обрабатывают `canvas/measure-r`, однако 0007 эмитит его под `kDomMetric` (25). Условие `sinkfilter.rs:1473` вызывает `value_of_prose` только для `r.kind == "fingerprint"`. Результат: ширина текста (ключевой сигнал canvas-fingerprinting'а) в граф не попадает.

7. **`cookie-attach` (0025) не участвует в графе.** Тег `cookie-attach url=…` под kind 17 не совпадает ни с `is_upload` (нужен ровно `req-body`/`req-body-stream`), ни с `is_query_sink` (нужен HTTP-метод). Единственный источник HttpOnly-cookie в дампе остаётся непрочитанным.

8. **Жёсткие обрезы значений без флага усечения.** `EmitFlags` ставит `flags|=1` только при обрезе по `kMaxRecord`. Обрезы, сделанные ДО вызова `EmitSpan`, невидимы: cookie 960 байт (0013), storage 800 байт (0013), cookie-attach 640 байт (0025), audio offline 16384 байт (0007). Rust-сторона считает такие записи полными (`stats.truncated` их не учитывает, `collect.rs:335-337`).

9. **Несогласованные капсы.** Патчи 0006, 0007, 0009, 0010, 0011, 0017, 0032 не имеют счётчиков ВООБЩЕ — при агрессивной странице (mousemove 60 Гц × `event_dispatcher` × `widget_event_handler` × `mouse_event_manager` = до 3 записей на движение) ring на 8 MiB переполняется, и это видно только через 0023. Патчи 0012–0016, 0018–0019, 0024–0025, 0029–0030 имеют капсы от 100k до 8M. Единой политики нет. `SERIES.md:86` прямо заявляет про 0033 «НИКАКИХ ЛИМИТОВ» — но это верно только для 0033.

10. **Кап 0016 общий на 5 API.** `kAfeyeTaintCap = 100000` применяется к глобальному `blink::afeye::g_afeye_taint` (sink.cc:7), который инкрементируют `btoa`, `atob`, `form-data`, `url-search-params`, `text-decoder`, `text-encoder`, `text-encoder-into` совместно. Страница, активно вызывающая `btoa`/`atob`, исчерпает бюджет до того, как сработает `form-data` — и данные формы потеряются. Порядок исчерпания зависит от порядка вызовов в странице.

11. **`AfeyeApiCell`: 65536 ячеек, ~7.5 MiB BSS, без освобождения.** Таблица в 0008 заполняется линейным probing'ом под глобальным mutex'ом; при исчерпании `AfeyeWrapDomApi` возвращает пустой `Local` и член интерфейса остаётся БЕЗ хука молча (счётчика исчерпания нет, в отчёт ничего не пишется). Dedupe по `(orig, prop)`, `what` фиксирует только первый увиденный `interface_name`.

12. **Кап `g_afeye_api_calls` = 8 000 000 на процесс** (0008/0024). После исчерпания DOM-API вызовы продолжают исполняться, но не логируются; счётчик переполнения никуда не сообщается (в отличие от ring-drop'ов, которые видны через kind 39).

13. **`ctx=` (Tag()) может быть устаревшим.** `SetTag` пишут только 0006 (`evt:<type>`, `timer:<id>`) и никто не очищает тег по завершении обработчика. Все `dom/*`-записи 0007 и `fetch`-запись 0006 печатают `ctx=<Tag()>` — значение, оставшееся от ПОСЛЕДНЕГО события/таймера этого потока. Записи, сделанные вне обработчика (например при initial layout), получат `ctx=evt:load` или что там было последним. На Rust-стороне поле `ctx=` не парсится нигде.

14. **0012 vs 0034 — два независимых блока в одной функции.** `Performance::now()` содержит СНАЧАЛА лог 0012 (`AFEYE_TRACE_CLOCK`, kind 33), ЗАТЕМ виртуализацию 0034 (`AFEYE_VIRTUAL_CLOCK`, возврат `origin_ms + afeye_vclock_ns()/1e6`). При включённой виртуализации залогированное число вызовов `performance.now` остаётся реальным, а возвращаемое значение — виртуальным. Это согласовано с комментарием 0034 («the 0012 trace above still logs real now() calls»), но означает, что kind 33 не несёт информации о том, КАКОЕ значение увидела страница.

15. **`0x40000`-клампы в blink-слое мертвы.** 0032-B (`message_port.cc`) клампит wire-данные до 262144, но blink `kSpanCap = 65536` — реально пишется 64 KiB. В net-слое (0011, 0017, 0032-A) тот же кламп 0x40000 совпадает с `kSpanCap = 262144` и тоже избыточен, но безвреден.

16. **net `ReinitAfterFork` без guard'а** — см. раздел 0011: создаёт файл и вечный поток при выключенном sink.

17. **Файлы multipart-загрузки не перехватываются.** 0011 `SetUpUpload` пропускает все `DataElement`, у которых `type() != kBytes`. Загрузка файла через `<input type=file>` + form submit даёт `DataElementFile` — его содержимое в `req-body` не попадёт. 0032-A закрывает только chunked-pipe-путь.

18. **`GetWireData()` в 0032-B даёт уже сериализованный blob** (structured clone), а 0007 эмитит `ssv` из конструктора `SerializedScriptValue(DataBufferPtr)`. Оба пишут одни и те же байты под разными kind'ами (15 и 14). Kind 14 в графе не участвует, поэтому дублирование безвредно, но объём `raw/` удваивается для каждого postMessage.

---

## Взаимодействия

### Как blink/net-патчи связаны с V8-патчами
- **Общий номерной пространство kind'ов.** Три независимых enum'а (`v8/src/afeye/sink.h`, `platform/afeye/sink.h`, `services/network/afeye_sink.h`) согласованы вручную. Пересечения: 0 (`sink-hello`), 16 (`fingerprint` — v8 и blink), 19 (`websocket` — net и blink), 33 (`clock` — v8 и blink), 39 (`sink-drop` — все три). Расхождение: v8 не имеет 11 (`crypto-op`), blink не имеет 1–10, 30–32, 34, 38, 40; net имеет только 17/18/19.
- **Один renderer-бинарник на blink+v8.** Комментарий 0034 (`performance.cc`, hunk `@@ -37,6 +37,13 @@`): «The renderer binary contains both blink and v8, so the v8 sink's instruction counter links directly». Поэтому blink вызывает `extern "C" uint64_t afeye_vclock_ns(void)` из v8-sink'а напрямую.
- **Тейнт-мост blink → v8.** 0032-B из `message_port.cc` (blink) вызывает `extern "C"` `afeye_taint_get_string` / `afeye_taint_emit_sink`, определённые в `v8/src/afeye/taint_abi.cc` (0027, строки 320, 334). Это единственный прямой вызов v8-кода из blink-патчей.
- **Тейнт-счётчик blink внутренний.** `blink::afeye::g_afeye_taint` (sink.cc:7) — СВОЙ, не связанный с v8-тейнтом; используется только как бюджет записей 0016.

### Как патчи связаны с Rust-конвейером
```
C++ хук → Emit*(kind, ts, …) → ring (8 MiB, слой-локальный)
        → DrainLoop → <AFEYE_RAW_DIR>/<layer>-<pid>.rec
        → collect.rs::scan_once  (tail-чтение, декод 16-байтного заголовка,
                                  kind → имя по KINDS[], layer → по имени файла,
                                  blake3(payload)[..16], text_preview до 4096 байт,
                                  BATCHED_KINDS → part-файлы raw/<layer>-<kind>-pNNNN.bin)
        → index.jsonl  (ts, l, pid, k, len, f, h, p, [o], [txt]) + stats.json
        → sinkfilter.rs  (payload_kinds → граф blake3-run'ов, seeds от sink-тегов,
                          BFS назад ≤6 hop'ов, флаги цепочек, dead-end + drop-witness)
        → bctrace.rs  (только kind 40, вне моих патчей)
```
- `collect.rs:10` `DEFAULT_RAW_DIR = "/tmp/afeye-raw"` совпадает с `RawDir()` во всех трёх sink'ах.
- `collect.rs:76-83` `layer_of` определяет слой по префиксу имени файла до первого `'-'`: `v8`/`blink`/`net`. Именно поэтому `kLayer` в sink'ах жёстко задан и не может быть произвольным.
- `browser.rs:126-131` и `163-166` пробрасывают `AFEYE_SINK` и `AFEYE_RAW_DIR` в процесс Chrome (приоритет: `AFEYE_RAW_DIR`, fallback `AF_RAW_DIR`, fallback `/tmp/afeye-raw`; `AFEYE_SINK` по умолчанию `"1"`).

### Сводка env-гейтов blink/net-стороны
| переменная | патч | где читается | полярность | эффект |
|---|---|---|---|---|
| `AFEYE_SINK` | 0005, 0011 | `blink sink.cc:59`, `afeye_sink.cc:53` | ON если задана, непуста, `!= '0'` | мастер-выключатель слоя |
| `AFEYE_RAW_DIR` | 0005, 0011 | `blink sink.cc:65`, `afeye_sink.cc:59` | — | каталог `.rec`, default `/tmp/afeye-raw` |
| `AFEYE_TRACE_DOM_VALUES` | 0024 | `idl_member_installer.cc` | **OFF при `== '0'`** | `=0` → kind 29 без ` val=` |
| `AFEYE_TRACE_CLOCK` | 0012 | `performance.cc` | OFF при `'0'` | `=0` → нет записей kind 33 |
| `AFEYE_TRACE_STORAGE` | 0013 | `document.cc`, `storage_area.cc` (2× независимо) | OFF при `'0'` | `=0` → нет cookie/storage |
| `AFEYE_TRACE_INPUT` | 0015 | `widget_event_handler.cc` | OFF при `'0'` | `=0` → нет `input/raw` |
| `AFEYE_TRACE_TAINT` | 0016 | 5 файлов (общий счётчик) | OFF при `'0'` | `=0` → нет kind 37 |
| `AFEYE_TRACE_WT_RTC` | 0029 | 4 файла | OFF при `'0'` | `=0` → нет wt/rtc |
| `AFEYE_TRACE_WEBGPU` | 0030 | 3 файла | OFF при `'0'` | `=0` → нет webgpu |
| `AFEYE_TRACE_COOKIEATTACH` | 0025 | `url_loader.cc` | OFF при `'0'` | `=0` → нет `cookie-attach` |

Все `AFEYE_TRACE_*` по умолчанию ВКЛЮЧЕНЫ (срабатывает только явный `'0'` первым символом). `AFEYE_SINK` по умолчанию ВЫКЛЮЧЕН. Ни один из этих гейтов не влияет на GN-аргументы: `blink_enable_afeye` / `network_enable_afeye` решают на этапе сборки, попадёт ли код в бинарник вообще.

### Сводка GN-аргументов и макросов
| GN-аргумент | define | target | патч |
|---|---|---|---|
| `blink_enable_afeye` (default false) | `BLINK_AFEYE` | `component("platform")`, через `config("afeye_config")` в `public_configs` | 0005 |
| `network_enable_afeye` (default false) | `NET_AFEYE` | `component("network_service")`, `defines +=` | 0011 |
| (v8, вне раздела) | `V8_AFEYE` | `group("v8_base")` | 0001 |

Каждый хук во всех патчах обёрнут в `#ifdef BLINK_AFEYE` или `#ifdef NET_AFEYE`, поэтому при выключенном GN-аргументе стоковое поведение сохраняется побитово. Единственное исключение — статический массив `g_afeye_api_cells[65536]` (0008), который тоже под `#ifdef`, так что и он не создаётся.

### Кто кого зовёт внутри blink-слоя
- `Enabled()` — из КАЖДОГО хука (единственная точка инициализации и fork-детекта).
- `NowNs()` — из каждого хука, как второй аргумент всех `Emit*`.
- `EmitStr` → `EmitFlags`; `EmitTwoStr` → `EmitFlags`; `EmitSpan` → `EmitFlags`; `Emit` → `EmitFlags` (не используется).
- `SetTag` ← 0006 (`event_dispatcher.cc`, `dom_timer.cc`); `Tag()` → 0006 (`resource_fetcher.cc`), 0007 (все `dom/*`, `canvas/*`).
- `g_afeye_taint` (sink.cc:7) ← 0016 (5 файлов).
- `Flush(500)` ← `std::atexit` (sink.cc:164).
- `DrainLoop` ← `InitOnce`, `ReinitAfterFork`; `WriteDropReport` (0023) ← `DrainLoop`.

### Кто кого зовёт внутри net-слоя
- Те же связи, минус `SetTag`/`Tag()`/`g_afeye_taint`/`Flush`-atexit (atexit есть, `InitOnce` net-версия, строка 168).
- `afeye_sink.h` включается в `url_loader.cc` (0011, 0025), `websocket.cc` (0011, 0017), `chunked_data_pipe_upload_data_stream.cc` (0032-A).

---

## АУДИТ СООТВЕТСТВИЯ ЭТАЛОНУ

### Пункт 1. `--jitless` / `--no-opt` / `--no-sparkplug`

Все chrome-флаги формируются в одной функции: `src/browser.rs:58-102` (`fn chrome_flags(f: &Flags) -> Vec<String>`).

Базовый вектор, `browser.rs:64-81`: `--no-first-run`, `--no-default-browser-check`, `--disable-session-crashed-bubble`, `--hide-crash-restore-bubble`, `--disable-search-engine-choice-screen`, `--disable-features=IsolateOrigins,site-per-process,PrivacySandboxSettings4`, `--disable-site-isolation-trials`, `--enable-unsafe-swiftshader`, `--password-store=basic`, `--use-mock-keychain`, `--no-sandbox`, `--remote-debugging-address=<f.bind>`, `--remote-debugging-port=<f.port>`, `--user-data-dir=<profile>`, `--window-size=1280,832`, `--window-position=<x>,<y>`.

Условные:
- `browser.rs:82-84` — `--user-agent=<f.ua>`, если `!f.ua.is_empty()`.
- `browser.rs:85-88` — `--headless`, `--disable-gpu`, если задан `AF_TEST_HEADLESS`.
- `browser.rs:89-92` — `--headless`, `--disable-gpu`, если `f.headless_shell` (может продублировать пару выше).
- `browser.rs:93-99` — **`--jitless`**, гейт: `std::env::var("AF_JITLESS").map(|v| v == "1").unwrap_or(false)`. То есть строго строка `"1"`; `AF_JITLESS=true` или `AF_JITLESS=` НЕ сработают. Комментарий в строках 94-97 связывает флаг с патчем 0033 и упоминает `AFEYE_VIRTUAL_CLOCK` (0034) как компенсацию таймингов.
- `browser.rs:100` — `about:blank` (стартовый URL, замыкает argv).

| эталон | факт | где |
|---|---|---|
| `--jitless` | **ЕСТЬ** | `browser.rs:98`, гейт `AF_JITLESS == "1"` на строке 93 |
| `--no-opt` | **НЕТ** | grep по всему репо (`src/`, `patches/`, `tools/`, `tests/`, `SERIES.md`) — ноль совпадений с `no-opt` |
| `--no-sparkplug` | **НЕТ** | ноль совпадений с `no-sparkplug` |
| `--js-flags=…` | **НЕТ** | ноль совпадений с `js-flags` |

Чего не хватает списком:
1. `--no-opt` — не передаётся нигде.
2. `--no-sparkplug` — не передаётся нигде.
3. Нет механизма `--js-flags`, через который V8-флаги вообще прокидываются в Chrome; единственный V8-флаг — `--jitless`, передаваемый как флаг командной строки Chrome напрямую.
4. `AF_JITLESS` по умолчанию НЕ задан (`unwrap_or(false)`), то есть в дефолтном запуске JIT ВКЛЮЧЁН и патч 0033 теряет все инструкции, ушедшие в Sparkplug/Maglev/TurboFan. `SERIES.md:85` описывает `AF_JITLESS=1` как обязательную часть включения, но в коде принуждения к этому нет — ни проверки, ни предупреждения.

Частичное соответствие: `--jitless` в V8 сам по себе запрещает и Sparkplug, и TurboFan, и Maglev `[INFERENCE — по семантике флага V8, не проверяемо в этом репо]`, поэтому практическое покрытие может быть полным и без `--no-opt`/`--no-sparkplug`. Но по букве эталона двух флагов нет, и проверкой это не покрыто.

### Пункт 2. Патч диспетчера Ignition

**Эталон требует:** файл `src/interpreter/interpreter-generator.cc`, макрос `GENERATE_BYTECODE_HANDLER`.

**Реально в `patches/0033-v8-ignition-bytecode-trace.patch`:**

| эталон | факт | где |
|---|---|---|
| файл `src/interpreter/interpreter-generator.cc` | **НЕ СООТВЕТСТВУЕТ**: файл не тронут | `diff --git` в 0033: `v8/src/afeye/bcrec.h` (новый), `v8/src/afeye/sink.cc`, `v8/src/afeye/sink.h`, `v8/src/interpreter/interpreter-assembler.cc`, `v8/src/runtime/runtime-trace.cc`, `v8/src/runtime/runtime.h`. `interpreter-generator.cc` в списке ОТСУТСТВУЕТ |
| макрос `GENERATE_BYTECODE_HANDLER` | **НЕ СООТВЕТСТВУЕТ**: ноль совпадений с этой строкой во всём патче | — |
| точка входа хука №1 | `InterpreterAssembler::InterpreterAssembler(...)` — КОНСТРУКТОР | патч 0033, строки 419-437 (hunk `@@ -48,6 +48,18 @@ InterpreterAssembler::InterpreterAssembler(CodeAssemblerState* state,`) |
| точка входа хука №2 | `InterpreterAssembler::InlineShortStar(TNode<WordT>)` | патч 0033, строки 438-454 (hunk `@@ -1381,6 +1393,16 @@`) |
| механизм вызова | `CallRuntime(Runtime::kAfeyeTraceBytecodeEntry, GetContext(), BytecodeArrayTaggedPointer(), SmiTag(BytecodeOffset()), GetAccumulatorUnchecked(), SmiTag(IntPtrConstant((int)operand_scale_)))` | патч 0033:430-433 и 446-449 |
| обработчик | `RUNTIME_FUNCTION(Runtime_AfeyeTraceBytecodeEntry)` | патч 0033:750-894, в `v8/src/runtime/runtime-trace.cc` |
| регистрация runtime-функции | `F(AfeyeTraceBytecodeEntry, 4, 1, RuntimeCallProperty::kCannotTriggerGC)` в новом макросе `FOR_EACH_INTRINSIC_AFEYE(F, I)` | патч 0033:910-912, в `v8/src/runtime/runtime.h` |

Расхождения по пунктам (что фиксируется реально vs что требует эталон):

1. **BytecodeOffset** — **соответствует**. Передаётся как `SmiTag(BytecodeOffset())` (0033:431), принимается как `args.smi_value_at(1)` (0033:762), пересчитывается в логический offset: `offset = bytecode_offset - BytecodeArray::kHeaderSize + kHeapObjectTag` (0033:773), кладётся в `Hdr.offset` (bcrec.h:44, через `InstrBuilder::Begin`, 0033:807-809).
2. **Опкод** — **соответствует, но читается не из аргументов, а из памяти**: `uint8_t op_byte = *pc` (0033:786), где `pc = GetFirstBytecodeAddress() + offset` (0033:778-780). Комментарий 0033:782-783 объясняет: `scale` — константа codegen'а, а по адресу `pc` лежит РЕАЛЬНЫЙ опкод, префиксы `Wide`/`ExtraWide` уже потреблены диспетчером. Далее `interpreter::Bytecodes::FromByte(op_byte)` (0033:787). В `Hdr.opcode` (bcrec.h:37).
3. **Аргументы** — **соответствует, декодируются движком**: цикл по `nops = Bytecodes::NumberOfOperands(bc)` (0033:816-869). Для каждого — `Bytecodes::GetOperandType(bc, i)` и `Bytecodes::GetOperandOffset(bc, i, scale)`. Для не-регистровых: `BytecodeDecoder::DecodeUnsignedOperand` / `DecodeSignedOperand` (0033:861-864), значение уходит как блок `kTagOperand` через `ib.Operand(i, sv)` (0033:865).
4. **Имя свойства из пула констант** — **НЕ соответствует по форме, соответствует по данным**. В самой записи инструкции имени НЕТ: `ib.Operand(i, …)` кладёт только cp-ИНДЕКС. Содержимое пула констант эмитится ОТДЕЛЬНЫМ записью func-def (`AfeyeEmitFuncDef`, 0033:658-748): обход `arr->raw_constant_pool()` с guard'ом `if (!IsSmi(raw_pool))` (0033:687-688, комментарий объясняет, что пустой пул — это Smi и разыменование его как массива даст краш), строки → `kCpTagStr`/`kCpTagStr16`, HeapNumber → `kCpTagF64`, остальное → `kCpTagRaw` (сырое слово). Разрешение индекса в имя происходит на Rust-стороне: `bctrace.rs:637-663` (`cp_json(&d.cp, *v as usize)`) для списка опкодов `LdaConstant`/`LdaGlobal`/`GetNamedProperty`/`SetNamedProperty`/`CallProperty*`/`Construct*`/`TestReferenceEqual`/`JumpIfTrueConstant`/`JumpIfFalseConstant`/`LdaLookupGlobalSlot` и др.
5. **Регистры источника** — **соответствует, и богаче эталона**. `if (interpreter::Bytecodes::IsRegisterInputOperandType(ot))` (0033:822) → `BytecodeDecoder::DecodeRegisterOperand` (0033:823-825), для `kRegList` дополнительно читается count из следующего операнда (0033:827-832). Затем для каждого регистра `frame->ReadInterpreterRegister(ridx)` (0033:839) и эмитятся: `ib.Reg(ru, val.ptr())` (сырое слово, `kTagReg`) + при `IsString` — полные байты через `AfeyeStringBytes` (`kTagRegStr`/`kTagRegStr16`), при `IsHeapNumber` — `kTagRegF64`, при `IsSmi` — `kTagRegSmi` (0033:841-855). Плюс `Hdr.regs[6]` хранит сырые слова первых шести входных регистров (bcrec.h:55).
6. **Регистры приёмника** — **НЕ соответствует**. Условие `IsRegisterInputOperandType(ot)` (0033:822) отсекает все output-only операнды: они уходят в `else`-ветку (0033:860-868), где эмитится ТОЛЬКО декодированный индекс, значение регистра не читается. Формально корректно (у регистра-приёмника до исполнения нет значения), но эталон требует фиксировать и приёмник — фактически доступен лишь его номер.
7. **SharedFunctionInfo** — **частично**. `sfi` читается: `Tagged<JSFunction> fn = frame->function(); Tagged<SharedFunctionInfo> sfi = fn->shared();` (0033:792-793). Используется для: `script_id` (`Cast<Script>(sfi->script())->id()`, 0033:795-796), `function_literal_id()`, `StartPosition()` — всё это сворачивается в FNV-1a хеш `func_id` (`MakeFuncId`, bcrec.h:120-131). Сам SFI (указатель или имя) в запись НЕ попадает. Получение кадра — через `JavaScriptStackFrameIterator` + `reinterpret_cast<UnoptimizedJSFrame*>` (0033:789-791): при включённом JIT этот cast невалиден, что ещё раз привязывает 0033 к `AF_JITLESS=1`.
8. **Имя исходного скрипта** — **соответствует**: `Tagged<Object> nm = sc->name()` → `AfeyeStringBytes(nm, &name_buf, &name_utf16, no_gc)` (0033:674-677), затем в func-def blob через `FuncDefBuilder::Build(..., name_buf.data(), name_buf.size(), ...)` (0033:728-730). Раскладка blob'а: `[u32 bc_len][u32 name_len][u32 cp_bytes][i32 frame_size][u32 param_count][bc…][name…][cp blocks…]`, head = 24 байта (bcrec.h:269-279).
9. **Имя ФУНКЦИИ** — **НЕ соответствует, и это активная ошибка**. `sfi->Name()` не вызывается нигде в патче (grep по 0033: `AfeyeFuncName`, `sfi->Name`, `GetFunctionName` — ноль совпадений). Поле `name` в func-def blob — это имя СКРИПТА (0033:674, `sc->name()`). На Rust-стороне `FuncDef.name` (`bctrace.rs:60-68`) заполняется из того же поля (`parse_func_def_blob`, `bctrace.rs:263`), выводится в отчёт как `"name": def.name` (`bctrace.rs:570`), а `src/bin/bcrec-dump.rs:24-31` печатает его в секции `--- functions ---` как имя функции. То есть **инструмент показывает URL скрипта под видом имени функции** для всех функций одного файла одинаково.
10. **Дополнительно, чего эталон не требует, но что есть**: аккумулятор — `GetAccumulatorUnchecked()` (0033:432), сырое слово в `Hdr.acc` (bcrec.h:53) + полное значение блоками `kTagAccStr`/`kTagAccStr16`/`kTagAccF64`/`kTagAccSmi` (0033:872-885); meta-blob с именами и сигнатурами всех байткодов и runtime-функций (`MetaBuilder`, bcrec.h:294-330, `AfeyeEmitMeta`); isolate-тег в `Hdr.line` для инструкций (`AfeyeIsoTag` = `(uintptr(isolate) >> 3) & 0xffffffff`, 0033:526-529); сплиттинг длинных записей через `EmitSplit` с `kFlagCont` (bcrec.h:332-360, `kSinkRecordCap = (1<<20) - 16`).
11. **Dedupe func-def**: `AfeyeSeenKey{func_id, arr->length()}` в `g_afeye_seen` (`unordered_set`, 0033:800-803) — func-def эмитится один раз на пару (func_id, длина байткода). Комментарий 0033:531-534 подчёркивает, что таблица unbounded и «never silently skips»; при повторной компиляции функции с тем же id func-def переэмитится только если изменилась длина массива байткода.
12. **Расхождение `SERIES.md` с кодом по лимитам.** `SERIES.md:85` утверждает: «Квоты: 50M инструкций на процесс (backstop), AFEYE_BC_CAP переопределяет». Проверено grep'ом по ВСЕМ патчам: ни `AFEYE_BC_CAP`, ни константы `50000000`/`50<<20`, ни какого-либо счётчика инструкций в 0033 НЕТ. Более того, сам патч в комментарии 0033:495-496 заявляет обратное: «No caps, no truncation, no dedupe table overflow paths. Every record is emitted in full». Единственный гейт 0033 — `AfeyeBcOff()` из `AFEYE_TRACE_BYTECODE` (0033:501-507, off при `'0'` первым символом), то есть вкл/выкл, а не квота. `SERIES.md:86` («НИКАКИХ ЛИМИТОВ») соответствует коду, `SERIES.md:85` — не соответствует.
13. **Следствие отсутствия квоты.** Единственный backstop при переполнении — ring на 8 MiB и drop-witness (0023). При `AF_JITLESS=1` на тяжёлой странице поток записей не ограничен ничем; потери будут видны только как `sink-drop` (kind 39), и они обесценивают dead-end'ы (см. раздел 0023).

**Вывод по пункту 2:** по месту хука — НЕ соответствует эталону (другой файл, другой механизм: конструктор `InterpreterAssembler` + `InlineShortStar` вместо `GENERATE_BYTECODE_HANDLER`). По покрытию — `[INFERENCE]` эквивалентно или лучше: `interpreter-generator.cc` генерирует обработчики, конструируя `InterpreterAssembler`, поэтому хук в конструкторе покрывает все обработчики; второй хук в `InlineShortStar` закрывает `Star0`–`Star15`, которые инлайнятся в предыдущий обработчик через `StarDispatchLookahead` и через конструктор не проходят (это же обоснование приведено в комментарии патча 0033:444-445 и в `SERIES.md:86`). По составу данных — соответствует по offset/опкоду/аргументам/входным регистрам/имени скрипта; НЕ соответствует по имени функции (его нет вообще) и по значению регистра-приёмника (только индекс).

### Пункт 3. Виртуализация таймингов

**Эталон:** `src/base/platform/time.cc` ИЛИ `Performance::now` в blink; формула `virtual_time += kBaseInstructionCost * instruction_count`.

**Реально в `patches/0034-v8-blink-virtual-clock.patch`** (85 строк, 3 файла):

| эталон | факт | где |
|---|---|---|
| `src/base/platform/time.cc` | **НЕ тронут** | список `diff --git` в 0034: `third_party/blink/renderer/core/timing/performance.cc`, `v8/src/objects/js-objects.cc`, + (из 0033) `v8/src/afeye/sink.cc`/`sink.h`. `time.cc` отсутствует |
| `Performance::now` в blink | **ЕСТЬ** | 0034:19-44, hunk `@@ -1373,6 +1380,25 @@ DOMHighResTimeStamp Performance::now() const` |
| `Date.now()` | **ЕСТЬ дополнительно** (эталон не требует) | `JSDate::CurrentTimeValue(Isolate*)`, 0034:60-82, hunk `@@ -5914,6 +5918,25 @@` |
| формула `virtual_time += cost * instruction_count` | **соответствует по сути, реализована как аккумулятор** | инкремент: `VclockTick(AfeyeVclockNsPerInstr())` на каждую инструкцию (0033:768-770); счётчик: `g_vclock_ns.fetch_add(ns, relaxed)` (0033:381-383); чтение: `afeye_vclock_ns()` (0033:377-379) |

Что сделано реально, по шагам:
1. **Счётчик** живёт в v8-sink'е: `std::atomic<uint64_t> g_vclock_ns{0}` (0033:375), `extern "C" uint64_t afeye_vclock_ns(void)` (0033:377-379), `void VclockTick(uint64_t ns)` (0033:381-383). Объявления добавлены в `v8/src/afeye/sink.h` (0033:404-410).
2. **Инкремент** — в `Runtime_AfeyeTraceBytecodeEntry`, то есть один тик на каждую исполненную байткод-инструкцию: `if (AfeyeVclockOn()) { v8::afeye::VclockTick(AfeyeVclockNsPerInstr()); }` (0033:768-770). Это соответствует эталонной формуле: `kBaseInstructionCost` = `AfeyeVclockNsPerInstr()`, `instruction_count` накапливается в `g_vclock_ns`.
3. **Шаг** — `AfeyeVclockNsPerInstr()` (0033:517-523): `getenv("AFEYE_VCLOCK_NS_PER_INSTR")`, `strtoull`, если результат `> 0` — он, иначе **дефолт 10 нс**.
4. **Гейт** — `AfeyeVclockOn()` из `getenv("AFEYE_VIRTUAL_CLOCK")` (упоминается в 0033:768 и в `SERIES.md:88`); в blink-части 0034 гейт продублирован локально: `static bool g_afeye_vclock = [](){ const char* v = ::getenv("AFEYE_VIRTUAL_CLOCK"); return v && *v && v[0] != '0'; }()` (0034:30-33). Полярность та же, что у `AFEYE_SINK`: **включено при любом значении, кроме начинающегося с `'0'`** (то есть по умолчанию ВЫКЛЮЧЕНО, в отличие от `AFEYE_TRACE_*`).
5. **`performance.now()`** (0034:34-41): `static double g_afeye_origin_ms` = `base::TimeTicks::Now().since_origin().InMillisecondsF()`, снимается один раз; возврат `g_afeye_origin_ms + (double)afeye_vclock_ns() / 1000000.0`. Вставка стоит ПОСЛЕ лог-блока 0012 и ДО штатного `return MonotonicTimeToDOMHighResTimeStamp(base::TimeTicks::Now());`.
6. **`Date.now()`** (0034:69-81): `static int64_t g_afeye_epoch_ms = V8::GetCurrentPlatform()->CurrentClockTimeMilliseconds()` (один раз); возврат `g_afeye_epoch_ms + (int64_t)(v8::afeye::afeye_vclock_ns() / 1000000ull)`. Стоит после `if (v8_flags.correctness_fuzzer_suppressions) return 4;`.
7. **Линковка blink → v8**: `extern "C" uint64_t afeye_vclock_ns(void);` объявлен в `performance.cc` (0034:15) под `#ifdef BLINK_AFEYE`. Комментарий 0034:10-14 объясняет: renderer-бинарник содержит и blink, и v8, поэтому символ линкуется напрямую, без mojom/IPC.

Чего не хватает:
1. `src/base/platform/time.cc` не тронут → **`base::TimeTicks::Now()` остаётся реальным**. Всё, что в Chrome читает время мимо `Performance::now`/`Date.now()` (внутренние таймауты, `MessagePump`, `base::Timer`, `TimeTicks` в net-стеке, `DOMTimer` через `base::TimeTicks`), видит настоящее время и расхождение с виртуальным.
2. **`Hdr`/записи sink'а не несут виртуальное время.** `ts_ns` в 16-байтном заголовке всегда `MonoNs()` = реальный `CLOCK_MONOTONIC` (blink `sink.cc:51-56`, `194`; net `afeye_sink.cc:45-50`, `184`; v8 — то же). Значение `g_vclock_ns` в записи НЕ пишется. Соответственно `ts` в `sem/*.jsonl` (`bctrace.rs:716`) — реальное время, не виртуальное.
3. **Счётчик глобальный на процесс, не на isolate.** `g_vclock_ns` — одна `std::atomic` на весь процесс (`v8/src/afeye/sink.cc`). `SERIES.md:89` это признаёт: «vclock глобальный на процесс, не на isolate — несколько вкладок делят счётчик». При нескольких isolate'ах (воркеры, несколько вкладок) время каждого течёт от суммарного числа инструкций всех.
4. **`NowNs()` не виртуализован** — то есть сами afeye-записи при включённом `AFEYE_VIRTUAL_CLOCK` имеют реальную метку времени, а страница видит виртуальную. Сопоставление «когда страница думала, что произошло событие» требует отдельного пересчёта, которого в коде нет.
5. **Гранулярность `Date.now()`** — 1 мс при шаге 10 нс/инструкцию = 100 000 инструкций на тик. `SERIES.md:89` это отмечает. Эталон гранулярности не оговаривает.

**Вывод по пункту 3:** соответствует наполовину. `Performance::now` виртуализован (0034:19-44), формула эквивалентна эталонной (`VclockTick(NsPerInstr)` на инструкцию, 0033:768-770), дополнительно закрыт `Date.now()` (0034:60-82). НЕ соответствует: `time.cc` не тронут, `base::TimeTicks` остаётся реальным, виртуальное время не попадает в записи sink'а, счётчик процесс-глобальный.

### Пункт 4. WebIDL/DOM-биндинги

**Эталон:** патч `src/bindings/core/v8/`, логировать конкретный геттер/сеттер интерфейса **с переданными аргументами** и **типом возвращаемого значения**.

**Реально:**

| эталон | факт | где |
|---|---|---|
| патч `src/bindings/core/v8/` | **НЕ СООТВЕТСТВУЕТ**: каталог не тронут | 0008 и 0024 содержат ровно один `diff --git`: `third_party/blink/renderer/platform/bindings/idl_member_installer.cc` (0008:1, 0024:1). 0019 трогает 7 файлов, ни один не в `bindings/core/v8/` |
| `V8DOMConfiguration` | **НЕ СООТВЕТСТВУЕТ**: ноль совпадений во всех патчах | — |
| логировать геттер/сеттер интерфейса | **соответствует** | `CreateFunctionTemplate<kind>` с `if constexpr (kind == v8::ExceptionContext::kAttributeGet) afeye_access = "get"; … kAttributeSet → "set"; else "call"` (0008, hunk `@@ -134,12 +198,33 @@`); строка `"dom <Interface>.<get\|set\|call> <property>"` через `snprintf` в `AfeyeWrapDomApi` |
| имя интерфейса | **соответствует** | `interface_name_ptr` передаётся в 6 вызовов `CreateFunctionTemplate`/`CreateFunction` из `InstallAttribute`/`InstallOperation` (0008, hunks `@@ -233`, `@@ -293`, `@@ -347`, `@@ -398`) |
| **аргументы** | **НЕ СООТВЕТСТВУЕТ: аргументы НЕ логируются** | `AfeyeDomApiThunk` обращается только к `info.Data()` и `info.GetReturnValue()` (0024, hunk `@@ -40,14 +81,26 @@`). `info.Length()` / `info[i]` не вызываются нигде в патче. Единственная информация об аргументах приходит косвенно — из kind 25/16 (например `canvas/get-image-data rect=…` в 0007) |
| **тип возвращаемого значения** | **НЕ СООТВЕТСТВУЕТ: типа нет, есть только приведённое значение** | `AfeyeCaptureValue` (0024, hunk `@@ -32,6 +34,45 @@`) возвращает СТРОКУ; имя JS-типа в запись не попадает. Ветки: `"undefined"`, `"null"`, `"1"`/`"0"`, `"%.17g"`, UTF-8-строка с заменой байтов `<0x20 \|\| >=0x7f` на `'?'`, `"[array len=N]"`, `"[object]"`. Для объекта отличить `HTMLCanvasElement` от `Object` невозможно — обе дадут `[object]` |
| значение | **соответствует (частично)**: только для undefined/null/boolean/number/string; array даёт лишь длину; object — заглушку | 0024, `AfeyeCaptureValue`, буфер 160 байт, в запись идёт `val=%.150s` |
| покрытие всех членов IDL | **соответствует** | хук в `CreateFunctionTemplate`/`CreateFunction` покрывает все атрибуты и операции всех интерфейсов, устанавливаемые через `idl_member_installer` |

Что эмитит каждый патч:
- **0008**: `EmitStr(kDomApi=29, …, "dom <Interface>.<accessor> <property>")`. Кап 8 000 000 (`g_afeye_api_calls`), таблица на 65536 ячеек.
- **0024**: достраивает значение — `EmitStr(kDomApi=29, …, "dom <Interface>.<accessor> <property> val=<до 150 символов>")`. Порядок изменён: сначала `cell->orig(info)`, потом чтение `GetReturnValue()`. Гейт `AFEYE_TRACE_DOM_VALUES=0` возвращает поведение 0008 (без ` val=`).
- **0019**: kind 29 НЕ трогает вообще. Эмитит только kind 16 (`fingerprint`) с собственными C++-хуками в 7 файлах (см. таблицу в разделе 0019). Это параллельный, НЕ связанный с IDL-thunk'ом механизм ручной инструментировки конкретных методов. Rust-сторона 0019 не читает (ноль совпадений с его тегами в `src/`).

Сопутствующие расхождения:
1. **Fast-call ABI.** При выдаче afeye-ячейки `callback` подменяется на `&AfeyeDomApiThunk`, но `v8_cfunction_table_data`/`v8_cfunction_table_size` продолжают передаваться в `NewWithCFunctionOverloads` (0008, hunk `@@ -151,7 +236,7 @@`). CFunction-таблица описывает оригинальную функцию. `[INFERENCE]` — V8 может выбрать fast-path в обход thunk'а; патч этого не обрабатывает и не тестирует.
2. **Мёртвый include**: 0024 добавляет `#include "v8/include/v8-container.h"` (0024:12), символы из него в патче не используются.
3. **Молчаливая потеря членов**: при исчерпании 65536 ячеек `AfeyeWrapDomApi` возвращает пустой `Local`, хук не ставится, счётчика/репорта нет (0008, ветка `return v8::Local<v8::Value>();` в конце функции).
4. **UTF-8 → `'?'`**: `AfeyeCaptureValue` заменяет все байты вне `[0x20, 0x7f)` на `'?'` (0024, цикл санитизации). Значения `navigator.languages`, `document.title` с не-ASCII теряют содержимое.
5. **Кап 8 000 000 не репортится**: после исчерпания записи просто прекращаются; в отличие от ring-drop'ов (kind 39, патч 0023) свидетельств в отчёте нет.

**Вывод по пункту 4:** НЕ соответствует по файлу (`platform/bindings/idl_member_installer.cc` вместо `bindings/core/v8/`), НЕ соответствует по аргументам (отсутствуют полностью), НЕ соответствует по типу возвращаемого значения (есть только строковое представление значения, тип не фиксируется). Соответствует по покрытию (все IDL-геттеры/сеттеры/методы через одну точку) и по идентификации (`<Interface>.<accessor> <property>`).

### Пункт 5. Финальный формат лога

**Эталон требует для каждой операции:** `timestamp_virtual`, `script_id`, `function_name`, `bytecode_op`, `target_property`, `arguments_hash`, формат JSONL/protobuf.

**Что реально пишет 0033** — заголовок `bcrec::Hdr`, 72 байта, `static_assert(sizeof(Hdr) == 72)` (bcrec.h:57), little-endian, без паддинга (bcrec.h:35-56):

| поле | размер | инструкция | func-def | meta |
|---|---|---|---|---|
| `opcode` | u8 | опкод после префикса | `0xff` (`kOpFuncDef`) | `0xfe` (`kOpMeta`) |
| `scale` | u8 | raw `OperandScale` (1/2/4) | — | — |
| `n_payload` | u8 | число payload-блоков (насыщается на 255) | — | — |
| `flags` | u8 | `kFlagCont`/`kFlagAccPayload` | `kFlagFuncDef` | `kFlagCont` |
| `offset` | u32 | логический bytecode-offset (одинаков на всех частях — ключ склейки) | позиция части в blob'е | позиция части |
| `func_id` | u32 | FNV-1a от (script_id, literal_id, start_pos, isolate_tag) | то же | 0 |
| `line` | u32 | **isolate-тег** (не номер строки!) | номер строки начала функции | 0 |
| `acc` | u64 | сырое tagged-слово аккумулятора | полная длина blob'а | полная длина blob'а |
| `regs[6]` | 6×u64 | сырые tagged-слова первых шести входных регистров | — | — |

Payload-блоки: `[u8 tag][u32 len][len bytes]`, `kBlockPrefixSize = 5` (bcrec.h:85). Теги (bcrec.h:67-83): 0 `kTagAccStr`, 1 `kTagAccF64`, 2 `kTagAccSmi`, 3 `kTagReg`, 4 `kTagRegStr`, 5 `kTagRegF64`, 6 `kTagRegSmi`, 7 `kTagOperand`, 8 `kTagCpStr`, 9 `kTagCpF64`, 10 `kTagCpRaw`, 11 `kTagAccStr16`, 12 `kTagRegStr16`. Декод строго по тегу, «тип НИКОГДА не выводится из длины» (bcrec.h:65-66).

Формат sink-записи: kind **40** (`bcrec::kKind = 40`, bcrec.h:33; `KINDS[40] = "bytecode-trace"`, `collect.rs:56`), ts = реальный `CLOCK_MONOTONIC`. Сплиттинг: `kSinkRecordCap = (1<<20) - 16` (bcrec.h:89), `EmitSplit` ставит `kFlagCont` на все части кроме последней (bcrec.h:332-360).

**Что реально парсит `src/bctrace.rs` в `sem/*.jsonl`** (строки 711-749): файл на функцию — `sem/<func_id:08x>.jsonl` (строка 712). Поля строки:
- `"ts": r.ts` (716)
- `"off": r.offset` (717)
- `"op": m.name` (718) — имя байткода из meta-blob'а (`OpMeta.name`, `bctrace.rs:44-48`)
- `"args": [...]` (720-722) — разрешённые значения операндов
- `"acc": a` (723-725) — аккумулятор на входе
- `"res": res` (726-728) — результат: для опкодов с `acc_use & 2 != 0` берётся `acc` СЛЕДУЮЩЕЙ записи того же `(pid, iso)` (`bctrace.rs:668-674`, `592-595`)
- `"regs": [{"reg":i,"word":w} | {"reg":i,"v":…}]` (730-748)

Отдельный отчёт на функцию — `<func_id:08x>.json` (`bctrace.rs:568-588`): `func_id`, `name`, `line`, `frame_size`, `param_count`, `bc_len`, `instructions`, `blocks`, `executions`, `live_blocks`, `dead_blocks`, `dead_ranges`, `first_ts`.

**Таблица соответствия:**

| поле эталона | есть ли реально | где именно | что делать, если нет |
|---|---|---|---|
| `timestamp_virtual` | **НЕТ** | `bctrace.rs:716` пишет `"ts": r.ts`, где `r.ts` (`InstrRec.ts`, `bctrace.rs:86`) — ts из 16-байтного заголовка sink'а = `MonoNs()` = реальный `CLOCK_MONOTONIC` (`v8/src/afeye/sink.cc:51-56`). Виртуальный счётчик `g_vclock_ns` (0033:375) в запись НЕ пишется: `Hdr` (bcrec.h:36-56) поля под него не имеет | добавить `uint64_t vclock` в `Hdr` (расширив его с 72 байт и поправив `static_assert` на bcrec.h:57) ИЛИ отдельный payload-блок с новым тегом в `PayloadTag` (bcrec.h:67-83); заполнять из `afeye_vclock_ns()` в `Runtime_AfeyeTraceBytecodeEntry` (0033:750); читать в `InstrRec` и писать в `sem`-строку |
| `script_id` | **НЕТ как поле** | читается в `AfeyeEmitFuncDef` (`int32_t script_id = -1; … script_id = sc->id();`, 0033:668/673) и в `Runtime_AfeyeTraceBytecodeEntry` (0033:795-796), но используется ТОЛЬКО как вход FNV-1a в `MakeFuncId(script_id, literal_id, start_pos, isolate_tag)` (bcrec.h:120-131). В func-def blob'е его нет: раскладка `[u32 bc_len][u32 name_len][u32 cp_bytes][i32 frame_size][u32 param_count][bc][name][cp]` (bcrec.h:269-279). `FuncDef` в Rust (`bctrace.rs:60-68`) поля `script_id` не имеет | добавить `int32 script_id` в head func-def blob'а (`FuncDefBuilder::Build`, bcrec.h:257-280, увеличить `head` с 24 до 28) + поле в `FuncDef` (`bctrace.rs:60-68`) + парсинг в `parse_func_def_blob` (`bctrace.rs:244-290`) + вывод в отчёт (`bctrace.rs:568-582`) |
| `function_name` | **НЕТ — и это активная подмена** | `AfeyeEmitFuncDef` берёт `sc->name()`, то есть имя **СКРИПТА** (0033:674-677, комментарий «script name, full bytes» на строке 664). `sfi->Name()` не вызывается нигде в патче. Rust-сторона кладёт это в `FuncDef.name` (`bctrace.rs:65`, заполняется в `parse_func_def_blob`, `bctrace.rs:263`), выводит как `"name": def.name` (`bctrace.rs:570`), а `src/bin/bcrec-dump.rs:28` печатает его в списке `--- functions ---` как имя функции | в `AfeyeEmitFuncDef` дополнительно прочитать `sfi->Name()` (или `sfi->NameOrInferredName()`) под `no_gc` через `AfeyeStringBytes` и передать в `FuncDefBuilder::Build` отдельным полем; расширить blob и `FuncDef`; до тех пор поле `"name"` в отчётах следует переименовать в `"script"`, чтобы не вводить в заблуждение |
| `bytecode_op` | **ЕСТЬ** | `Hdr.opcode` (bcrec.h:37) ← `op_byte = *pc` (0033:786) ← `ib.Begin(op_byte, …)` (0033:807). В Rust: `InstrRec.opcode` (`bctrace.rs:90`) → имя из meta-blob'а (`OpMeta.name`, `bctrace.rs:45`) → `"op": m.name` (`bctrace.rs:718`). Дополнительно есть `scale` (bcrec.h:40, `InstrRec.scale`, `bctrace.rs:91`) | — |
| `target_property` | **ЕСТЬ косвенно, не как отдельное поле** | в C++ — индекс операнда: `ib.Operand(i, decoded)` → блок `kTagOperand` (bcrec.h:75-77, 0033:858-866). Содержимое пула констант — в func-def blob'е (`kTagCpStr`/`kTagCpStr16`/`kTagCpF64`/`kTagCpRaw`, 0033:687-718). В Rust разрешение индекса в имя: `bctrace.rs:637-663` (`cp_json(&d.cp, *v as usize)`) для явного списка опкодов (`GetNamedProperty`, `SetNamedProperty`, `LdaGlobal`, `CallProperty*`, …); результат попадает в `"args"` (`bctrace.rs:720-722`) и в агрегат `api_calls` с ключами `"prop <имя>"` / `"call <имя>"` / `"global <имя>"` / `"runtime <имя>"` (`bctrace.rs:676-709`), который выводится в summary как `"api_calls": [{"what","times","values"}]` (`bctrace.rs:752-772`) | вынести в отдельное поле `sem`-строки (например `"target": key`), сейчас имя свойства растворено внутри `"args"` и доступно только в агрегате на функцию |
| `arguments_hash` | **НЕТ — хеширования аргументов нет вообще** | единственная хеш-функция в `bcrec.h` — `MakeFuncId` (строки 120-131), FNV-1a по 16 байтам ИДЕНТИФИКАТОРА функции (script_id, literal_id, start_pos, isolate_tag), не по аргументам. Вместо хеша эмитятся ПОЛНЫЕ ЗНАЧЕНИЯ: `kTagOperand` (декодированные операнды), `kTagReg`/`kTagRegStr`/`kTagRegStr16`/`kTagRegF64`/`kTagRegSmi` (сырые слова и значения регистров, 0033:837-856), `kTagAccStr`/`kTagAccStr16`/`kTagAccF64`/`kTagAccSmi` (аккумулятор, 0033:872-885) | не требуется: реализация СТРОГО богаче эталона (полные значения вместо хеша). Если хеш нужен для компактности — считать на Rust-стороне из уже имеющихся `args`/`regs` при записи `sem`-строки (`bctrace.rs:715-749`), C++-патч менять не нужно |
| формат JSONL | **ЕСТЬ** | `sem/<func_id:08x>.jsonl`, по одной JSON-строке на инструкцию (`writeln!(f, "{}", line)`, `bctrace.rs:749`); плюс `<func_id:08x>.json` — pretty-отчёт на функцию (`bctrace.rs:583-588`) и `summary` (`bctrace.rs:763-775`) | — |
| формат protobuf | **НЕТ** | — | не требуется: JSONL покрывает требование («JSONL / protobuf») |

Дополнительно к эталону реализовано (эталон не требует):
- **`res` — результат инструкции как dataflow движка**: для опкодов, пишущих в аккумулятор (`acc_use & 2 != 0`), берётся `acc` следующей записи того же `(pid, iso)` (`bctrace.rs:668-674`). Правило зафиксировано в `bctrace.rs:773`: «Result of a write-acc instruction = acc of the next same-(pid,iso) record».
- **`meta`-blob** (`MetaBuilder`, bcrec.h:294-330; `AfeyeEmitMeta`, 0033:594-656): имена всех байткодов, число операндов, флаги (bit0 jump, bit1 returns, bit2 calls, bits 3-4 subtype перехода, bit5 conditional — `bctrace.rs:47`), `acc_use` (1 читает, 2 пишет, 4 clobber, 8 short-star — `bctrace.rs:48`), для каждого из трёх масштабов — `total_size` и по операндам `(operand_type, operand_offset)`, плюс таблица имён runtime-функций. Семантика переходов берётся ИЗ ДВИЖКА, а не угадывается (`SERIES.md:81`).
- **func-def blob**: полный массив байткода функции (`bc_len` байт), что позволяет на Rust-стороне делать статический обход и вычислять мёртвые блоки: `bctrace.rs:531-590`, «dead = basic block whose offsets NEVER appear in the executed stream» (`bctrace.rs:773`). Выход — `dead_blocks`/`live_blocks`/`dead_bytes`/`live_bytes`/`dead_ranges`.
- **Склейка частей**: `kFlagCont` (bcrec.h:60) + карта `parts: BTreeMap<(opcode, func_id), BTreeMap<u32, Vec<u8>>>` (`bctrace.rs:433-500`).
- **Отсутствие лимитов**: в `Runtime_AfeyeTraceBytecodeEntry` нет ни счётчика записей, ни усечения строк (0033:750-894; `SERIES.md:86`). Единственный dedupe — `g_afeye_seen` по `(func_id, bc_len)` для func-def (0033:800-803).

**Вывод по пункту 5:** из шести полей эталона реально присутствуют два (`bytecode_op`, `target_property` — последнее в разрешённом виде внутри `args`), одно присутствует в более сильной форме (`arguments_hash` → полные значения), три ОТСУТСТВУЮТ (`timestamp_virtual`, `script_id`, `function_name`). Причём `function_name` не просто отсутствует — под его именем в отчётах выводится имя скрипта (`bctrace.rs:570`, `bcrec-dump.rs:28`).
