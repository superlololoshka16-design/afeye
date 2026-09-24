# Бинарники, тесты, инструменты, сборка и CI

## src/bin/afeye-collect.rs — отдельный демон-коллектор: бесконечно сканирует raw-каталог sink'а и материализует timeline

### fn main()  (строки 3-9)
- назначение: standalone-обёртка над `afeye::collect::run_standalone`.
- что внутри: читает env `AF_RAW_DIR` (default `afeye::collect::DEFAULT_RAW_DIR` = `/tmp/afeye-raw`, src/collect.rs:11) и `AF_COLLECT_OUT` (default `.`), присоединяет к нему `collect`; вызывает `run_standalone(raw, out)`.
- связи: `run_standalone` (src/collect.rs:505-517) — цикл `scan_once` каждую 1000 мс + печать stats в stderr. Тот же сканер, который в основном бинарнике `afeye` запускается потоком `afeye-collect` через `Collector::spawn` (src/collect.rs:415-420), где out = `<stage>/collect`.
- env: `AF_RAW_DIR`, `AF_COLLECT_OUT`. Аргументов CLI нет.

## src/bin/bcrec-dump.rs — человекочитаемый дамп отчёта bytecode-trace (0033)

### fn main()  (строки 3-39)
- назначение: прогнать `bctrace::run` по готовому collect-каталогу и напечатать сводку.
- что внутри: argv[1] → каталог (default `/tmp/proof-collect/collect`); `afeye::bctrace::run(&dir)`; при Ok печатает одну строку `instructions= funcs= live_blocks= dead_blocks= live_bytes= dead_bytes=` из `bctrace::Stats` (src/bctrace.rs:99-107), затем читает и парсит `<dir>/filtered/bctrace.json` и печатает две секции: `--- api_calls ---` (поля `what`, `times`, `values` каждого элемента массива `api_calls`) и `--- functions ---` (поля `name`, `line`, `bc_len`, `instructions`, `executions`, `live_blocks`, `dead_blocks`, `dead_ranges` каждого элемента `functions`). При Err — `bctrace failed: {e}` в stderr и `exit(1)`.
- связи:消费 `bctrace::run` (src/bctrace.rs:390), который сам пишет `filtered/bctrace.json`, `filtered/bctrace/<fid:08x>.json` и `filtered/bctrace/sem/<fid:08x>.jsonl`.
- аргументы: один позиционный (каталог collect). env не использует.

## src/bin/jscheck.rs — синтаксическая проверка инъектируемого JS из src/inject.rs

### fn extract_src(inject_rs: &str) -> String  (строки 4-8)
- назначение: вырезать тело raw-строки `r#"..."#` из текста inject.rs.
- что внутри: ищет первое вхождение `r#"` (+3), затем первое `"#;` после него; возвращает срез между ними. Оба `unwrap()` — паника, если inject.rs не содержит ровно такой конструкции.
- связи: единственный потребитель — main ниже. Хрупко: завязан на то, что `const SRC: &str = r#"(function(){` (src/inject.rs:9) остаётся первым raw-литералом в файле и что закрывающая последовательность именно `"#;`.

### fn main()  (строки 10-24)
- назначение: доказать, что JS-харнесс (v12.1, маркер `AFXH`) синтаксически валиден, без запуска браузера.
- что внутри: читает `<manifest>/src/inject.rs`; `extract_src`; подставляет плейсхолдеры: `__B__`→`_k42z`, `__G__`→`1` (глобальный replace, в отличие от `inject::source`, который делает `replacen(.., 2)` — src/inject.rs:1-7); пишет `/tmp/afeye_inject_check.js` (`std::env::temp_dir()`); запускает `node --check <tmp>`; успех → `SYNTAX OK (<n> bytes)`, провал → stderr node'а и `exit(1)`.
- связи: проверяет ровно тот текст, который `capture.rs:189` инжектит через `AddScriptToEvaluateOnNewDocument(inject::source(binding, gl_spoof))`. Требует `node` в PATH — без него `unwrap()` на spawn паникует.
- env: нет (только `CARGO_MANIFEST_DIR` на компиляции). Аргументов нет.

## tests/bcrec_roundtrip.rs — байт-точный round-trip wire-формата 0033: C++ из патча → g++ → запись → production collect → production bctrace

### fn extract_new_files(patch: &Path, out_root: &Path)  (строки 18-57)
- назначение: достать из unified-diff патча ВСЕ новые файлы (ханки `@@ -0,0`).
- что внутри: построчный парсер. `diff --git ` → flush предыдущего + 4-й токен заголовка как путь (`b/...`); `@@ -0,0` → начало ханка нового файла; строки с `+` накапливаются в `body` (префикс `+` снимается, `\n` сохраняется через `split_inclusive`); строка с пробелом/`-` внутри ханка → flush. flush: если путь известен и body непустой — `create_dir_all(parent)` + `write(out_root/path.trim_start_matches("b/"), body)`. Идентичен одноимённой функции в sink_roundtrip.rs:13-54 (дублирование, не общий модуль).
- связи: зовётся из теста для патчей `patches/0001-v8-sink.patch` и `patches/0033-v8-ignition-bytecode-trace.patch`.

### fn have_gxx() -> bool  (строки 59-65)
- `g++ --version`, успех → true. Без g++ тест скипается (return, не failure) — строки 69-72.

### #[test] fn bcrec_wire_roundtrip_is_byte_exact()  (строки 67-179)
- что доказывает (конкретно, по шагам):
  1. tempdir; извлечение из 0001 (даёт `v8/src/afeye/sink.h`, `sink.cc`) и 0033 (даёт `v8/src/afeye/bcrec.h`); assert'ы существования обоих (строки 81-84).
  2. компиляция g++: `-std=c++17 -O2 -DV8_AFEYE -I<src>/v8 <src>/v8/src/afeye/sink.cc tools/bcrec_main.cc -o bcrec_test -lpthread` (строки 86-101). То есть компилируется ТОТ sink.cc, который лежит в патче, а не копия из дерева.
  3. запуск эмиттера с `AFEYE_SINK=1`, `AFEYE_RAW_DIR=<tmp>/raw` (строки 109-116); sleep 300 мс на flush drain-потока (119); assert ≥1 файла `*.rec` (120-125).
  4. production-коллектор: `scan_once(&raw, &collect_dir, &mut ScanState, &mut Stats)` (131); assert `stats.corrupt == 0` (132); assert `stats.per["v8/bytecode-trace"] == 5` — meta + func-def + 3 инструкции (133-138).
  5. production-декодер: `bctrace::run(&collect_dir)` (141); assert `funcs==1`, `instructions==3` (142-143); `dead_blocks==1`, `dead_bytes==2` — недостижимый хвост `LdaConstant` на offsets [4,6) (144-147).
  6. семантический поток: из `filtered/bctrace.json` берётся `functions[0].func_id`, читается `filtered/bctrace/sem/{fid:08x}.jsonl` (150-164); assert 3 строки; строка 0: `op=="LdaConstant"`, `args[0]=="secret-key"` (операнд cp idx 0 разрешён через пул констант), `acc==7` (Smi 7 на входе), `res=="Mozilla/5.0"` (результат = acc СЛЕДУЮЩЕЙ записи того же pid+isolate) (165-171); строка 1: `op=="Star0"`, в `regs[]` есть `v=="Mozilla/5.0"` (172-175); строка 2: `op=="Return"`, ключ `res` отсутствует (терминатор читает acc, не пишет) (176-178).
- связи: `afeye::collect::{scan_once, ScanState, Stats}` (src/collect.rs), `afeye::bctrace::run` (src/bctrace.rs:390), `tools/bcrec_main.cc`, патчи 0001+0033, `tempfile` (dev-dep), `serde_json`. Внешние: `g++`.
- green здесь = C++-энкодер из патча и Rust-декодер из src согласованы байт-в-байт, без сборки chromium.

## tests/sink_roundtrip.rs — байт-точный round-trip sink-слоёв: C++ из патчей 0001/0005/0011 → g++ (3 бина) → запись → production collect → assert'ы по байтам

### fn extract_new_files / fn have_gxx  (строки 13-54 / 56-62)
- идентичны версиям из bcrec_roundtrip.rs (см. выше); комментарий строк 18-19 поясняет выбор только `@@ -0,0` ханков.

### #[test] fn sink_patch_roundtrip_is_byte_exact()  (строки 64-266)
- что доказывает, по шагам:
  1. извлечение из `0001-v8-sink.patch`, `0005-blink-sink.patch`, `0011-net-wire.patch` (74-80); assert'ы что на диске появились `v8/src/afeye/sink.cc`, `third_party/blink/renderer/platform/afeye/sink.cc`, `services/network/afeye_sink.cc` (81-86).
  2. три компиляции g++ `-std=c++17 -O2` (92-137): v8_test = `-DV8_AFEYE -I<src>/v8 sink.cc + tools/sink_test_main.cc`; blink_test = `-DBLINK_AFEYE -I<src> blink sink.cc + tools/blink_smoke_main.cc`; net_test = `-DNET_AFEYE -I<src> net sink.cc + tools/net_smoke_main.cc`. Два include-корня потому что v8-sink включает по v8-корню (`src/afeye/sink.h`), blink/net — по chromium-корню (комментарий 89-90).
  3. env-off (139-146): `v8_test off` с удалённым `AFEYE_SINK` → exit 0 и stdout ровно `enabled=0`. Доказывает: без env патченный sink молчит (Enabled()==false, main возвращает 0).
  4. env-on батарея (148-163): все три бина с `AFEYE_SINK=1 AFEYE_RAW_DIR=<tmp>/afeye-raw`, каждый должен выйти 0.
  5. drain-poll (165-181): цикл `scan_once` каждые 300 мс, дедлайн 15 с, пока в `collect/index.jsonl` не появится `BATTERY-END`; иначе assert-провал со stats.
  6. точные счётчики по `"k":"<kind>"` в index.jsonl (183-204): `sink-hello==3` (по одному на слой), `script-source==3` (EmitStr + EmitTwoStr + truncated), `wasm-module==1`, `microtask-enqueue==1`, `atomics==2` (probe + BATTERY-END; запись нулевой длины `Emit(kAtomics,…,"x",0)` дропается — sink.cc EmitFlags early-return на len==0), `sab-backing==1`, `bytecode-entry==4000` (8 потоков × 500), `timer==1`, `crypto-op==1`, `message==1` (blink smoke), `net-request==2` (method/url + req-body span).
  7. байт-точные payload'ы (206-225): `console.log(1);` → ровно эти 15 байт; `http://x/dd.js` → `http://x/dd.js\0var a=1;` (EmitTwoStr = a + \0 + b); `sab-backing` → `span-tag\0` + 100 байт `(i*7+3) as u8` (EmitSpan = tag + \0 + bytes); `wasm-module` → 4096 байт `(i*7+3) as u8`; `BATTERY-END` → ровно 11 байт.
  8. truncation (227-235): находит строку index с `"k":"script-source"` и `"f":1` (флаг truncation); payload обязан быть `(1<<20)-16` байт, все `b'B'` — вход 2 МиБ урезан до `kMaxRecord-16` с флагом 1 (sink.cc EmitFlags: `len > kMaxRecord-16 → len = kMaxRecord-16; flags |= 1`).
  9. storm integrity (237-254): каждый `bytecode-entry` payload = 12 байт `[u32 tid][u32 i][u32 tag]` LE; assert `tag==2`, `i<500`; BTreeMap tid→count: ровно 8 tid'ов, у каждого ровно 500 записей — ни одна (tid,i)-пара не потеряна в ring-буфере и файловом drain'е.
  10. финальный `stats.json` (256-261): `corrupt==0` (ни одной рваной записи на файловом пути), `truncated==1` (ровно одна — 2 МиБ скрипт).
- связи: `afeye::collect::{scan_once, ScanState, Stats}`, `tools/sink_test_main.cc`, `tools/blink_smoke_main.cc`, `tools/net_smoke_main.cc`, патчи 0001/0005/0011, `tempfile`. Внешние: `g++`.
- green здесь = байты, лежащие в патчах, компилируются, работают и производят ровно тот timeline, который читает production-коллектор.

Примечание: тест, требующий `node`, находится не в tests/, а в src/relay.rs:261-276 (`wrapper_is_valid_js`, mod tests): пишет `/tmp/afeye_relay_check.js` и гоняет `node --check`; без node — паника на `.unwrap()` spawn'а. Второй тест relay (`parse_raw_and_api`, строки 247-259) node не требует.

## tools/sink_test_main.cc — батарея для v8-слоя sink (компилируется в sink_roundtrip)

### static void storm(int tid)  (строки 13-19)
- 500 итераций: `uint32_t tuple[3] = {tid, i, 2}` → `Emit(kBytecodeEntry, NowNs(), tuple, 12)`. Источник 4000 записей и 12-байтных payload'ов, которые проверяет тест.

### int main(int argc, char** argv)  (строки 21-51)
- ветка `argv[1]=="off"` (22-26): печатает `enabled=%d` и возвращает `on ? 1 : 0` — тест гоняет её БЕЗ env и ждёт `enabled=0`/exit 0.
- без sink (27-30): stderr + return 2.
- батарея (31-46), порядок важен для счётчиков теста:
  - `EmitStr(kScriptSource, "console.log(1);")`;
  - `EmitTwoStr(kScriptSource, "http://x/dd.js", "var a=1;")`;
  - `Emit(kWasmModule, wasm[4096])`, где `wasm[i] = i*7+3` (static, строки 33-35);
  - `Emit(kMicrotaskEnqueue, uint64_t[2]{5,42})` (36-37);
  - `EmitStr(kAtomics, "atomics.wait probe")` (38);
  - `EmitSpan(kSabBacking, "span-tag", wasm, 100)` (39);
  - `Emit(kAtomics, "x", 0)` — нулевая длина, sink обязан дропнуть (40);
  - `EmitStr(kScriptSource, 2МиБ из 'B')` — путь truncation (41-42);
  - 8 потоков `storm(t)`, join (43-45);
  - `EmitStr(kAtomics, "BATTERY-END")` — маркер конца для drain-poll теста (46).
- `Flush(5000)`; stdout `done dropped=%llu flushed=%d` из `SinkDropped()` (47-49); return 0.
- связи: API из `v8/src/afeye/sink.h` (из патча 0001): `Enabled/NowNs/Emit/EmitStr/EmitTwoStr/EmitSpan/Flush/SinkDropped`, константы kind `kScriptSource=1, kBytecodeEntry=2, kWasmModule=3, kMicrotaskEnqueue=6, kAtomics=9, kSabBacking=10`.

## tools/blink_smoke_main.cc — дымовой прогон blink-слоя sink

### int main()  (строки 6-21)
- без `blink::afeye::Enabled()` → stderr + return 2.
- эмитит ровно 3 записи: `EmitStr(kTimer, "blink-smoke")`; `EmitSpan(kCryptoOp, "smoke", "abcdef", 6)`; `EmitTwoStr(kMessage, "bc-post", "{\"obj\":true}")`. Печатает `blink done dropped=%llu`; return 0. `Flush` НЕ вызывает — тест полагается на atexit-хук `Flush(500)` (sink InitOnce, патч 0001) и 15-с drain-poll.
- связи: `third_party/blink/renderer/platform/afeye/sink.h` из патча 0005; kind'ы `kCryptoOp=11, kTimer=12, kMessage=14`. Комментарий строки 1 устарел: говорит «0006-blink-sink.patch», реально тест берёт 0005.

## tools/net_smoke_main.cc — дымовой прогон network-слоя sink

### int main()  (строки 6-22)
- без `network::afeye::Enabled()` → return 2.
- 2 записи kind `kNetReq=17`: `EmitTwoStr(kNetReq, "POST", "https://tlx.antifraud.example/collect")` → payload `POST\0https://tlx.antifraud.example/collect`; `EmitSpan(kNetReq, "req-body", "device_id=abc&signals=%7Bx%7D", 29)` → payload `req-body\0device_id=abc&signals=%7Bx%7D`. Печатает `net done dropped=%llu`.
- связи: `services/network/afeye_sink.h` из патча 0011. Комментарий строки 1 говорит «0011-network-wire.patch», фактическое имя файла — `0011-net-wire.patch` (расхождение только в комментарии).

## tools/bcrec_main.cc — синтетический эмиттер bytecode-trace (компилируется в bcrec_roundtrip)

### static void emit(const Hdr& h, const uint8_t* pl, size_t n)  (строки 21-27)
- склеивает `Hdr`(72Б)+payload в thread_local буфер и зовёт sink-`Emit(kKind=40, NowNs(), buf, size)` — та же функция, которую runtime-хук 0033 зовёт через `AfeyeEmit`.

### int main()  (строки 29-126)
- без sink → return 2 (30-33).
- meta (35-58): `MetaBuilder mb; mb.Begin(3, -1)` — 3 опкода, `reg_file_start_offset=-1` (операнд r0); опкод 0 `LdaConstant` (1 операнд, flags=0, acc_use=2 «пишет acc») + 3 пары Scale/Operand: `Scale(2),Operand(8,1)`, `Scale(3),Operand(8,1)`, `Scale(5),Operand(8,1)` — тип операнда 8 (cp-индекс), смещение 1; опкод 1 `Star0` (0 операндов, acc_use=1 «читает acc»), 3×`Scale(1)`; опкод 2 `Return` (flags=2 терминатор, acc_use=1), 3×`Scale(1)`; `RuntimeNames(1)`, `RuntimeName("ArrayConcat")`. Отправка: `Hdr{opcode=kOpMeta(0xfe), acc=mb.size()}` → `EmitSplit(h, data, size, true, emit)`. Коммент строк 35-36: таблицы зеркалят раскладку реального `AfeyeEmitMeta` байт-в-байт.
- func-def (60-86): байткод `bc[] = {0x00,0x00, 0x01, 0x02, 0x00,0x00}` — offset 0: `LdaConstant cp0` (2Б), offset 2: `Star0` (1Б), offset 3: `Return` (1Б), offset 4: `LdaConstant cp0` (2Б) — НИКОГДА не исполняется → мёртвый блок [4,6). `FuncDefBuilder fb; cp[0] = {tag=kCpTagStr(8), data="secret-key", len=10}`; `fb.Build(bc, 6, "translit.js", 11, frame_size=4, param_count=1, cp, 1)`; `fid = MakeFuncId(script_id=7, literal_id=0, start_pos=0, isolate_tag=0x1234)` (FNV-1a по 16 байтам, патч 0033:120-135). Отправка: `Hdr{opcode=kOpFuncDef(0xff), flags=kFlagFuncDef(1), func_id=fid, line=10, acc=fb.size()}` → `EmitSplit(…, true, emit)`.
- instruction rec1 (88-97): `InstrBuilder.Begin(opcode=0x00, scale=1, offset=0, fid, iso=0x1234, acc_word=0x0e)` — 0x0e = tagged Smi 7; `Operand(0, 0)` (cp-индекс 0); `AccSmi(7)`; `FinishHdr()`; `EmitSplit(…, false, emit)`.
- instruction rec2 (98-111): `Begin(0x01, scale=1, offset=2, fid, 0x1234, acc_word=0xbeef)`; `RegStr(0, "Mozilla/5.0", 11, utf16=false)`; `Reg(0, 0xbeef)`; `AccStr("Mozilla/5.0", 11, false)` — acc на входе = РЕЗУЛЬТАТ предыдущего LdaConstant (dataflow по «acc следующей записи»).
- instruction rec3 (112-121): `Begin(0x02, scale=1, offset=3, fid, 0x1234, 0xbeef)`; только `AccStr("Mozilla/5.0", …)`.
- `Flush(1000)`; stdout `bcrec battery emitted`; return 0 (123-125).
- связи: `src/afeye/bcrec.h` из 0033 (Hdr 72Б: opcode,scale,n_payload,flags,offset,func_id,line,acc,regs[6]; payload-блоки `[u8 tag][u32 len][len bytes]`, теги 0=AccStr,2=AccSmi,3=Reg,4=RegStr,7=Operand,8=CpStr; `kFlagAccPayload=4`, `kFlagCont=2`, `kSinkRecordCap=(1<<20)-16`) и `src/afeye/sink.h` из 0001. Тест bcrec_roundtrip сверяет результат с декодером src/bctrace.rs (HDR_LEN=72, OP_META=0xfe, OP_FUNC_DEF=0xff, FLAG_ACC_PAYLOAD=4 — bctrace.rs:21-25).

## tools/push-js.py — CLI-продюсер JS-очереди в файл queue/pending.json через GitHub Contents API

- Модульные константы (строки 10-14): env `REPO` (owner/name, обязателен), `BRANCH` (default `main`), `GITHUB_TOKEN` (для приватных репо); `API = https://api.github.com/repos/<REPO>`; `WF = "afeye.yml"`.

### def call(method, path, data=None)  (строки 17-34)
- urllib-запрос к API с заголовками `Accept: application/vnd.github+json`, `User-Agent: afeye-push-js`, `Authorization: Bearer <TOKEN>` если задан; JSON-body при data; timeout 30; HTTPError 404 → None, прочее → raise.

### def get_queue()  (37-44)
- GET `/contents/queue/pending.json?ref=<BRANCH>&t=<epoch>` (антикэш); 404 → `({"items": []}, None)`; иначе base64-decode поля `content` → (json, sha файла).

### def put_queue(q, sha)  (47-55)
- PUT `/contents/queue/pending.json` с `{"message":"queue: push js","content":b64(json),"branch":BRANCH[, "sha":sha]}` — sha обязателен при обновлении существующего файла (защита от конфликтной записи).

### def active_run()  (58-65)
- GET `/actions/runs?per_page=30`; True если есть run с `path`, оканчивающимся на `afeye.yml`, и статусом из `in_progress|queued|waiting|pending`.

### def dispatch()  (68-69)
- POST `/dispatches` с `{"event_type":"afeye-js"}` — триггерит `repository_dispatch` в afeye.yml.

### def main()  (72-101)
- аргумент: `-` → stdin, существующий файл → его содержимое, иначе строка как JS-код; пустой → exit 1. Формирует item `{"id":"j<ms-epoch>","js":<код>,"added":<epoch>}`, append в `items`, обрезка до последних 100 (`del items[:-100]`), put_queue. Если active_run → «live session подхватит за 30с» (relay в afeye опрашивает очередь периодически, src/relay.rs:136+); иначе dispatch и «выполнится на старте».
- связи: потребитель — `src/relay.rs::run` (читает `AFEYE_QUEUE_URL`, парсит `items[].id/js` через `parse_items`, relay.rs:66-98) и `finalize`-шаг afeye.yml (вычёркивает исполненные id из pending.json в queue/processed/). Формат wire: `queue/pending.json` = `{"items":[{"id","js","added"}]}`; текущий файл в репо содержит items вида `{"u": "<url>"}` — такие записи `parse_items` ИГНОРИРУЕТ (требует непустые id И js), URL-таргеты живут в targets.json.

## tools/rec_census.py — перепись .rec-файлов sink'а с assert'ами (используется CI smoke патченного chrome)

- docstring (2-20): назначение — доказать, что .rec содержат реальные записи, а не только sink-hello («мёртвый sink — не catch»); вызывается из CI с `--expect`.
- `KIND_NAMES` (26-67): словарь kind 0-39 → имя; сверяется с `KINDS` в src/collect.rs:14-58 и совпадает для 0-39. kind 40 (`bytecode-trace`) ОТСУТСТВУЕТ — см. дырки.
- `HDR = struct.Struct("<IBHI")` (69): 16-байтный заголовок записи sink'а = `[u32 total_len][u8 kind][u8 flags][u16 rsv]`… фактически struct читает `total_len, kind, flags, _rsv`, где `_rsv` — это u16 из байт 6-7, а ts_ns (байты 8-15) не читается. Раскладка совпадает с EmitFlags (патч 0001: `rec[4]=kind, rec[5]=flags, rec[6]=rec[7]=0, ts в rec+8`).

### def parse_layer(fname)  (72-74)
- слой = префикс имени файла до первого `-` (`v8-1234.rec` → `v8`), без `-` → `?`. Совпадает с `layer_of` в src/collect.rs:74-85 (v8/blink/net).

### def census(path)  (77-97)
- читает файл целиком, шагает по записям: `rec_len<16` или выход за буфер → проверка «рваного хвоста»: если `16<=rec_len<=1MiB && 0<=kind<=39 && flags<=1 && tail>=16` — печать `torn tail at <path>:<off>` и break БЕЗ bad++; иначе `bad+=1`, break. Валидная запись → bucket `(layer, kind_name)+=1`. Возвращает (buckets, total, bad).

### def main()  (100-146)
- args: `dir` + повторяемый `--expect LAYER:KIND=MIN`. Обходит `*.rec` в dir (сортированно), агрегирует buckets; печатает `layer/kind = N` по каждому и `#files=N bad_files=N`. `bad_files>0` → `CENSUS FAIL: … corrupt` → exit 1. Каждое ожидание парсится (`rsplit("=",1)`, `split(":",1)`); синтаксическая ошибка → exit 1; `got < MIN` → собирает missing → печать + exit 1. Иначе `census ok`, exit 0.
- связи: единственный вызов в репо — `.github/workflows/afeye-build.yml:226-239` (13 ожиданий после прогона smoke-страницы на патченном chrome).

## tools/recount_patches.py — пересчёт счётчиков в @@-заголовках патчей серии

- docstring (2-7): серия anchor-style (применяется `git apply`, никогда `--3way`, см. SERIES.md), поэтому НОМЕРА строк приблизительны, а счётчики +/- в заголовках обязаны совпадать с телом ханка — скрипт их пересчитывает.
- `MARKERS` (11) объявлен, но НЕ используется (мёртвая константа).

### def body_line(l)  (14-17)
- строка тела ханка = непустая и начинается с одного из `" +-\"`.

### def fix(path)  (20-66)
- построчно: на `@@ ` разбирает `old_spec,new_spec` (стартовые номера сохраняются, счётчики отбрасываются); собирает тело до первой не-body строки; считает ctx (`" "`), add (`"+"`), rem (`"-"` кроме `"---"`); полностью пустой ханк (add==rem==ctx==0) → УДАЛЯЕТСЯ из вывода (`changed+=1`, `i=j`, continue — заголовок не попадает в out); иначе новые счётчики `old=ctx+rem`, `new=ctx+add` в формате `-start[,count]` (count опускается при 1, `,0` при 0) + хвост `@@<func>` сохраняется; заголовок заменяется если отличается. Файл перезаписывается на месте. Возвращает число изменений.

### def main()  (69-80)
- `glob("*.patch")` в ТЕКУЩЕМ каталоге (запускать из patches/), sort, fix по каждому, печать `done: N headers adjusted`.
- связи: обслуживает целостность патчей для `git apply` в scripts/build-chromium.sh:41.

## Cargo.toml — манифест крейтa afeye

- `[package]` (1-5): name afeye, version 0.1.0, edition 2021, `publish = false`. Явных `[[bin]]`/`[lib]` секций нет: lib = src/lib.rs (`pub mod bctrace; collect; events; sinkfilter`), главный бин = src/main.rs (`afeye`, модули arch/arena/browser/capture/classify/ctx/events/human/inject/relay/tg/timefmt/wg/writer/zipper — main.rs:1-15), плюс авто-бины src/bin/{afeye-collect,bcrec-dump,jscheck}.rs.
- `[profile.release]` (7-11): `opt-level=3`, `lto="thin"`, `codegen-units=16`, `strip=true`.
- `[profile.release.package.chromiumoxide_cdp]` (13-15): `codegen-units=64`, `opt-level=1` — CDP-крейт сознательно компилируется быстро и без оптимизации (огромный кодоген, не горячий путь).
- `[dependencies]` (17-35), назначение по фактическому использованию:
  - `tokio` (rt-multi-thread, macros, time, process, net, fs, io-util, signal): `#[tokio::main]` (main.rs), `tokio::process::Command` (arch.rs:5, wg.rs:3, browser.rs:8), `tokio::time::{sleep,timeout}` (browser.rs:236, capture.rs:233 и др., human.rs:45), `tokio::select!` + `tokio::signal::ctrl_c` (main.rs:479-481), `tokio::spawn` (capture.rs:251), `tokio::runtime::Builder::new_current_thread` для вложенного relay-цикла (main.rs:469). Фичи `net`/`fs`/`io-util` прямых использований `tokio::net|fs|io` в src не нашлось — вероятно нужны chromiumoxide; точно не подтверждено.
  - `futures 0.3`: `StreamExt` для CDP-ивентов (browser.rs:3, capture.rs:252), `future::join_all` (main.rs:22).
  - `chromiumoxide 0.9, default-features=false`: CDP-клиент — `Browser` (browser.rs:2), `Page`, типы browser_protocol/js_protocol (capture.rs:7-12), `EvaluateParams` (relay.rs:7), input-события (human.rs:3-4).
  - `crossbeam-channel 0.5`: unbounded-каналы `FxEvent`/`Art` между capture и writer (main.rs:186-187 — `crossbeam_channel::unbounded`), Sender в ctx.rs:3, Receiver в writer.rs:6.
  - `dashmap 6`: конкурентные карты — `endpoints` (ctx.rs:206), индекс интернера (arena.rs:43), capture.rs:13.
  - `bumpalo 3 (collections)`: arena-аллокатор writer'а — `Bump::with_capacity(1<<21)` (writer.rs:447), `BVec` (writer.rs:5).
  - `bytes 1`: `Bytes/BytesMut/BufMut` — полезная нагрузка FxEvent (events.rs:1, main.rs:21, relay.rs:6, tg.rs:6), writer.rs:378-380.
  - `simdutf8 0.1`: валидация UTF-8 срезов без копирования — arena.rs:150, browser.rs:221, collect.rs:406, writer.rs:176/262/298, main.rs:144/199.
  - `blake3 1`: контент-хэши — capture.rs:138 (хэш артефакта), collect.rs:360 (`"h"` — первые 16 hex в index.jsonl), sinkfilter.rs:432 (ключи taint-графа, 8 байт хэша).
  - `serde 1 (derive)` + `serde_json 1 (raw_value)`: derive на `collect::Stats` (collect.rs:87) и структурах отчётов; serde_json — index/статы/отчёты повсюду. Фича `raw_value` включена, но `RawValue` в src/ не используется (grep пуст) — вероятно тянется для chromiumoxide; точно не подтверждено.
  - `zip 2 (default-features=false, deflate)`: упаковка дампов — zipper.rs:4-5 (`SimpleFileOptions`, `CompressionMethod`).
  - `base64 0.22`: decode очереди relay (relay.rs:5,37-44), encode тел в sinkfilter (sinkfilter.rs:1516-1518), capture.rs:5.
  - `rand 0.8 (small_rng)`: человеческий ввод — `SmallRng/SeedableRng/Rng` (human.rs:5-6).
  - `itoa 1`: формат u64 без аллокаций (writer.rs:381).
  - `ryu 1`: формат f64 без аллокаций (events.rs:111, writer.rs:339/563/579/595).
  - `core_affinity 0.8`: прижать поток writer'а к последнему ядру (writer.rs:442-445).
  - `libc 0.2`: mmap-арена (MAP_PRIVATE|MAP_ANONYMOUS, fallback без MAP_HUGETLB) — arena.rs:52-64.
- `[dev-dependencies]` (37-38): `tempfile 3` — tempdir'ы обоих roundtrip-тестов и inline-тестов collect.rs/sinkfilter.rs.

## targets.json — список URL-целей обхода

- Формат: `{"targets": ["<url>", …]}`. Текущее содержимое (4 цели): `https://chat.z.ai/auth`, `https://chat.z.ai/`, `https://accounts.x.ai/sign-up?redirect=grok-com`, `https://freebuff.com/login`.
- потребитель: `load_targets` (src/main.rs:142-163): читает файл от `AF_ROOT` (default `.`), валидирует UTF-8 (simdutf8), парсит JSON, берёт только строки, начинающиеся с `http`, превращает в `Target{host,url}` (host через `ctx::host_of`); пустой список → ошибка `"targets.json: no http targets"` (main.rs:160); вызов — main.rs:189 `load_targets(&root.join("targets.json"))`.

## scripts/build-chromium.sh — полный цикл сборки патченного Chromium на CI-раннере

Порядок выполнения (set -euo pipefail, строка 2):

1. Конфиг из env с дефолтами (4-9): `CHROMIUM_REF=153.0.8010.52`, `WORK=/mnt/chromium`, `OUT_REL=out/afeye`, `NINJA_TARGET=chrome`, `BUILD_WINDOW_SECS=16200` (4ч30м), `CCACHE_DIR=/mnt/ccache`. Печать шапки (11).
2. Освобождение диска раннера (13-15): `sudo rm -rf /usr/local/lib/android /usr/share/dotnet /opt/ghc /usr/local/.ghcup /opt/hostedtoolcache/CodeQL`, затем `df -h /`.
3. depot_tools (17-21): если нет `$WORK/depot_tools` — `git clone -q --depth 1 https://chromium.googlesource.com/chromium/tools/depot_tools.git`; `export PATH=$WORK/depot_tools:$PATH`; прогрев `gclient --version`.
4. Исходники (23-33): `mkdir -p $WORK/src`; если нет `.gclient` — `gclient config --name=src https://chromium.googlesource.com/chromium/src.git`; если `src/.git` отсутствует ИЛИ `git describe --tags --exact-match` != `$CHROMIUM_REF` — `gclient sync --no-history --with_branch_heads --delete_unversioned_trees -r src@refs/tags/$CHROMIUM_REF`; печать `git rev-parse HEAD`.
5. Системные зависимости (35-36): `sudo ./build/install-build-deps.sh --no-arm` (первый прогон с подавленным выводом, при неудаче повтор с выводом, `|| true`).
6. Патчи (38-42): `REPO_ROOT="${REPO_ROOT:-$GITHUB_WORKSPACE}"`; цикл по `$REPO_ROOT/patches/*.patch` в лексикографическом порядке (0001…0034): `git apply "$p" || patch -p1 --fuzz=0 --no-backup-if-mismatch < "$p"`. Именно под `git apply` без `--3way` recount_patches.py держит счётчики ханков.
7. ccache (44-46): `export CCACHE_DIR`; `ccache -M 9G` (fallback `--max-size=9G`); `ccache -z` (сброс статистики).
8. `gn gen out/afeye --args=…` (48-73), аргументы ПОЛНОСТЬЮ:
   ```
   is_debug = false
   is_official_build = false
   is_component_build = true
   symbol_level = 0
   v8_symbol_level = 0
   blink_symbol_level = 0
   dcheck_always_on = false
   treat_warnings_as_errors = false
   use_remoteexec = false
   use_lld = true
   concurrent_links = 4
   cc_wrapper = "ccache"
   use_clang_modules = false
   enable_nacl = false
   v8_enable_afeye = true
   blink_enable_afeye = true
   network_enable_afeye = true
   extra_cflags = [
     "-DV8_AFEYE=1",
     "-DBLINK_AFEYE=1",
     "-DNET_AFEYE=1",
   ]
   ```
   (gn-переменные `v8_enable_afeye`/`blink_enable_afeye`/`network_enable_afeye` объявляются самими патчами в GN-файлах v8/blink/network; `extra_cflags` — глобальные дефайны, фикс v6-бага «вложенный GN-scope»).
9. Сборка в окне (75-84): `mkdir -p $CCACHE_DIR`; `set +e`; `timeout --signal=TERM $BUILD_WINDOW_SECS ninja -C out/afeye -j $(nproc) chrome`; `rc=$?`; `set -e`. Если `rc != 0 && rc != 124` — реальная ошибка сборки, `exit $rc` (124 = таймаут окна).
10. Исход (85-92): если `out/afeye/chrome` не существует/не исполняем — печать «window exhausted, cache saved, next run resumes», `ccache -s`, `exit 42` (код 42 означает «окно кончилось, прогресс в ccache»); иначе «== built ==», `ccache -s`, `exit 0`.
- env-контракт скрипта: `CHROMIUM_REF, WORK, OUT_REL, NINJA_TARGET, BUILD_WINDOW_SECS, CCACHE_DIR, REPO_ROOT` (по умолчанию `$GITHUB_WORKSPACE`), плюс `sudo`, `git`, `python`, сеть.
- связи: вызывается только из `.github/workflows/afeye-build.yml:85` (`bash scripts/build-chromium.sh || rc=$?`).

## .github/workflows/afeye-build.yml — сборка патченного chrome и публикация релиза (manual-only, самопродлевающаяся цепочка окон)

- триггеры (31-37): только `workflow_dispatch` с input `chromium_ref` (default `153.0.8010.52`). Push в main сборку НЕ начинает.
- permissions `contents: write, actions: write` (39-41); concurrency группа `afeye-build`, без отмены (43-45).
- env (47-53): `CHROMIUM_REF` (из input или default), `WORK=/mnt/chromium`, `OUT=out/afeye`, `NINJA_TARGET=chrome`, `BUILD_WINDOW_SECS='16200'`, `CCACHE_DIR=/mnt/ccache`.
- job `build` (56-60): ubuntu-latest, `timeout-minutes: 350`, output `status`.
- шаги:
  1. `actions/checkout@v4` (62).
  2. workspace (64-70): `sudo mkdir/chown /mnt/chromium /mnt/ccache`, `apt-get install ccache`, `df -h`.
  3. ccache-restore (72-79): `actions/cache/restore@v4`, path `/mnt/ccache`, key `afeye-ccache-<REF>-<run_id>`, restore-keys `afeye-ccache-<REF>-` и `afeye-ccache-` — тёплый кэш прошлых окон.
  4. build (81-88): `bash scripts/build-chromium.sh || rc=$?`; `rc` в GITHUB_OUTPUT; `continue-on-error: true` — провал шага не рвёт job.
  5. ccache-save (90-96): `if: always()`, тот же path, key с текущим run_id, continue-on-error.
  6. result (98-112): статус = `built` если `$WORK/src/$OUT/$NINJA_TARGET` исполняем; иначе `window` если rc==42; `failed` если outcome шага build == failure; иначе `window`.
  7. smoke-test (114-239), только при `status=='built'`: `./chrome --version`; генерит `/tmp/afeye-smoke/smoke.js` (внешний скрипт: функция tok, dispatchEvent CustomEvent `afeye-ping`, addEventListener mousemove; внутри setTimeout 30мс: fetch('probe.txt'), `Function.prototype.toString.call(tok)`, WebAssembly.instantiate 8-байтного модуля, `eval('1+1')`, `new Function('return 2')()`, `Date.now()`, `performance.now()`, canvas 16×16 fillText/getImageData/toDataURL, `document.cookie='afeye=smoke'`, localStorage set/get, `new TextEncoder().encode`, `btoa`, FormData+URLSearchParams, getComputedStyle font-family ×2, `document.fonts.check`, matchMedia+matches, `navigator.permissions.query({name:'notifications'})`, `Notification.permission`, `JSON.stringify`, `new Error('afeye-stack').stack`, `Object.getOwnPropertyDescriptor(Navigator.prototype,'userAgent')`, первый вызов ленивой функции `afeyeLazy`, `new Date()`) и `smoke.html` (внешний + inline скрипт); `python3 -m http.server 8099` в фоне; `timeout 45 env AFEYE_SINK=1 AFEYE_RAW_DIR=/tmp/afeye-smoke/rec ./chrome --headless --no-sandbox --disable-gpu --user-data-dir=… --virtual-time-budget=10000 --dump-dom http://127.0.0.1:8099/smoke.html`; затем ГЛАВНЫЙ assert — `tools/rec_census.py /tmp/afeye-smoke/rec` с 13 ожиданиями (226-239): `v8:script-source=2, v8:call-completed=1, v8:clock=1, blink:clock=1, blink:event-dispatch=1, blink:timer=1, blink:fetch=1, blink:dom-api=1, blink:fingerprint=1, blink:taint-edge=1, v8:fingerprint=1, v8:error-stack=1, net:net-request=1`.
  8. package + release (241-293), при built: `tar czf /tmp/chrome.tgz` из out-каталога с исключениями `./obj*`, `./gen`, `*.ninja*`, `./toolchain.ninja`, `./args.gn`, `./build.ninja`, `*.stamp`, `*.TOC`, `*.a` (т.е. бинарь + все компонентные .so + resources.pak + icudtl.dat + snapshot blobs + locales + vk_swiftshader + crashpad); sanity-assert'ы содержимого: ≥1 `./chrome`, ≥10 `.so`, ≥1 `icudtl.dat` (265-267); `sha256sum`; релиз тегом `chrome-$CHROMIUM_REF` (`gh release upload --clobber` или `create`); запись `build/BUILT.txt` (target/tag/chromium/sha256/built/bytes) и git push его в репо (279-293).
  9. continue-chain (295-302): если status не `failed` и не `built` (т.е. `window`) — sleep 30 и `gh workflow run afeye-build.yml --ref <ref> -f chromium_ref=$CHROMIUM_REF` — цепочка окон до успешной сборки, никогда не упирается в 6-часовой лимит раннера.
  10. fail-loudly (304-308): при `failed` — echo и `exit 1`.

## .github/workflows/afeye.yml — основной crawl-workflow (cron каждые 3ч + dispatch очереди JS)

- триггеры (3-8): `schedule: cron '0 */3 * * *'`, `repository_dispatch: [afeye-js]` (его шлёт push-js.py), `workflow_dispatch`.
- permissions contents/actions write (10-12); concurrency группа `afeye`, `cancel-in-progress: false` (14-16).
- env (18-24): `AFEYE_TG_TOKEN/AFEYE_TG_CHAT` (secrets), `AFEYE_TG_ON` (vars, default '1'), `AFEYE_QUEUE_URL=https://raw.githubusercontent.com/<repo>/<ref>/queue/pending.json`, `AFEYE_QUEUE_TOKEN` (secret, fallback github.token), `AF_BUDGET_MB=350`.
- job `eye` (27-32): ubuntu-latest, timeout 48 мин, outputs `cadence`, `chrome`.
- шаги:
  1. checkout (34).
  2. gate (35-84): inline python читает `state/cadence.json` (`last_end`, `credits`); `deadline = last_end + 3*3600*credits`, эффективные credits = 0 если дедлайн прошёл; для НЕ-dispatch событий → `cadence=go` безусловно; для dispatch: credits≥2 → `cadence=skip` (экономия квоты Actions), пустая очередь → `cadence=skip empty-queue`, иначе `cadence=go`. Комментарии v12.1/v12.1.2 (47-56) документируют два прошлых бага: вывод в stdout вместо `$GITHUB_OUTPUT` и «значение = вся строка после =» (из-за чего `cadence == 'go'` никогда не срабатывал и cron-crawl не бегал).
  3. chrome (85-131), при go: качает `releases/latest/download/chrome.tgz` из релизов ЭТОГО репо; распаковывает в `/opt/afeye-chrome`; бинарь = `chrome`, fallback `headless_shell` (комментарий v7: headless_shell — урезанный, антифрод-селфчеки в нём молча умирают); sink-liveness probe: `AFEYE_SINK=1 AFEYE_RAW_DIR=/tmp/afeye-smoke $CHROME_BIN [--headless --disable-gpu если не headless_shell] --no-sandbox --user-data-dir=/tmp/afeye-smoke-prof --dump-dom about:blank`, счёт .rec-файлов, при 0 — `::warning::`; `AF_CHROME=$CHROME_BIN` в GITHUB_ENV; output `mode=patched`. Если релиза нет — `mode=missing` и `gh workflow run afeye-build.yml` (пинг сборочной цепочки), crawl скипается.
  4. rust-toolchain@stable + rust-cache@v2 (132-135), при go && patched.
  5. env+chrome+tunnels (136-161): фон — `modprobe wireguard`, apt-get `wireguard-tools xvfb aria2 curl zip p7zip-full`, распаковка `wg/*.conf` из secret `WG_CONF_B64` (tar.gz в base64; конфигов в дереве нет намеренно), создание пользователей `fx1..fx7` (uid 2001-2007); параллельно в foreground `cargo build --release`; wait фона.
  6. run (162-185), при go && patched: keepalive-цикл в фоне — каждые 300с копирует `/tmp/afeye/stage/.` → `live/<run_id>/stage/`, `/tmp/afeye-raw/.` → `live/<run_id>/raw/` (только если raw < 200 МБ), git add/commit/pull --rebase/push (force-fallback); затем ОСНОВНОЙ ПРОЦЕСС: `sudo -E env AFEYE_TG_ON=… AFEYE_TG_TOKEN=… AFEYE_TG_CHAT=… AFEYE_QUEUE_URL=… AFEYE_QUEUE_TOKEN=… AF_BUDGET_MB=350 AFEYE_SINK=1 AF_BROWSE_SECS=2280 AF_HARD_SECS=2340 ./target/release/afeye`; kill keepalive. Обратите внимание: `AF_JITLESS`, `AFEYE_VIRTUAL_CLOCK`, `AFEYE_TRACE_BYTECODE` НЕ выставляются — байткод-трейс 0033 в CI-кроуле по умолчанию выключен (см. Аудит).
  7. finalize (186-263), always && go && patched: python — обновляет `state/cadence.json` (`last_end=now`; credits+1 если событие dispatch, обнуляются по дедлайну); вычёркивает из `queue/pending.json` items, чьи id есть в `dumps/relay-state.jsonl`, складывает их JS в `queue/processed/<id>.js`, truncates relay-state; обрезка очереди до 100. Shell — свежайший `dumps/*.zip` (+manifest) копируется В КОРЕНЬ репо (требование «главная страница показывает capture»), в корне держится 3 последних zip/manifest, в dumps — 16; git add dumps/state/queue/live/*.zip/*.manifest.json, commit `run <ts> <event>`, pull --rebase, push (force-fallback); prune старых `live/` (кроме 5) отдельным коммитом.
  8. backup (264-272), always && go && patched: `actions/upload-artifact@v4` имя `afeye-runs`, пути `dumps/*.zip`, `dumps/*.7z`, if-no-files-found ignore.
- связи: потребляет релиз afeye-build.yml; драйвит основной бинарник `afeye` (src/main.rs), который читает `targets.json`, `wg/*.conf`, `AF_CHROME`; очередь пишется tools/push-js.py, исполняется src/relay.rs, отчитывается в `dumps/relay-state.jsonl`.

## Взаимодействия

- `src/bin/afeye-collect.rs` → `afeye::collect::run_standalone`/`scan_once` (src/collect.rs). Дублирует функциональность встроенного потока Collector в главном бинарнике; нужен для ручного разбора raw-каталога.
- `src/bin/bcrec-dump.rs` → `afeye::bctrace::run` + `filtered/bctrace.json`. Человекочитаемый просмотр результатов 0033.
- `src/bin/jscheck.rs` → `src/inject.rs` (raw-строка SRC) + внешний `node --check`. Страж синтаксиса того, что `src/capture.rs:189` инжектит в каждую страницу.
- `tests/sink_roundtrip.rs` ← патчи 0001/0005/0011 + tools/{sink_test_main,blink_smoke_main,net_smoke_main}.cc → `afeye::collect`. Замкнутая цепочка «байты патча = байты timeline» без chromium.
- `tests/bcrec_roundtrip.rs` ← патчи 0001/0033 + tools/bcrec_main.cc → `afeye::collect` + `afeye::bctrace`. Замкнутая цепочка «C++-энкодер 0033 = Rust-декодер bctrace».
- `src/relay.rs` (mod tests) → внешний `node --check` (единственный node-зависимый тест).
- `tools/rec_census.py` ← `.github/workflows/afeye-build.yml` (smoke-assert патченного chrome). Парсит ту же 16-байтовую раскладку записи, что пишет sink (патч 0001) и читает `src/collect.rs`.
- `tools/push-js.py` → GitHub Contents API `queue/pending.json` → `AFEYE_QUEUE_URL` → `src/relay.rs::run` → `dumps/relay-state.jsonl` → finalize-шаг `afeye.yml` (обратная вычитка очереди). Замкнутый контур «внешний JS-заказ → исполнение в патченном chrome → отчёт».
- `tools/recount_patches.py` → `patches/*.patch` → `git apply` в `scripts/build-chromium.sh` → `afeye-build.yml`.
- `scripts/build-chromium.sh` ← только `afeye-build.yml`; результат (chrome.tgz в релизе) ← шаг chrome в `afeye.yml`.
- `Cargo.toml`: lib-крейт `afeye` (bctrace/collect/events/sinkfilter) используется обоими roundtrip-тестами и бинарниками afeye-collect/bcrec-dump; основной бин `afeye` (src/main.rs) живёт в CI-кроуле. `targets.json` → main.rs:189.
- Дырка: `rec_census.py` знает kind 0-39, но 0033 эмитит kind 40 (`kBytecodeTrace=40`, патч 0033 sink.h hunk) — census назовёт его `kind40` (не фатально), а при рваном хвосте проверка `0<=kind<=39` (rec_census.py:87) классифицирует файл с kind-40 записями как corrupt. В CI-смоук 0033 выключен (нет `AFEYE_TRACE_BYTECODE`/`AFEYE_SINK`-конфига для трейса… точнее трейс gated env'ом `AFEYE_TRACE_BYTECODE=0`-off по умолчанию ВКЛ при AFEYE_SINK, но smoke-assert'ы kind 40 не проверяют), так что на практике не стреляло.

## АУДИТ СООТВЕТСТВИЯ ЭТАЛОНУ

Сравнение РЕАЛЬНОГО кода репо с четырёхслойным эталоном. Только факты с номерами строк.

### 1. jitless / no-opt / no-sparkplug

| Флаг эталона | Реально | Где |
|---|---|---|
| `--jitless` | ЕСТЬ, но условно | src/browser.rs:93-99: `if std::env::var("AF_JITLESS").map(\|v\| v == "1").unwrap_or(false) { a.push("--jitless") }` |
| `--no-opt` | НЕТ нигде | grep по src/, scripts/, .github/, tools/ — единственные вхождения «jitless/no-opt/no-sparkplug» это browser.rs:93,96,98 |
| `--no-sparkplug` | НЕТ нигде | там же |

- env-гейт: `AF_JITLESS=1` (browser.rs:93). По умолчанию ВЫКЛ.
- Полный список флагов `chrome_flags` (browser.rs:58-102): `--no-first-run, --no-default-browser-check, --disable-session-crashed-bubble, --hide-crash-restore-bubble, --disable-search-engine-choice-screen, --disable-features=IsolateOrigins,site-per-process,PrivacySandboxSettings4, --disable-site-isolation-trials, --enable-unsafe-swiftshader, --password-store=basic, --use-mock-keychain, --no-sandbox, --remote-debugging-address=<bind>, --remote-debugging-port=<port>, --user-data-dir=<profile>, --window-size=1280,832, --window-position=<grid>, [--user-agent=<ua>], [--headless --disable-gpu если AF_TEST_HEADLESS или headless_shell], [--jitless если AF_JITLESS=1], about:blank`.
- НЕ СООТВЕТСТВУЕТ эталону: (а) `--no-opt` и `--no-sparkplug` отсутствуют — при включённом `--jitless` они избыточны (jitless сам запрещает JIT-тиры), но при выключенном AF_JITLESS код исполняется в Sparkplug/Maglev/TurboFan и хук 0033 такие инструкции НЕ видит; (б) CI-кроул (afeye.yml:184) `AF_JITLESS` не выставляет → продакшн-прогоны идут С JIT, трейс байткода неполный по покрытию; (в) `AFEYE_TRACE_BYTECODE`/`AFEYE_VIRTUAL_CLOCK` в afeye.yml:184 также не передаются. Требуется: либо выставлять `AF_JITLESS=1` (+ `AFEYE_VIRTUAL_CLOCK=1`) в run-шаге afeye.yml, либо добавить `--no-opt --no-sparkplug` в chrome_flags под тем же гейтом.

### 2. Патч диспетчера Ignition

Эталон: хук в `GENERATE_BYTECODE_HANDLER` в `src/interpreter/interpreter-generator.cc`.
Реально (patches/0033-v8-ignition-bytecode-trace.patch):
- файл `src/interpreter/interpreter-generator.cc` НЕ тронут — grep по всем патчам: 0 вхождений (проверено `grep -rn "interpreter-generator" patches/` → пусто).
- Хук №1: `v8/src/interpreter/interpreter-assembler.cc`, конструктор `InterpreterAssembler::InterpreterAssembler` (патч, строки 419-436): `#ifdef V8_AFEYE` → `CallRuntime(Runtime::kAfeyeTraceBytecodeEntry, GetContext(), BytecodeArrayTaggedPointer(), SmiTag(BytecodeOffset()), GetAccumulatorUnchecked(), SmiTag(IntPtrConstant(operand_scale_)))` (патч:430-433). Комментарий патч:425-429: компилируется ВНУТРЬ каждого bytecode-handler генератором — т.е. это функциональный эквивалент хука в GENERATE_BYTECODE_HANDLER, но точка вставки — конструктор InterpreterAssembler (CodeAssembler-слой), а не макрос генератора.
- Хук №2: там же, `InterpreterAssembler::InlineShortStar` (патч:438-452): Star0-Star15 инлайнятся lookahead'ом в предыдущий handler и через конструктор не проходят — второй CallRuntime с `OperandScale::kSingle`. Это ПОКРЫТИЕ, которого эталонный «хук в генераторе» без такой правки не дал бы.
- Регистрация runtime-функции: `v8/src/runtime/runtime.h` (патч:901-930): `FOR_EACH_INTRINSIC_AFEYE(F,I) = F(AfeyeTraceBytecodeEntry, 4, 1, kCannotTriggerGC)`, добавлен в `FOR_EACH_INTRINSIC_TRACE`.
- Реализация: `v8/src/runtime/runtime-trace.cc`, `RUNTIME_FUNCTION(Runtime_AfeyeTraceBytecodeEntry)` (патч:750-900).

Что фиксируется реально vs эталон, по пунктам:
| Эталон требует | Реально | Где (строки патча 0033) | Вердикт |
|---|---|---|---|
| BytecodeOffset | ДА: `SmiTag(BytecodeOffset())` → args.smi_value_at(1) → `offset = bytecode_offset - kHeaderSize + kHeapObjectTag` | 430-432, 757-772 | соответствует |
| опкод | ДА: `op_byte = *pc`, `Bytecodes::FromByte(op_byte)` → `ib.Begin(op_byte,…)` | 786-790, 806-810 | соответствует |
| аргументы: операнды, decoded движком | ДА: цикл по `NumberOfOperands(bc)`, `BytecodeDecoder::DecodeRegisterOperand/DecodeSignedOperand`, каждый операнд → `ib.Operand(i, value)` (tag kTagOperand=7) | 818-868 | соответствует |
| аргументы: регистры источника/приёмника — индексы | ДА: для register-input операндов деконируется индекс + count (RegList), каждый `ib.Reg(ridx, raw_word)` (tag 3) | 828-845 | соответствует |
| аргументы: ЗНАЧЕНИЯ регистров | БОЛЬШЕ эталона: String → полные байты `RegStr` (tag 4/12), HeapNumber → `RegF64` (5), Smi → `RegSmi` (6) | 838-848 | соответствует+ |
| имя свойства из пула констант | ДА, но на стороне декодера: cp целиком уезжает в func-def blob (`AfeyeEmitFuncDef` → raw_constant_pool → CpSpan'ы, патч:684-731), разрешение cp-индекса в значение делает Rust (src/bctrace.rs:634-655, список cp-опкодов `LdaConstant/GetNamedProperty/SetNamedProperty/CallProperty/...`) | 684-731; bctrace.rs:636-655 | соответствует (другое место, факт тот же) |
| SharedFunctionInfo | ЧАСТИЧНО: SFI не передаётся в записи; из него берётся `func_id = MakeFuncId(script_id, function_literal_id, StartPosition, iso_tag)` (FNV-1a, GC-стабильный) | 793-798; bcrec.h патч:118-135 | НЕ соответствует буквально (нет ссылки/поля SFI), соответствует по смыслу (детерминированная идентичность функции) |
| имя исходного скрипта | ДА: в func-def blob — `sc->name()` полными байтами + `line = sc->GetLineNumber(sfi->StartPosition())` + script_id участвует в func_id | 666-681 | соответствует |
| аккумулятор | БОЛЬШЕ эталона: сырое tagged-слово в Hdr.acc + полное значение (AccStr/AccF64/AccSmi, tags 0/11, 1, 2) | 806-810, 871-884 | соответствует+ |
| лимиты/dedupe | `g_afeye_seen` — thread_local unordered_set по (func_id, bc_len), точный, без cap'а (патч:531-552); записи без truncation, oversized → EmitSplit с kFlagCont (bcrec.h патч:338-360) | — | соответствует заявленному «никаких лимитов» |
| гейты | early-return если `!Enabled()` (AFEYE_SINK) или `AFEYE_TRACE_BYTECODE=0` | 751-757, 503-509 | — |

Итог п.2: функционально СООТВЕТСТВУЕТ эталону и шире его (значения регистров/аккумулятора, инлайновые Star, split больших записей); расхождения — (а) точка хука: конструктор InterpreterAssembler + InlineShortStar, а не GENERATE_BYTECODE_HANDLER в interpreter-generator.cc (эквивалентно по покрытию, патч:425-452); (б) SFI/имя скрипта не в каждой записи, а один раз в func-def по func_id (патч:658-748).

### 3. Виртуализация таймингов

Эталон: `src/base/platform/time.cc` ИЛИ `Performance::now` в blink; формула `virtual_time += kBaseInstructionCost * instruction_count`.
Реально (patches/0034-v8-blink-virtual-clock.patch, 85 строк, 2 файла):
- `third_party/blink/renderer/core/timing/performance.cc`: `Performance::now()` (патч:19-44) — при `blink::afeye::Enabled()` и `AFEYE_VIRTUAL_CLOCK` (не "0") возвращает `g_afeye_origin_ms + afeye_vclock_ns()/1e6`, где origin фиксируется один раз (`base::TimeTicks::Now().since_origin().InMillisecondsF()`), счётчик читается через `extern "C" uint64_t afeye_vclock_ns(void)` (патч:15). СООТВЕТСТВУЕТ ветке эталона «Performance::now в blink».
- `v8/src/objects/js-objects.cc`: `JSDate::CurrentTimeValue` (патч:60-82) — `g_afeye_epoch_ms + v8::afeye::afeye_vclock_ns()/1e6`, эпоха-база один раз через `V8::GetCurrentPlatform()->CurrentClockTimeMilliseconds()`. Это Date.now()/new Date() — в эталоне не упомянуто, сделано ДОПОЛНИТЕЛЬНО.
- Инкремент счётчика: НЕ в 0034, а в 0033 — `RUNTIME_FUNCTION(Runtime_AfeyeTraceBytecodeEntry)`: `if (AfeyeVclockOn()) v8::afeye::VclockTick(AfeyeVclockNsPerInstr())` (патч 0033:768-770), т.е. +N нс на КАЖДУЮ исполненную инструкцию. Счётчик: `v8/src/afeye/sink.cc` — `std::atomic<uint64_t> g_vclock_ns`, `afeye_vclock_ns()` (relaxed load), `VclockTick(ns)` (fetch_add) (патч 0033:371-386); объявления в sink.h (патч 0033:400-413).
- Формула: `virtual_time += ns_per_instr * 1` на инструкцию; `ns_per_instr` = env `AFEYE_VCLOCK_NS_PER_INSTR`, default 10 (патч 0033:517-523). Это ТОЧНО `virtual_time += kBaseInstructionCost * instruction_count` (kBaseInstructionCost = 10нс по умолчанию, настраивается env).
- `src/base/platform/time.cc` НЕ тронут (в 0034 только performance.cc и js-objects.cc) — эталон допускает «ИЛИ», так что СООТВЕТСТВУЕТ; но: прочие потребители `base::TimeTicks::Now()` (таймауты blink-планировщика, setTimeout-дедлайны, монохромные часы вне Performance::now) остаются на физическом времени — виртуализация покрывает только JS-видимые `performance.now()` и `Date.now()`. Чего не хватает относительно полной модели эталона: time.cc/MonotonicallyIncreasingTime не виртуализованы.
- Гейты: `AFEYE_VIRTUAL_CLOCK` (вкл), по умолчанию ВЫКЛ в обеих точках (0034:30-33, 69-73) и в тикере (0033:510-515). В CI (afeye.yml:184) не выставляется.

### 4. WebIDL/DOM биндинги

Эталон: патч `src/bindings/core/v8/` (V8DOMConfiguration) — логировать геттер/сеттер интерфейса с АРГУМЕНТАМИ и ТИПОМ возвращаемого значения.
Реально:
- `patches/0008-blink-dom-api.patch` (202 строки, 1 файл): `third_party/blink/renderer/platform/bindings/idl_member_installer.cc` — НЕ `src/bindings/core/v8/`, а platform-слой установки IDL-членов (через него проходят ВСЕ сгенерированные V8*-bindings, т.е. покрытие шире точечного V8DOMConfiguration). Механика: `AfeyeWrapDomApi` (патч:52-77) для каждого callback'а атрибута/операции аллоцирует ячейку `AfeyeApiCell{orig, prop, what[104]}` из статической таблицы 64K слотов (открытая адресация, слот = `(orig>>4) & mask`), identity-строка `"dom <Interface>.<get|set|call> <property>"` (патч:68-69); callback подменяется на `AfeyeDomApiThunk` (патч:34-50), data-slot = External на ячейку; подстановка afeye_data в обе ветки `FunctionTemplate::New` (патч:117-133); проброс `interface_name_ptr` в InstallAttribute/InstallOperation (патч:151-199). Эмит: `EmitStr(kDomApi=29, what)` с глобальным cap 8 000 000 вызовов (патч:41-45). При выключенном sink/исчерпанных ячейках — бит-в-бит стоковое поведение (патч:94-96, 57-59).
- `patches/0024-blink-dom-api-values.patch` (93 строки, тот же файл): thunk перестроен — сначала `cell->orig(info)`, ПОТОМ захват возвращаемого значения `AfeyeCaptureValue(info.GetReturnValue().Get())` (патч:25-58): undefined/null/bool(0|1)/number(`%.17g`)/string(WriteUtf8, cap 159, непечатаемые → '?')/array(`[array len=N]`)/object(`[object]`); итоговая строка `"%s val=%.150s"` → `EmitStr(kDomApi, buf320)` (патч:76-90). Гейт `AFEYE_TRACE_DOM_VALUES=0` откатывает к именам без значений (патч:20-23, 77-79).
- `patches/0019-blink-fp-values.patch` (341 строка, 7 файлов — точечные хуки, НЕ idl_member_installer): css_computed_style_declaration.cc — `css/get-computed prop=<name> val=<CssText>` (патч:37-46, kind kFingerprint=16, cap 2M); font_face_set.cc — `fonts/check font=… text=…` (87-95, cap 200K); media_query_list.cc — `media/matches q=… m=<0|1>` (136-143); local_dom_window.cc — `matchMedia`: `media/query q=…` (184-191, cap 200K); base_rendering_context_2d.cc — `canvas/draw-text op=<stroke|fill> text=… font=… xy=…` (226-238, cap 2M); notification.cc — `perm/notification value=<granted|denied|default|prompt> ctx=…` (266-303); permissions.cc — `perm/query name=…` (331-337). Все → `EmitStr(blink::afeye::kFingerprint, …)`.

Сравнение с эталоном:
- АРГУМЕНТЫ вызова: НЕ СООТВЕТСТВУЕТ — thunk в 0008/0024 логирует только identity (`dom I.get prop`) и RETURN value; `info[i]` (входные аргументы) не читаются и не эмитятся. Частичное покрытие аргументов есть только в точечных хуках 0019 (текст/font/media-query/permission-name — это и есть аргументы соответствующих вызовов). Требуется: в `AfeyeDomApiThunk` до/после `orig(info)` снимать `info.Length()/info[i]` тем же `AfeyeCaptureValue`.
- ТИП возвращаемого значения: НЕ СООТВЕТСТВУЕТ буквально — `AfeyeCaptureValue` (0024:29-57) кодирует тип НЕЯВНО формой строки (`undefined`/`null`/`0|1`/`%.17g`/строка/`[array len=N]`/`[object]`), отдельного поля типа нет. Значение — ДА (0024:81-88). Требуется при буквальном соответствии: префикс вида `t=<typeof>`.
- Место патча: `src/bindings/core/v8/` НЕ тронут; вместо него platform-слой `idl_member_installer.cc` (0008:1) — функционально эквивалентно и шире (единая точка для всех IDL-членов), расхождение только в файле.
- Геттер/сеттер различаются: ДА — `afeye_access = "get"/"set"/"call"` по ExceptionContext kind (0008:100-105).

### 5. Финальный формат лога

Эталон: на каждую операцию `timestamp_virtual, script_id, function_name, bytecode_op, target_property, arguments_hash` (JSONL/protobuf).
Реальный wire (0033): бинарная запись sink kind=40: 16Б sink-заголовок (`[u32 total_len][u8 kind=40][u8 flags][u16 0][u64 ts_ns]`, патч 0001 EmitFlags) + `Hdr` 72Б (`opcode, scale, n_payload, flags, offset, func_id, line(=iso_tag для инструкций), acc, regs[6]`, bcrec.h патч:36-58) + payload-блоки `[u8 tag][u32 len][bytes]`.
Реальный человекочитаемый выход: `src/bctrace.rs` пишет `filtered/bctrace/sem/<func_id:08x>.jsonl`, строка = `{"ts","off","op"[,"args"][,"acc"][,"res"][,"regs"]}` (bctrace.rs:724-757), плюс `filtered/bctrace.json` c `functions[]` = `{"func_id","name","line","frame_size","param_count","bc_len","instructions","blocks","executions","live_blocks","dead_blocks","dead_ranges","first_ts"}` (bctrace.rs:569-583) и `api_calls[]` = `{"what","times","values"}` (bctrace.rs:753-761).

| Поле эталона | Есть ли реально | Где именно | Что делать, если нет |
|---|---|---|---|
| `timestamp_virtual` | ЧАСТИЧНО | `ts` в sem-строке = sink `NowNs()` = `MonoNs()` (CLOCK_MONOTONIC, патч 0001:92-97, 235) — ФИЗИЧЕСКОЕ время, записанное в ts_ns заголовка. Виртуальные часы (0034) подменяют только то, что видит СТРАНИЦА (performance.now/Date.now), не ts записей | если нужен виртуальный ts в логе: в `AfeyeEmit` (0033:580-588) при `AfeyeVclockOn()` передавать `afeye_vclock_ns()` вместо `NowNs()`, либо добавить поле в sem-строку bctrace.rs:724-727 |
| `script_id` | ЧАСТИЧНО | в per-instruction записи НЕТ отдельным полем; впечён в `func_id = MakeFuncId(script_id, literal_id, start_pos, iso_tag)` (0033:796-798) — необратимо (FNV-хэш); сам script_id в wire не кладётся | добавить поле в Hdr или payload-блок (свободный тег) в AfeyeEmitFuncDef/ib.Begin, либо таблицу func_id→script_id в func-def blob |
| `function_name` | ЧАСТИЧНО | в записи инструкции НЕТ; есть в func-def blob (имя СКРИПТА `sc->name()`, 0033:666-681, не имя функции как `DebugName`) и в отчёте `functions[].name` (bctrace.rs:571) | для буквального соответствия: эмитить `sfi->DebugName()`/`GetFunctionName` в func-def blob (сейчас только script name) |
| `bytecode_op` | ДА | `op_byte` → Hdr.opcode (0033:786-790, 806-810) → имя из meta-таблицы → `"op"` в sem-строке (bctrace.rs:726) | — |
| `target_property` | ЧАСТИЧНО | отдельного поля нет; для ~20 cp-опкодов (GetNamedProperty/SetNamedProperty/CallProperty*/LdaGlobal/…) `args[0]` = разрешённое через constant pool имя свойства (bctrace.rs:634-665), в sem-строке это `"args"`; агрегат — `api_calls[].what` вида `"prop navigator"`/`"call fetch"` (bctrace.rs:676-706) | при буквальном соответствии: продублировать args[0] в поле `target_property` для named-property/call опкодов |
| `arguments_hash` | НЕТ (сделано сильнее) | хэша нет; операнды пишутся ПОЛНЫМИ значениями: engine-decoded `Operand`-блоки (0033:818-868), значения регистров RegStr/RegF64/RegSmi (0033:838-848), аккумулятор AccStr/AccF64/AccSmi (0033:871-884), в sem — `"args"`, `"regs"`, `"acc"`, `"res"` (bctrace.rs:728-757) | ничего; если нужен именно хэш — считать blake3 от args на стороне bctrace.rs |

Итог п.5: формат НЕ JSONL-в-wire (бинарный, JSONL появляется только после Rust-обработки), `bytecode_op`/операнды/значения соответствуют и превышают эталон; `timestamp_virtual` в записях отсутствует (виртуальны только часы страницы); `script_id` и `function_name` не лежат в per-instruction записи (первый — только внутри хэша func_id, второе — только имя скрипта в func-def); `target_property` существует как разрешённый args[0], а не отдельное поле; `arguments_hash` заменён полными значениями.
