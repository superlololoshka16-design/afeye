# V8-сторона патчей afeye (v8/src/afeye + хуки в движке V8)

Охват: patches/0001, 0002, 0003, 0004, 0020, 0021, 0022, 0023 (v8-часть), 0025 (v8-часть), 0026, 0027, 0028, 0031, 0033, 0034 (v8-часть + performance.cc), patches/SERIES.md. Номера строк — это строки ФАЙЛА ПАТЧА в /home/xarle/afeye/patches/ (проверяемо `sed -n`), плюс позиции в целевых файлах из @@-заголовков ханков. Все патчи гейтятся макросом `V8_AFEYE`; сборка включает его через `v8_enable_afeye = true` и `extra_cflags = ["-DV8_AFEYE=1", ...]` (scripts/build-chromium.sh:63-69). Патчи применяются по имени в алфавитном порядке: `git apply`, fallback `patch -p1 --fuzz=0` (build-chromium.sh:39-41).

---

## patches/SERIES.md — манифест серии (89 строк, местами устарел)

Ключевые утверждения (строки файла):
- :1 — предупреждение, что текст может быть неактуален, «читай код».
- :2 — **0028 known-unwired**: `WasmShadowPushStoreTaint` никто не вызывает, JS typed-array store в wasm-память не имеет C++ funnel на этой ревизии, `t_store_taint = 0`, записи `wasm-shadow-*` НЕ эмитятся. Подтверждено grep'ом: вызовов `WasmShadowPushStoreTaint`/`ShadowSetRange` нет ни в одном патче (только определения в 0028, строки 614, 437 и объявления 681, 674).
- :4 — 0031: witness-каунтеры (dropped/imbalance/misses/minted) ненулевые = async-дерево неполное.
- :6 — мёртвые enum'ы: kPerfEntry 13, kClientHints 20, kAtomics 9, kSabBacking 10, kSwCache 21 — определены, названы коллектором, НЕ эмитятся. (По v8-стороне additionally мертвы kBytecodeEntry 2, kWasmTable 5, kMicrotaskEnqueue 6, kMicrotaskRun 7 — см. аудит.)
- :23 — JS→JS вызовы не пересекают Invoke; interpreter hooks больше нет (до 0033).
- :27 — DefineOwnProperty НЕ захвачен (audit R4, deferred): без шумового фильтра хук топит стрим.
- :31 — G6 caller-edges не гуляются на lazy-compile; замена: callee first-execution (0022), Error.stack (0021), Invoke entries (0003).
- :66 — SIGKILL-only shutdown теряет хвост ring невидимо для kind-39 witness; обязателен SIGTERM + 1.2s grace.
- :70 — fork/zygote: дочерний рендерер наследует once_flag + ring без drain-потока → решено ReinitAfterFork (0001).
- :72 — sink-drop пишется НАПРЯМУЮ в fd, никогда через ring; throttle ~10/s, только когда счётчик сдвинулся (реализация 0023, порог 100 мс).
- :80-86 — описание 0033 (формат v3, два хука, func_id FNV, dedupe, EmitSplit, tools/bcrec_main.cc + tests/bcrec_roundtrip.rs как доказательство формата без сборки хрома).
- :85 — «Квоты: 50M инструкций на процесс (backstop), AFEYE_BC_CAP переопределяет» — **ПРОТИВОРЕЧИТ** :86 «НИКАКИХ ЛИМИТОВ» и коду: ни `AFEYE_BC_CAP`, ни 50M-счётчика нет ни в 0033, ни где-либо в репо (grep по patches/, src/, tools/ — единственное вхождение: сам SERIES.md:85). Устаревшая строка.
- :88-89 — описание 0034 (виртуальные часы, extern "C" `afeye_vclock_ns`, дефолт 10 нс/инструкцию, честные оговорки: vclock глобальный на процесс; Date.now() миллисекундная гранулярность).

---

## patches/0001-v8-sink.patch — ядро: ring-синк v8 (BUILD.gn + src/afeye/sink.{h,cc})

Файлы: `v8/BUILD.gn`, новые `v8/src/afeye/sink.cc` (325 строк), `v8/src/afeye/sink.h` (52 строки).

### BUILD.gn (патч строки 1-40)
- `declare_args()`: новый arg **`v8_enable_afeye = false`** (патч :9-10, hunk @@ -64,6 +64,9).
- В `v8_cluster_source_set("v8_base_without_compiler")` (hunk @@ -7041,6 +7044,25, патч :15-38): блок SIBLING vtune-блока (не вложен — комментарий :20-25 объясняет: в v6 был вложен под `v8_enable_vtunetracemark` и sink.cc никогда не компилировался). `defines = []` объявляется ПЕРЕД `+=` (v12.1 фикс: bare `defines +=` в этом scope = GN Undefined identifier, CI падал на BUILD.gn:7059; патч :26-30). При `v8_enable_afeye`: `sources += ["src/afeye/sink.cc", "src/afeye/sink.h"]`, `defines += ["V8_AFEYE"]`.

### sink.h enum EventKind (патч :389-408 → sink.h:12-31)
Полный список v8-стороны (после всех патчей серии; порядок объявления в enum НЕ числовой):

| № | имя | эмитируется (патч) |
|---|-----|--------------------|
| 0 | kSinkHello | 0001 EmitHello ( DrainLoop ) |
| 1 | kScriptSource | 0002 (eval/script/streamed), 0022 (wrapped) |
| 2 | kBytecodeEntry | **НИКЕМ (мёртв)**; заменён kind 40 (0033) |
| 3 | kWasmModule | 0003 SyncCompile/AsyncCompile; 0020 OnFinishedStream/Deserialize |
| 4 | kWasmMemory | 0026 EmitWasmMemContent; 0028 EmitShadow |
| 5 | kWasmTable | **НИКЕМ (мёртв)** |
| 6 | kMicrotaskEnqueue | **НИКЕМ (мёртв)**; заменён kind 30 |
| 7 | kMicrotaskRun | **НИКЕМ (мёртв)**; заменён kind 30 |
| 8 | kCallCompleted | 0003 AfeyeLogInvoke; 0022 AfeyeLogLazyCompile |
| 9 | kAtomics | **НИКЕМ (мёртв, SERIES.md:6)** |
| 10 | kSabBacking | **НИКЕМ (мёртв, SERIES.md:6)** |
| 16 | kFingerprint | 0021 json-stringify; 0022 gopd; 0025 gopd-proxy; 0027 taint-sink; 0031 causality; 0032 taint-swept/deadend |
| 30 | kMicrotaskDrain | 0004 RunMicrotasks start/end |
| 31 | kWasmInstance | 0001 EmitWasmMemGrow; 0003 instantiate/import; 0020 trap/firstcall |
| 32 | kFnToString | 0004 FunctionPrototypeToString |
| 33 | kClock | 0004 DateNow; 0022 DateConstructor |
| 34 | kIsolateBirth | 0003 Isolate::New; 0025 JitLogger exec-записи (переиспользование kind!) |
| 38 | kErrorStack | 0021 GetFormattedStack wrapper |
| 39 | kSinkDrop | 0023 WriteDropReport |
| 40 | kBytecodeTrace | 0033 (объявлен в sink.h патчем 0033 :396) |

### sink.cc константы и глобальное состояние (патч :73-90 → sink.cc:27-44)
- `kRingBytes = 8u << 20` (8 МиБ) — логический размер ring.
- `kMaxRecord = 1u << 20` (1 МиБ) — максимум на запись.
- `kSpanCap = 64u * 1024u` (64 КиБ) — cap тела в EmitSpan.
- `kLayer = "v8"` — имя слоя (файл `<dir>/v8-<pid>.rec`, hello-текст, drop-репорт).
- `g_on` (atomic bool), `g_dropped` (atomic u64, ring-дропы), `g_init_once` (once_flag), `g_pid` (atomic pid_t), `t_pid` (thread_local pid_t — кэш для fork-детекта).
- `struct Ring { atomic_flag lock; size_t head, tail; uint8_t data[kRingBytes + kMaxRecord]; }` — спин-лок (test_and_set/clear), head/tail — логические offsets mod kRingBytes; **доп. kMaxRecord байт pad'а**: запись, начинающаяся у конца ring, пишется непрерывно в pad, поэтому reader делает один memcpy без склейки (патч :84-89).
- `g_write_err` (atomic u64, патч :112) — счётчик ошибок write().

### fn MonoNs() (патч :92-97 → sink.cc:46-51)
`clock_gettime(CLOCK_MONOTONIC)` → u64 нс. Все ts в wire — РЕАЛЬНЫЙ монотонный время, не vclock (важно для аудита п.5).

### fn EnvOn() (патч :99-102)
env **AFEYE_SINK**: включено если задан, непуст и первый символ НЕ '0'.

### fn RawDir() (патч :104-110)
env **AFEYE_RAW_DIR**, дефолт `/tmp/afeye-raw`; static-кэш (читается один раз).

### fn WriteAll(fd, p, n) (патч :114-126)
Цикл write(); EINTR → retry; ошибка → `g_write_err++` и выход; w==0 → выход.

### fn EmitHello(fd) (патч :128-144)
Пишет kind-0 запись напрямую в fd: текст `"afeye-sink/v8 v2 pid=<pid>"` (snprintf в 96 байт), раскладка `[u32 total=16+n][kind=0][flags=0][0][0][u64 MonoNs][text]`.

### fn DrainLoop() (патч :146-196 → sink.cc:100-150)
Единственный потребитель ring, detached-поток:
1. path = `<RawDir()>/v8-<pid>.rec`, open O_CREAT|O_APPEND|O_WRONLY 0666; при успехе EmitHello.
2. thread_local buf 1 МиБ.
3. Бесконечный цикл: spin-lock (yield каждые 64 спина); если tail != head — читать u32 len из data[tail]; **валидация `16 <= len <= kMaxRecord`, иначе `tail = head`** (ресинк всего ring = массовый сброс при рассинхроне); memcpy len байт в buf; tail += len, wrap mod kRingBytes.
4. Вне лока: WriteAll(buf); если g_write_err сдвинулся — close(fd), fd=-1; если fd<0 — reopen + новый EmitHello (ротация при исчезновении файла).
5. Пусто → sleep 500 мкс.
6. (0023 добавляет сюда drop-witness — см. 0023.)

### fn ReinitAfterFork() (патч :198-205)
После fork(): clear lock, head=tail=0 (незадрейненные записи РОДИТЕЛЯ ТЕРЯЮТСЯ), g_dropped=0, g_pid=getpid(), новый detached DrainLoop. Закрывает проблему SERIES.md:70 (zygote-наследник без drain-потока).

### fn InitOnce() (патч :207-215)
Если !EnvOn() — выход (g_on остаётся false, sink мёртв, но Enabled() всё равно вызывается один раз). mkdir+chmod 0777 RawDir; g_on=true; g_pid=getpid(); spawn DrainLoop; `atexit([]{ Flush(500); })`.

### fn Enabled() (патч :219-233)
`call_once(InitOnce)`; кэш pid в t_pid; если `g_pid != me` — CAS g_pid→me, победитель вызывает ReinitAfterFork (fork-детект на каждое обращение, дешево: thread_local сравнение). Возвращает g_on. Все хуки серии начинаются с `if (v8::afeye::Enabled())` — при выключенном sink цена = один atomic load (+один call_once).

### fn NowNs() (патч :235)
= MonoNs().

### fn EmitFlags(kind, ts_ns, flags, data, len) (патч :237-274 → sink.cc:191-228)
Единственная точка записи в ring:
- гейты: g_on, data!=null, len>0.
- `len > kMaxRecord-16` → clamp + `flags |= 1` (бит truncation).
- spin-lock (yield/64); `used = (h>=t) ? h-t : kRingBytes-t+h`; если `kRingBytes - used < need + 8` → **drop: g_dropped++** и выход (8 байт slack).
- запись заголовка в data[h]: `[u32 total=16+len][u8 kind][u8 flags][0][0][u64 ts_ns][payload]`; head = (h+need) mod kRingBytes.

Wire-формат записи .rec ( little-endian, идентичен у v8/blink/net sinks ):
```
off 0: u32 total (= 16 + len)
off 4: u8 kind (EventKind)
off 5: u8 flags (бит0 = truncated)
off 6: u8 0
off 7: u8 0
off 8: u64 ts_ns (CLOCK_MONOTONIC)
off 16: payload[total-16]
```
collect.rs валидирует ровно это (src/collect.rs:294-299: kind <= 40, flags <= 1, байты 6-7 == 0).

### fn Emit / EmitStr / EmitTwoStr / EmitSpan (патч :276-328)
- `Emit(kind, ts, data, len)` = EmitFlags с flags=0 (сырые байты; clamp 1 МиБ-16).
- `EmitStr(kind, ts, s)` = strlen-вариант.
- `EmitTwoStr(kind, ts, a, b)`: payload = `a \0 b`; cap каждого `kMaxRecord-17`; thread_local std::string buf; truncation flag. Используется 0002 для script-source (name\0source).
- `EmitSpan(kind, ts, tag, bytes, n)`: payload = `tag(≤64) \0 bytes(≤ kSpanCap=64КиБ)`; thread_local vector; truncation flag.

### fn EmitWasmMemGrow(old_pages, new_pages) (патч :329-343)
env **AFEYE_TRACE_WASMMEM**=0 выключает; счётчик cap **100 000**; текст `"wasm-mem grow old=%u new=%u"` → EmitStr kind 31.

### fn SinkDropped() / Flush(timeout_ms) (патч :346-365)
- SinkDropped = g_dropped + g_write_err.
- Flush: poll ring до empty или дедлайна (sleep 200 мкс); вызывается из atexit(500 мс). Возвращает true если ring пуст.

---

## patches/0002-v8-scripts.patch — дамп исходников скриптов (kind 1)

Файл: `v8/src/codegen/compiler.cc`.

### static fn AfeyeDumpScriptSource(isolate, DirectHandle<String> source, fallback_name, MaybeHandle<Object> maybe_name) (патч :39-77; hunk @@ -75,6 +83,61)
- Одно определение ДО всех call sites; три funnel'а компиляции (eval, streamed, buffered) все проходят через неё.
- env **AFEYE_SOURCE**=0 выключает (static-кэш, патч :46-49). Комментарий :43-45: getenv вместо v8_flag, т.к. DEFINE_BOOL в flag-definitions.h форсит перекомпиляцию ВСЕГО v8.
- Инвариант v12.4 (N8, патч :31-38): тело АЛЛОЦИРУЕТ (Utf8Value может Flatten→GC, std::string) — легально только в compile-funnels (аллоцирующий контекст), запрещено переносить в Invoke/GC-active/DisallowGarbageCollection. Сам sink (EmitTwoStr) копирует в ring без аллокаций.
- Имя: `iso:%p ` (26 байт, snprintf) + script name (из maybe_name если String, иначе fallback) — iso-префикс группирует eval-цепочки per isolate: worker-поток не смешивается с main thread в одном pid.
- Эмит: `EmitTwoStr(kScriptSource=1, NowNs(), final_name, *utf8)` → payload `"iso:<ptr> <name>\0<source>"`, cap ~1 МиБ. **Без счётчика/cap** — только env-гейт.

### Точки вызова (3 хука)
1. `Compiler::GetFunctionFromEval` (hunk @@ -3304,6 +3367,9; патч :82-88) — fallback_name `"eval"`, name_obj пустой.
2. `GetSharedFunctionInfoForScriptImpl` (hunk @@ -3953,6 +4019,10; патч :92-99) — `"script"` + `script_details.name_obj` (обычные и streamed-скрипты через buffered-путь).
3. `Compiler::GetSharedFunctionInfoForStreamedScript` (hunk @@ -4297,6 +4367,10; патч :103-110) — `"script"` + name_obj (streaming-компиляция; байты модуля при этом ловит 0020 OnFinishedStream).
4-й call site ("wrapped") добавлен патчем 0022.

Почему здесь: это ЕДИНСТВЕННЫЕ funnel'ы, через которые любой JS-исходник попадает в компилятор ( eval() / <script> / streaming / wrapped ) — один хук на вход = полный охват source-текста.

---

## patches/0003-v8-calls-wasm.patch — C++→JS вызовы, изолейты, wasm-модули (kind 8/31/34/3)

Файлы: `v8/src/api/api.cc`, `v8/src/execution/execution.cc`, `v8/src/wasm/module-instantiate.cc`, `v8/src/wasm/wasm-engine.cc`.

### api.cc: комментарий о переносе хука (патч :20-22)
Хук call-origin перенесён ГЛУБЖЕ — из `Function::Call` в единый funnel `Execution::Invoke` (execution.cc). В `Isolate::New` (hunk @@ -10363,6 +10371,15; патч :27-41): после Initialize — `EmitStr(kIsolateBirth=34, "isolate-new iso=%p")`.

### execution.cc: static fn AfeyeLogInvoke(isolate, const InvokeParams& params) (патч :78-140; hunk @@ -302,9 +314,79)
- env **AFEYE_TRACE_CALLS**=0 выключает; cap **4 000 000** (g_afeye_calls).
- Базовый текст: `"call argc=%u%s"` (+`" c=1"` если params.is_construct).
- Если target — JSFunction (под `DisallowGarbageCollection`): SFI → script; `GetLineNumber(sfi->StartPosition())`; имя скрипта через `String::FlatContent` (one-byte/two-byte ветки), cap 200 символов, санитария в printable ASCII (не 0x20..0x7e → '?'), fallback `"native"`; дописывает `" script=%.*s:%d"`.
- Эмит: `EmitStr(kCallCompleted=8, ...)`, буфер 320 байт.
- Хук в `Invoke()` (патч :142-149) — первая строка после RCS_SCOPE. Почему Invoke: единственный funnel, через который проходят ВСЕ входы C++→JS (Function::Call, call-и из builtins, microtask-запуск и т.д.); JS→JS вызовы его НЕ пересекают (SERIES.md:23) — их покрывает 0022 lazy-compile + 0033.

### module-instantiate.cc: InstanceBuilder::ProcessImports (hunk @@ -2003,8 +2007,26; патч :168-191)
- До цикла: `EmitStr(kWasmInstance=31, "wasm-instantiate imports=%d")`.
- На каждый импорт: `"wasm-import %s kind=%d"` (ImportName(index), import.kind).

### wasm-engine.cc: SyncCompile / AsyncCompile (hunks @@ -613 и @@ -730; патч :209-238)
- Оба: `Emit(kWasmModule=3, bytes.begin(), min(size, 0xFFFFF0))` — **СЫРЫЕ байты wasm-модуля**. Внимание: Emit clamp'ит до kMaxRecord-16 = 1 МиБ-16 с truncation-флагом, т.е. cap 0xFFFFF0 (16 МиБ) фактически недостижим — модули >1 МиБ урезаются (см. аудит/дырки).

---

## patches/0004-v8-engine-fidelity.patch — Date.now, Function.prototype.toString, microtask drain (kind 33/32/30)

Файлы: `v8/src/builtins/builtins-date.cc`, `v8/src/builtins/builtins-function.cc`, `v8/src/execution/microtask-queue.cc`.

### BUILTIN(DateNow) (патч :17-37; hunk @@ -149,6 +154,20)
env **AFEYE_TRACE_CLOCK**=0 выключает; cap **2 000 000** (g_afeye_clock, static atomic внутри builtin); `EmitStr(kClock=33, "clock date-now")`. Хук ДО возврата значения — фиксирует сам факт чтения часов (текущее значение не эмитится; оно уходит через 0034 vclock или видно по ts записи).

### static fn AfeyeCopyString(str, no_gc, dst, cap) (патч :71-95)
Копирует FlatContent (one-byte/two-byte) с санитацией в printable, возвращает длину; не flat → пустая строка.

### static fn AfeyeLogToString(isolate, recv) (патч :97-141; hunk @@ -245,10 +255,89)
- cap **2 000 000** (g_afeye_fnts); env-гейта НЕТ (только общий Enabled()).
- Разматывает JSBoundFunction-цепочку до 8 hop'ов (`bound_target_function`).
- JSFunction: SFI Name (cap 80), script name (cap 200), GetLineNumber → `"fnts name=%.*s script=%.*s:%d"`; иначе `"fnts receiver=non-function"`.
- Эмит `kFnToString=32`. Зачем: `Function.prototype.toString` — стандартный приём детекта нативных/подменённых функций антифрод-скриптами; hook в BUILTIN(FunctionPrototypeToString) (патч :144-152) ловит КАЖДЫЙ такой вызов.

### MicrotaskQueue::RunMicrotasks (патч :171-205; hunks @@ -217 и @@ -268)
- Начало (после early-return на пустую очередь): `EmitStr(kMicrotaskDrain=30, "microtask-start pending=%u iso=%p")`.
- Конец (после DCHECK_EQ(0,size())): `"microtask-end ran=%d iso=%p"` (processed_microtask_count).
- Пара start/end даёт границы drain-цикла для привязки всего, что случилось между ними.

---

## patches/0020-v8-wasm-streaming-exec.patch — wasm-трапы, первый вызов, streaming/кэш (kind 31/3)

Файлы: `v8/src/runtime/runtime-wasm.cc`, `v8/src/wasm/module-compiler.cc`.

### ThrowWasmError (патч :19-37; hunk @@ -99,6 +106,18)
Единственный funnel всех wasm-трапов. cap **2 000 000** (g_afeye_wasmtrap); `EmitStr(kWasmInstance=31, "wasm-trap msg=%d")` (MessageTemplate id). Env-гейта нет.

### RUNTIME_FUNCTION(Runtime_WasmCompileLazy) (патч :38-57; hunk @@ -369,6 +388,19)
Вызывается при ПЕРВОМ вызове лениво-компилируемой wasm-функции. cap **2 000 000** (g_afeye_wasmfc); `"wasm-firstcall func_index=%d module=%p"` → kind 31. Это substitute per-call dispatch: сам вызов экспорта — сгенерированный машинный код без C++ funnel (SERIES.md:21), firstcall даёт «какие индексы ran, хотя бы раз».

### AsyncStreamingProcessor::OnFinishedStream (патч :72-85; hunk @@ -3188,6 +3191,14)
streaming-компиляция завершена → `Emit(kWasmModule=3, bytes, min(size,0xFFFFF0))` — сырой модуль (аналог SyncCompile; streaming-путь иначе был бы слеп).

### AsyncStreamingProcessor::Deserialize (патч :87-101; hunk @@ -3349,6 +3360,14)
Потребление code cache → `EmitSpan(kWasmModule=3, "cached", wire_bytes, min(size,0xFFFFF0))` — тег `"cached"` отличает кэш от свежих байт; cap EmitSpan 64 КиБ режет тело (см. дырки).

---

## patches/0021-v8-payload-stack.patch — JSON.stringify payload и Error.stack (kind 16/38)

Файлы: `v8/src/builtins/builtins-json.cc`, `v8/src/execution/messages.cc`, `v8/src/execution/messages.h`.

### AfeyeJsonCopyHead (анонимный namespace, патч :24-52)
Копия FlatContent головы строки, санитария printable, cap передаётся; не flat → -1.

### BUILTIN(JsonStringify) (патч :54-92; hunk @@ -30,14 +38,72)
- Результат stringify ПЕРЕХВАТЫВАЕТСЯ: `MaybeDirectHandle afeye_result = JsonStringify(...)` вместо прямого RETURN.
- env **AFEYE_TRACE_JSON**=0 выключает; cap **2 000 000** (g_afeye_json).
- Если результат String: голова 960 байт → `EmitSpan(kFingerprint=16, tag="json-stringify len=%d replacer=%d", head)` (tag ≤64, тело ≤ 960). kind 16 + span-формат `tag\0body` — так payload (сериализованный fingerprint-объект) попадает в граф content-match (sinkfilter.rs payload_kinds).
- Зачем: JSON.stringify — главный funnel сборки payload'а перед отправкой; чистый JS-конкатенейт не ловится ничем (SERIES.md:17).

### ErrorUtils::GetFormattedStack → split (messages.cc/h, патч :95-206)
- Оригинал переименован в `GetFormattedStackImpl` (патч :151 — БЕЗ #ifdef!), новый wrapper `GetFormattedStack` (патч :159-187) определён ТОЛЬКО под V8_AFEYE; в messages.h объявление Impl тоже только под ifdef (патч :200-203). **В non-afeye сборке это compile error** (определение члена без объявления) — см. дырки.
- Wrapper: env **AFEYE_TRACE_STACK**=0 выключает; cap **2 000 000**; голова стека 960 байт (санитария) → `EmitStr(kErrorStack=38, "errstack len=%d head=%s")`, буфер 1024.
- Зачем: `new Error().stack` — способ получить caller-chain из чистого JS; SERIES.md:31 — замена frame-walk'у на lazy-compile.

---

## patches/0022-v8-introspection.patch — Date ctor, lazy-compile, wrapped-source, GOPD (kind 33/8/1/16)

Файлы: `v8/src/builtins/builtins-date.cc`, `v8/src/codegen/compiler.cc`, `v8/src/objects/js-objects.cc`.

### BUILTIN(DateConstructor) (патч :5-28; hunk @@ -63,6 +63,23)
Только когда `(args.length()-1) == 0` (вызов `new Date()` без аргументов = чтение часов). env **AFEYE_TRACE_CLOCK**=0; cap **2 000 000** (отдельный g_afeye_date_ctor); `EmitStr(kClock=33, "clock date-ctor")`.

### static fn AfeyeLogLazyCompile(Tagged<SharedFunctionInfo> sfi) (патч :54-123; hunk @@ -3061,10 +3065,86)
- cap **4 000 000** (g_afeye_lazy); env-гейта нет.
- Под DisallowGarbageCollection: SFI Name (cap 64), script name (cap 160), line → `"lazy-compile name=%.*s script=%.*s:%d"` → **EmitStr(kCallCompleted=8)** (переиспользование kind 8!).
- Хук в `Compiler::Compile` (патч :125-133) — funnel ленивой компиляции каждой функции. Даёт «callee first-execution»-сигнал (SERIES.md:31). Rust-сторона ОБЯЗАНА отличать их от call-записей: sinkfilter.rs:878 исключает `lazy-compile` из entry-индекса (SERIES.md:61 — они называют скомпилированную функцию, не исполняющую entry).

### Compiler::GetWrappedFunction (патч :137-148; hunk @@ -4258,6 +4338,11)
4-й call site AfeyeDumpScriptSource: fallback `"wrapped"` + script_details.name_obj (REPL/devtools-обёртки).

### JSReceiver::GetOwnPropertyDescriptor (патч :169-230; hunk @@ -2034,6 +2043,61)
- env **AFEYE_TRACE_GOPD**=0; cap **2 000 000** (g_afeye_gopd).
- Ключ: `it->GetName()`, если String — FlatContent cap 64, санитария.
- Текст: `"gopd holder_type=%d key=%.64s kind=accessor|data writable=%d enumerable=%d configurable=%d"` (instance_type holder'а, биты атрибутов) → EmitStr(kFingerprint=16).
- Зачем: `Object.getOwnPropertyDescriptor` — детектор-приём (проверка native-геттеров, stack accessor'ов Error и т.п.); SERIES.md:25 — GOPD-хук ловит descriptor-трапы через special-receiver dispatch (Proxy-ветка добавлена 0025).

---

## patches/0023-sink-drop-witness.patch — drop-witness (kind 39), v8-часть

Файлы (v8-часть): `v8/src/afeye/sink.cc` (:139-194), `v8/src/afeye/sink.h` (:196-207). Патч ТАКЖЕ зеркалит то же самое в `services/network/afeye_sink.{cc,h}` и `third_party/blink/renderer/platform/afeye/sink.{cc,h}` (строки 1-137) — идентичный код, kLayer другой.

### sink.h: `kSinkDrop = 39` добавлен в enum (патч :200-205).

### fn WriteDropReport(fd, dropped) (патч :147-164; вставка после EmitHello)
Формирует kind-39 запись `"sink-drop layer=v8 dropped=%llu"` (msg 96 байт) и пишет **напрямую WriteAll(fd)**, МИНУЯ ring — drop-репорт, который сам может дропнуться, бесполезен (SERIES.md:72). Заголовок тот же 16-байтный, rec[4]=kSinkDrop.

### DrainLoop: witness-цикл (патч :169-194)
Локальные `reported_drops`, `last_report_ns`; после каждой итерации drain: если `g_dropped != reported_drops` И прошло ≥ **100 мс** (`100ull*1000ull*1000ull` нс) — WriteDropReport(fd, now_dropped); reported_drops/last_report_ns обновляются ТОЛЬКО при fd>=0 (иначе повторит). Throttle ≈10/с, только когда счётчик сдвинулся. Пишется только g_dropped (ring-дропы); g_write_err в репорт не входит.

Зачем: Rust-сторона строит «dead-end-proven» только при witness'е полноты: sinkfilter.rs:1088-1094 парсит `dropped=`, :405 `drops_witnessed()`, :2056 `dead_end_witness.ring_drops_in_pid` — ноль дропов в pid = доказательство, что отсутствие связи не вызвано переполнением ring.

---

## patches/0025-v12_2-total-capture.patch — v8-часть: JIT/bytecode exec-лог, GOPD-proxy, wasm grow (kind 34/16/31)

Файлы v8-части: `v8/src/api/api.cc`, `v8/src/logging/log.cc`, `v8/src/objects/js-objects.cc`, `v8/src/wasm/wasm-objects.cc` (net-часть url_loader.cc:14-52 — cookie-attach, вне моего охвата; SERIES.md:42 — текст v12.2 про url_request_http_job.cc был ложью, фактически SetRawRequestHeadersAndNotify в url_loader.cc).

### api.cc Isolate::New: SetJitCodeEventHandler (патч :57-78; hunk @@ -10378,6 +10378,21)
Один раз на процесс (atomic exchange afeye_exec_installed): env **AFEYE_TRACE_EXEC**=0 выключает; ставится `SetJitCodeEventHandler(kJitCodeEventDefault, <пустая лямбда>)`. Смысл: установка handler'а включает поток code events через JitLogger, благодаря чему выполняется афай-блок внутри LogRecordedBuffer (ниже). Сама лямбда игнорирует все события.

### log.cc JitLogger::LogRecordedBuffer (патч :98-155; hunk @@ -878,6 +886,58)
Перед `code_event_handler_(&event)`: env AFEYE_TRACE_EXEC, cap **4 000 000** (g_afeye_exec).
- Тип: `IsCode(code) ? "jit" : "byte"` (TurboFan/Maglev-код vs bytecode/baseline).
- Имя функции: cap 80, санитария.
- Script/line: только если `ThreadId::Current() == isolate_->thread_id()` (main thread) и maybe_shared→SFI→Script; имя скрипта one-byte cap 96; `GetLineNumber(shared->StartPosition())`.
- Формат: `"exec %s %s script=%s:%d len=%u"` (тип, имя, скрипт:линия, code_len) → **EmitStr(kIsolateBirth=34)** — kind 34 переиспользован как «isolate/exec»-поток (collect.rs KINDS[34]="isolate"; sinkfilter.rs:1109-1137 считает exec_compiles/exec_jit/exec_byte/exec_wasm_code и per-script计数).
- Зачем: даёт compile-provenance — какие функции реально исполнялись (JIT-компиляция = evidence исполнения), направление вверх по графу (SERIES.md:57).

### js-objects.cc GOPD proxy-ветка (патч :157-204; hunk @@ -1991,6 +1991,43)
В `GetOwnPropertyDescriptor`, виртуальный dispatch когда holder — JSProxy: ДО вызова JSProxy::GetOwnPropertyDescriptor — env AFEYE_TRACE_GOPD, cap **2 000 000** (отдельный g_afeye_gopd_proxy), ключ one-byte cap 64 → `EmitStr(kFingerprint=16, "gopd holder=proxy key=%s")`. Ловит Proxy getOwnPropertyDescriptor-трапы (SERIES.md:25).

### wasm-objects.cc WasmMemoryObject::Grow — 3 точки (патч :205-250; hunks @@ -1118, @@ -1137, @@ -1181)
Все три успешных пути grow (shared in-place, non-shared in-place, realloc+copy) после UpdateEstimatedSize/UpdateInstances: `if (Enabled()) EmitWasmMemGrow(old_pages, new_pages|old+pages)` → kind 31 `"wasm-mem grow old=%u new=%u"` (cap 100k и env AFEYE_TRACE_WASMMEM внутри EmitWasmMemGrow, 0001). Grow-паттерн — прокси для «wasm что-то накопил» (SERIES.md:19).

---

## patches/0026-v8-wasm-memory-content.patch — содержимое wasm-памяти в момент grow/доступа (kind 4)

Файлы: `v8/src/afeye/sink.cc` (:1-29), `v8/src/afeye/sink.h` (:30-42), `v8/src/wasm/wasm-objects.cc` (:43-115).

### fn EmitWasmMemContent(mem_id, base, byte_length) (патч :9-25 → sink.cc:~331)
- env **AFEYE_TRACE_WASMMEMDUMP**=0 выключает; cap **512** дампа на процесс (g_afeye_wmdump).
- Тег: `"wasm-mem-content id=%p len=%llu"` → `EmitSpan(kWasmMemory=4, tag, base, byte_length)` — тело cap 64 КиБ (kSpanCap), truncation flag при большем.

### Call sites в wasm-objects.cc
1. Grow in-place shared (патч :47-64; hunk @@ -1126): после EmitWasmMemGrow — дамп ЖИВОГО post-grow буфера (`memory_object->backing_store()->buffer_start()`, byte_length). Комментарий v12.5: off-heap, GC не двигает — sound.
2. Grow in-place non-shared (патч :66-80; hunk @@ -1148): то же.
3. Grow realloc (патч :82-98; hunk @@ -1195): после SetManagedObject/UpdateInstances — post-copy backing store уже live через memory_object.
4. `WasmMemoryObject::GetArrayBuffer` (патч :100-114; hunk @@ -1212,6 +1236,15): дамп при каждом JS-доступе к `wasm.memory.buffer` — момент, когда JS явно берёт ArrayBuffer поверх линейной памяти.

Зачем: per-access содержимого линейной памяти нет (SERIES.md:19), но grow + buffer-доступ — точки, где содержимое с большой вероятностью содержит накопленные данные (вход/выход wasm-трансформаций).

---

## patches/0027-v8-taint-core-factory.patch — taint-ядро, ABI для blink, propagation в Factory (kind 16)

Файлы: `third_party/blink/renderer/platform/bindings/idl_member_installer.cc` (малая вставка), `v8/BUILD.gn`, новые `v8/src/afeye/taint.{cc,h}`, `v8/src/afeye/taint_abi.{cc,h}`, `v8/src/builtins/builtins-json.cc`, `v8/src/heap/factory-base.cc`, `v8/src/heap/factory.cc`.

### BUILD.gn (патч :27-52; hunk @@ -7060,6 +7060,21)
В sources добавлены: taint.cc/h, taint_abi.cc/h (extern "C" ABI — blink не может включать v8-internal headers), **causality.cc/h (0031)** и **gc_witness.cc/h (0032)** — 0027 пред-регистрирует файлы ПОЗДНИХ патчей; серия применима только целиком (иначе GN не найдёт sources).

### taint.h (патч :230-298)
- `typedef uint32_t TaintTag`; enum TaintSource: kSrcNone=0, kSrcFingerprint=1<<0, kSrcClock=1<<1, kSrcInput=1<<2, kSrcRandom=1<<3, kSrcStorage=1<<4, kSrcNetwork=1<<5, kSrcStack=1<<6, kSrcWasm=1<<7, kSrcOther=1<<31.
- enum TaintKeySpace: kKeyHeap=0, kKeyWasm=1, kKeyStack=2, kKeyContext=3. kTaintSourceBits=32.
- API: TaintEnabled/TaintSet/TaintGet/TaintPropagate/TaintClear/TaintOnGCEpilogue/TaintEmitSink/TaintLiveHeapTagUnion/TaintSunkUnion/TaintDropped.

### taint.cc (патч :53-229)
- Хранилище: **kTaintSlots = 1<<20** (1M слотов) `TaintSlot { atomic u64 key; atomic u32 tag; }` — открытая адресация, static-массив ≈16 МиБ.
- env **AFEYE_TAINT**=0 выключает всё (TaintEnvOn, :88-94); TaintEnabled = Enabled() && TaintEnvOn (:143).
- `CompositeKey(space,key) = (space+1)<<61 | key&(2^61-1)` (:96-98) — space вшит в ключ, key = адрес heap-объекта.
- `HashKey` — FNV-1a 8 байт → маска (:100-107).
- `FindSlot(ck, for_insert)` (:109-125): линейный probing, max_probe = slots>>6 = 16384; пустой слот при insert возвращается сразу (first_empty).
- `AcquireSlot` (:127-139): CAS key 0→ck; g_taint_live++.
- `TaintSet` (:145-157): OR-тег CAS-циклом; нет слота → **g_taint_dropped++** (witness-счётчик, читается TaintDropped).
- `TaintGet`/`TaintPropagate`/`TaintClear` (:159-177): propagate = Get(src) → Set(dst) если не None.
- `TaintOnGCEpilogue(compacting)` (:179-191): только compacting — очищает ВСЕ слоты кроме kKeyWasm (heap-адреса после компакции невалидны; wasm-ключи — off-heap buffer_start, стабильны). Вызывается из 0032 GCEpilogueWitness.
- `TaintEmitSink(sink, space, key, tag)` (:193-203): `EmitStr(kFingerprint=16, "taint-sink %s space=%u key=%llx tag=%x")` + `g_sunk_union |= tag`.
- `TaintLiveHeapTagUnion` (:205-216): OR по всем живым heap-слотам; `TaintSunkUnion` (:218-220): g_sunk_union. Пара feeding 0032 taint-swept/taint-deadend witness.

### taint_abi.{cc,h} (патч :299-373)
extern "C" (для blink/network TU без v8 headers; default visibility — комментарий BUILD.gn :41): `afeye_taint_tag_string(key, source_bit)` → TaintSet(kKeyHeap,...); `afeye_taint_get_string(key)`; `afeye_taint_propagate_string(dst,src)`; `afeye_taint_active()` → TaintEnabled()?1:0; `afeye_taint_emit_sink(sink,space,key,tag)`.

### idl_member_installer.cc (патч :5-26)
В AfeyeCaptureValue (введён 0024), String-ветка: если `afeye_taint_active()` — `afeye_taint_tag_string(*str, kSrcFingerprint=1)`: каждое строковое ЗНАЧЕНИЕ, прочитанное через DOM API thunk, помечается как fingerprint-источник. Это точка РОЖДЕНИЯ тейнта.

### builtins-json.cc (патч :374-398; hunk @@ -100,6 +101,12)
В JsonStringify после span-эмита (0021): `TaintSet(kKeyHeap, afeye_s.address(), kSrcFingerprint)` — результат сериализации fingerprint-объекта тейнтится (дальше распространяется через Factory-швы).

### factory-base.cc (патч :399-470)
- Хелперы (анонимный ns, :417-437): `AfeyeStrKey(s)=s.address()`; `AfeyeTaintConcat(result,left,right)` — tag = Get(left)|Get(right), Set(result) если не None; `AfeyeTaintCopy(result,src)` — TaintPropagate.
- `NewConsString` — ТРИ точки: flat-one-byte copy-путь (:442-450, hunk @@ -997), flat-путь через WriteToFlat (:452-460, hunk @@ -1009), настоящий ConsString (:462-470, hunk @@ -1041). Конкатенация — основной переносчик тейнта в JS-строках.

### factory.cc Factory::NewProperSubString (патч :472-522)
- Не-slice путь (:486-505, hunk @@ -1470): NewCopiedSubstring → Get(src) → Set(result).
- SlicedString путь (:508-520, hunk @@ -1496): после set_parent/set_offset — Get(str) → Set(slice). Substring/slice наследуют тейнт родителя.

Почему Factory: это единственные funnel'ы создания строк из других строк (concat/substring) в C++ — минимум хуков на максимум покрытия string-dataflow. Не покрыто (честно): SlicedString-чтение через родителя без нового объекта, Rope/external строки, не-строковые значения (Number/Object) — тейнт только строковый.

---

## patches/0028-v8-wasm-shadow-memory.patch — побайтовый taint-shadow wasm-памяти (kind 4) + codegen-хуки Liftoff. **KNOWN-UNWIRED (SERIES.md:2)**

Файлы: `v8/BUILD.gn`, новые `v8/src/afeye/wasm_shadow.{cc,h}` (605+57 строк), `v8/src/wasm/baseline/liftoff-compiler.cc`, `v8/src/wasm/wasm-objects.cc`.

### wasm_shadow.cc константы и состояние (патч :44-115)
- kMaxTracked=**64** памяти (открытая адресация, kTombstone=(void*)1 — освобождённый слот); kMaxShadowBytes=**256 МиБ** на shadow-регион; kMaxBulkBytes=**8 МиБ** cap bulk-операций; kMigrateCapBytes=**32 МиБ** cap миграции при rekey; kEmitCap=**100 000** эмитов; kEmitBodyCap=**64 КиБ** тело эмита.
- `ShadowEntry { atomic u8* shadow; atomic size_t len; atomic void* mem_id; atomic bool dirty; }`; счётчики g_shadow_dropped/emitted/live.
- thread_local: **t_store_taint** (тег для следующего store), **t_load_taint** (результат последнего load), **t_last_sig** (dedup эмитов), **t_staged** (StagedBulk: op/dst_base/dst_off/src_base/src_off/len).
- ops enum: kOpNone/Load/Store/Copy/Fill/Init/ReKey.
- env: **AFEYE_WASM_SHADOW**=0 — ядро выключено (WasmShadowEnabled = Enabled() && ShadowEnvOn, :305); **AFEYE_TRACE_WASMSHADOW**=0 — эмиты выключены (EmitOn, :106-112).
- HashId: (ptr>>12)*0x9E3779B97F4A7C15 >> 51 & 63.

### Ключевые функции
- `SlotMapping` (:167-182): mmap 256 МиБ PROT_READ|WRITE, PRIVATE|ANON|NORESERVE — 1 байт тега на байт памяти, lazily.
- `Publish(e, byte_length, must_zero)` (:184-193): len=min(byte_length,256МиБ), при must_zero — memset 0.
- `NarrowTag/WidenTag` (:195-211): 32-битный TaintTag → 1 байт: биты 0-6 = именованные источники (0x7F), бит 7 = «wasm или other» (kSrcWasm|kSrcOther схлопнуты).
- `Resolve(mem_id,&off,&size,&len)` (:213-224): FindEntry → region; clamp size к len-off; null если вне.
- `ReduceRange(p,n)` (:231-235): OR по байтам → WidenTag.
- `Sig(op,a,b,c)` (:238-248): FNV-1a от 4 u64; 0→1.
- `EmitShadow(tag,base,off,n,sig)` (:250-269): гейты EmitOn/100k cap/**t_last_sig dedup** (одинаковая сигнатура подряд — один эмит); тело = shadow-байты [off,off+min(n,64КиБ)); base==null → 1 байт kNil. → `EmitSpan(kWasmMemory=4, tag, ...)`.
- `ApplyStoreTag` (:271-301): augment → OR-побайтово, иначе memset тега; b!=0 → MarkDirty; эмит `"wasm-shadow-store off=%llu len=%llu taint=0x%x was=0x%x erase=%d atomic=%d"` или fill-вариант; **erase=1 когда tag==0 && before!=0** (стейт-свидетельство стирания).
- `ShadowAlloc(mem_id, byte_length)` (:307-331): идемпотентный claim+mmap+Publish; вызывается из WasmMemoryObject::New.
- `ShadowGrow` (:333-340): расширение len in-place (ключ не меняется).
- `ShadowReKey(old,new,len)` (:342-415): при realloc-grow — claim нового слота, memmove тегов (cap 32 МиБ, truncated→CountDrop), zeroing старого, tombstone, эмит `"wasm-shadow-rekey old=0x%llx new=0x%llx len migrated truncated"`.
- `ShadowFree` (:417-428): memset 0, len=0, tombstone, live--.
- `ShadowGet/ShadowSetRange/ShadowGetRange` (:430-457): внешний доступ к shadow (SetRange OR'ит теги, GetRange — Reduce). **Вызовов ShadowSetRange/ShadowGet в патчах НЕТ** — мёртвый API.
- `WasmShadowOnLoad(mem_id,off,size)` (:459-476): Resolve → ReduceRange → **t_load_taint = t** (handoff для JS-boundary seam) → при t!=0 эмит `"wasm-shadow-load off len taint"`.
- `WasmShadowOnStore(mem_id,off,size,augment)` (:478-491): before=ReduceRange; t = **t_store_taint** (забирается и обнуляется); ApplyStoreTag.
- `WasmShadowStageCopy/Fill/Init` (:493-547): пишут t_staged (op, базы, офсеты, len cap 8 МиБ) — НЕ применяют сразу.
- `WasmShadowCommit` (:549-612): применяет staged: Init → memset 0 + эмит erase если before!=0; Fill → ApplyStoreTag с t_store_taint; Copy → ReduceRange(src) → memmove тегов → эмит `"wasm-shadow-copy dst_off src_off len taint"` при src_tag!=0.
- `WasmShadowPushStoreTaint(tag)` (:614): единственный способ передать тейнт JS-значения в store. **ВЫЗОВОВ НЕТ НИ В ОДНОМ ПАТЧЕ** → t_store_taint всегда 0 → все store/load/fill/init эмиты невозможны (tag==0&&before==0 → return в ApplyStoreTag; load ReduceRange всегда 0). Единственный достижимый эмит — `wasm-shadow-rekey` (не зависит от тейнта). Это и есть SERIES.md:2 «known-unwired».
- `WasmShadowConsumeLoadTaint` (:616-620): t_load_taint забирается и обнуляется — потребителей тоже нет в патчах.
- `WasmShadowDropped` (:622-624): g_shadow_dropped.

### liftoff-compiler.cc — codegen-хуки (патч :693-1059)
- `afeye_shadow_active_` (:1041-1055; hunk @@ -11319): const bool = WasmShadowEnabled(), читается ОДИН РАЗ на компиляцию функции — двухуровневый гейт: compile-time (ноль инструкций в не-afeye сборке, codegen байт-в-байт сток) + runtime (проба таблицы внутри callout). В non-afeye — static constexpr false + пустые stub-методы (:824-833), поэтому call sites без #ifdef.
- `AfeyeCallC(args, ext_ref)` (:714-718): CallC + SpillAllRegisters.
- `AfeyeShadowAccess(mem_index, index, offset, size, is_store, augment)` (:720-762): только 64-бит (kSystemPointerSize!=8 → return); SpillAllRegisters; pin index+memory start; эффективный адрес = offset + index (i64 для memory64, i32 иначе); CallC → WasmShadowOnStore(mem,eff,size,augment) или WasmShadowOnLoad(mem,eff,size).
- `AfeyePinToFrame(slot)` (:764-775): reg→spill slot (VarState в cache_state уже НЕТ после pop, SpillAllRegisters его не спасёт — pin вручную).
- `AfeyeShadowStageCopy/StageOne/ShadowCommit` (:777-823): CallC stage-функций и Commit без аргументов.
- Точки instrumented (все под `if (afeye_shadow_active_)`):
  - LoadMem (:838-850, hunk @@ -4518), LoadTransform (:853-864, @@ -4566 — access_size, не type.size(): lane уже реального footprint), LoadLane (:867-875, @@ -4610), StoreMem (:878-887, @@ -4675 — augment=false, store ЗАМЕНЯЕТ байты), StoreLane (:890-897, @@ -4714), atomic store (:900-909, @@ -6400 — augment=false: plain store значения), AtomicLoadMem (:911-920, @@ -6436), AtomicBinop (:922-933, @@ -6487 — **augment=true**: RMW комбинирует старое значение), AtomicCompareExchange (:935-949, @@ -6565 — augment=true, консервативно для успеха и провала; IA32-ветка не хукается — 32-бит, callout'ы всё равно ничто).
  - MemoryInit (:952-986, @@ -7557): STAGE до загрузки instance_data (иначе C-call затрёт регистр и реальный вызов получит мусор), все операнды pin'ятся; COMMIT ПОСЛЕ OOB-trap-jump (:980-985) — только успешно wykonавшийся init пишет тейнт-поток.
  - MemoryCopy (:989-1012, @@ -7620): stage-copy (dst_mem, src_mem), commit после trap-jump.
  - MemoryFill (:1014-1038, @@ -7665): stage-one (is_init=false), commit после trap-jump.

### wasm-objects.cc (патч :1060-1129)
- `WasmMemoryObject::New` (:1072-1083, hunk @@ -855): `ShadowAlloc(backing_store->buffer_start(), byte_length())` — ключ shadow = АДРЕС БУФЕРА (off-heap, GC-стабилен).
- Grow in-place shared/non-shared (:1085-1107): `ShadowGrow(buffer_start, byte_length)` — ключ не меняется, регион расширяется.
- Grow realloc (:1108-1125): до SetManagedObject запоминаются afeye_old_base/afeye_new_base; после UpdateInstances — `ShadowReKey(old, new, new_byte_length)` (миграция тегов между буферами).

---

## patches/0031-v8-async-causality.patch — причинность async-задач (kind 16, текст "causality ...")

Файлы: новые `v8/src/afeye/causality.{cc,h}` (299+52), `v8/src/builtins/builtins-microtask-queue-gen.cc`, `v8/src/builtins/builtins-promise-gen.cc`, `v8/src/execution/microtask-queue.cc`, `v8/src/runtime/runtime-promise.cc`, `v8/src/runtime/runtime.h`.

### Состояние (causality.cc, патч :22-135)
- env **AFEYE_CAUSALITY**=0 выключает (CausalityEnvOn :24-30; CausalityEnabled = Enabled() && env :165).
- g_next_id — монотонный счётчик trace_id (id начинаются с 1).
- **TaskSlot table: kTaskSlots = 1<<16** (64k), `TaskSlot { atomic u64 key; atomic u64 tid; }`, сентинелы kTaskKeyEmpty=0, kTaskKeyDead=~0; глобальный спин-лок TaskLock (yield/64). FNV-хеш ключа, probing max = slots>>4 = 4096, Dead-слоты переиспользуются.
- Witness-счётчики: **g_dropped** (нет слота при enqueue), **g_imbalance** (переполнение/исчерпание scope-стека, unbalanced exit, scope-rebalance losses), **g_misses** (run без найденного tid), **g_minted** (сколько id отчеканено).
- thread_local: g_ambient (текущий trace_id), g_scope[**kScopeCap=256**] (стек предыдущих ambient), g_depth, g_skipped.

### Эмит (патч :124-161)
- `EmitCausality(what, tid, parent)`: `EmitStr(kFingerprint=16, "causality %s tid=%llx parent=%llx")`.
- `EmitWitnessIfChanged()`: если любой из 4 счётчиков сдвинулся — `EmitCausality("witness dropped=%llu imbalance=%llu misses=%llu minted=%llu", 0, 0)`; снапшоты g_wit_* обновляются. Вызывается из CausalityScopeReset (начало и конец).

### API и семантика (патч :165-300)
- CausalityCurrent/Enter/ExitRestore (:167-175) — прямой ambient-контроль.
- CausalityNewRoot (:177-181): id = ++g_next_id; g_minted++.
- CausalityLink(parent,child) (:183-190): эмит `"causality link edge=<p>-><c>"` (tid=child, parent=parent).
- CausalityNewChild(parent) (:197-201): NewRoot + Link если parent!=0.
- **CausalityCaptureEnqueue(task_key)** (:203-215): parent = g_ambient (контекстenqueue'а); child = NewChild(parent); StoreTaskTid(key, child) — неуспех → g_dropped++; эмит `"enqueue task=<key>"` tid=child parent=parent.
- **CausalityEnterTask(task_key)** (:217-240): depth>=256 → g_imbalance++, g_skipped++, return 0; TakeTaskTid (забирает tid и метит слот Dead); push ambient в scope; tid==0 → **g_misses++**, эмит `"run-miss task=<key>"`; иначе ambient=tid, эмит `"run task=<key>"`.
- **CausalityExitTask(task_key)** (:242-260): если g_skipped>0 — декремент, эмит `"exit task="` (tid=parent=ambient) без pop; depth==0 → g_imbalance++, `"exit-unbalanced"`; иначе pop scope, эмит `"exit task=<key>"` tid=ambient parent=prev, ambient=prev.
- CausalityNotePromise (:262-268): `"promise-new promise=<key>"` tid=ambient.
- CausalityScopeDepth/ScopeReset (:270-288): reset до base depth после drain: lost = (depth-base)+skipped → imbalance += lost, эмит `"scope-rebalance lost=%llu base=%llu"`, восстановление depth/ambient; EmitWitnessIfChanged до и после.
- CausalityDropped/Imbalance/Misses/Minted (:290-300) — readers.

### Хуки
1. **TF_BUILTIN(EnqueueMicrotask)** (builtins-microtask-queue-gen.cc, патч :368-376; hunk @@ -777): после StoreNoWriteBarrier(size+1) — `CallRuntime(kAfeyeCausalityEnqueueMicrotask, context, microtask)` — CSA-путь enqueue (JS-вызовы microtask-queue).
2. **TF_BUILTIN(RunMicrotasks)** (патч :378-393; hunk @@ -878): вокруг `RunSingleMicrotask` — Enter/Exit CallRuntime'ы (ключ = указатель microtask-объекта).
3. **MicrotaskQueue::EnqueueMicrotask** (C++, microtask-queue.cc, патч :427-436; hunk @@ -165,6 +166,11): после ring_buffer_[...]=ptr — CausalityCaptureEnqueue(microtask.ptr()) — C++-путь enqueue (embedder/внешние microtasks).
4. **AllocateJSPromise** (builtins-promise-gen.cc, патч :399-412; hunk @@ -31,8): после Allocate — `CallRuntime(kAfeyeCausalityPromiseNew, context, promise)` — рождение каждого JSPromise (ключ = heap-адрес).
5. **CausalityDrainScope** (microtask-queue.cc, патч :443-462): RAII в MicrotaskQueue::RunMicrotasks — ctor запоминает CausalityScopeDepth(), dtor вызывает ScopeReset(base) — ребаланс после каждого drain (утечки scope из-за исключений/termination не копят imbalance молча).
6. **runtime-promise.cc** (патч :484-510): четыре RUNTIME_FUNCTION — AfeyeCausalityEnqueueMicrotask/EnterMicrotask/ExitMicrotask/PromiseNew, каждый DCHECK_EQ(1, args.length()), передают args[0].ptr() как u64-ключ.
7. **runtime.h** (патч :514-548; hunk @@ -880 и @@ -913): `FOR_EACH_INTRINSIC_AFEYE_CAUSALITY` — 4 intrinsic'а `F(имя, 1, 1, RuntimeCallProperty::kCannotTriggerGC)`, добавлен в FOR_EACH_INTRINSIC_RETURN_OBJECT_IMPL после WEAKREF.

Зачем ключ = указатель на microtask/promise: уникальный на время жизни объекта, не требует полей в JSPromise; Dead-сентинел освобождает слот после run. **Потребителя на Rust-стороне НЕТ** (grep 'causality' по src/ — пусто): записи kind 16 "causality ..." не парсятся (см. дырки).

---

## patches/0033-v8-ignition-bytecode-trace.patch — ЯДРО: тотальный трейс байткода Ignition (kind 40) + vclock

Файлы: новый `v8/src/afeye/bcrec.h` (360 строк), `v8/src/afeye/sink.{cc,h}` (vclock), `v8/src/interpreter/interpreter-assembler.cc` (2 хука), `v8/src/runtime/runtime-trace.cc` (runtime-функция), `v8/src/runtime/runtime.h` (intrinsic).

### sink.cc/sink.h: виртуальные часы (патч :367-413)
- sink.cc (hunk @@ -219,6 +219,16, после NowNs): `std::atomic<uint64_t> g_vclock_ns{0}`; **`extern "C" uint64_t afeye_vclock_ns(void)`** — relaxed load; **`void VclockTick(uint64_t ns)`** — relaxed fetch_add. Атрибута visibility в патче НЕТ — SERIES.md:88 утверждает default visibility (renderer-бинарник общий для blink и v8); [INFERENCE] работает, если сборка не ставит -fvisibility=hidden глобально (в extra_cflags его нет, build-chromium.sh:66-69).
- sink.h: `kBytecodeTrace = 40` в enum (патч :396); объявления afeye_vclock_ns/VclockTick + комментарий (:400-411).

### bcrec.h — wire-формат v3, header-only, НОЛЬ v8-зависимостей (патч :1-366 → bcrec.h:1-360)
Дизайн-инвариант (bcrec.h:4-15 = патч :10-21): tools/bcrec_main.cc компилируется g++ ОТДЕЛЬНО от хрома против bcrec.h+sink.cc, ИЗВЛЕЧЁННЫХ ИЗ ПАТЧЕЙ; tests/bcrec_roundtrip.rs гоняет его вывод через продакшн collect.rs + bctrace.rs — энкодер и декодер доказаны байт-в-байт БЕЗ сборки chromium.

- `kKind = 40` (патч :33).
- **struct Hdr — ровно 72 байта, LE, без padding** (патч :36-57 → bcrec.h:30-51; static_assert :57):

| поле | тип | смещение | инструкция | func-def | meta |
|------|-----|----------|-----------|----------|------|
| opcode | u8 | 0 | опкод после prefix'а (Wide/ExtraWide уже сняты диспетчером) | 0xff | 0xfe |
| scale | u8 | 1 | OperandScale enum raw (1/2/4) — codegen-константа handler'а, точная для Wide/ExtraWide | 0 | 0 |
| n_payload | u8 | 2 | число payload-блоков (saturate 255; парсер идёт структурно до конца части) | 0 | 0 |
| flags | u8 | 3 | kFlag* | kFlagFuncDef | 0 |
| offset | u32 | 4 | логический bytecode offset (одинаков на всех частях — glue key) | байтовая позиция части в blob | позиция части |
| func_id | u32 | 8 | MakeFuncId (GC-стабильный) | func_id | 0 |
| line | u32 | 12 | **isolate tag** (атрибуция результата не пересекает изолейты при общем pid) | start line функции | 0 |
| acc | u64 | 16 | СЫРОЕ tagged-слово аккумулятора | полная длина blob | длина blob |
| regs[6] | u64×6 | 24 | сырые слова первых 6 input-регистров | 0 | 0 |

- Флаги (патч :59-61): kFlagFuncDef=1, **kFlagCont=2** (есть ещё части), kFlagAccPayload=4 (в payload есть значение аккумулятора). Спец-опкоды: kOpFuncDef=0xff, kOpMeta=0xfe (:62-63).
- **Framing payload-блоков: `[u8 tag][u32 len][len bytes]`**; kBlockPrefixSize=5 (:85). Тип значения — ВСЕГДА из тега, никогда из длины.
- **PayloadTag** (патч :67-83 → bcrec.h:61-77): 0=kTagAccStr (String 8-bit), 1=kTagAccF64 (8 сырых бит f64), 2=kTagAccSmi (4 байта int32), 3=kTagReg ([u16 reg_index][u64 raw tagged word]), 4=kTagRegStr ([u16][8-bit bytes]), 5=kTagRegF64 ([u16][8 бит f64]), 6=kTagRegSmi ([u16][4 int32]), 7=kTagOperand ([u8 operand_index][u64 engine-decoded value]; для регистровых операндов value = индекс регистра, signed), 8=kTagCpStr (только func-def blob), 9=kTagCpF64, 10=kTagCpRaw, 11=kTagAccStr16 (UTF-16LE), 12=kTagRegStr16 ([u16][UTF-16LE]). Плюс kCpTagStr16=13 для constant pool (патч :247).
- kSinkRecordCap = (1<<20)-16 (:89) — максимум payload на одну sink-запись (sink wire-header 16 байт).
- Put/Get U16/U32/I32/U64 через memcpy (:91-115).
- **MakeFuncId(script_id i32, literal_id i32, start_pos i32, isolate_tag u32)** (:120-133): 16 байт LE → FNV-1a (offset basis 1469598103934665603, prime 1099511628211) → `(u32)(h >> 16)`. Только GC-неподвижные факты: SFI может двигаться, id стабилен весь run (старый hash(sfi.ptr()) расщеплял поток функции на два id — SERIES.md:86).
- AppendBlock (:136-144): resize + tag + u32 len + memcpy; БЕЗ cap — u32 len покрывает любую JS-строку.
- **class InstrBuilder** (:147-237): Begin(opcode,scale,offset,func_id,iso_tag,acc_word) — memset hdr, поля, payload_.clear(); Operand(index,value) — блок [u8 idx][u64] tag7; Reg(index,word) — [u16][u64] tag3 + **заполняет hdr_.regs[0..6]** (первые 6); RegStr(index,bytes,n,utf16) — [u16][bytes] tag4/12; RegF64 [u16][u64 bits] tag5; RegSmi [u16][i32] tag6; AccStr/AccF64/AccSmi — tag0|11/1/2 + **hdr_.flags |= kFlagAccPayload**; FinishHdr — n_payload=min(blocks,255).
- **Func-def blob layout** (:240-287): `[u32 bc_len][u32 name_len][u32 cp_bytes][i32 frame_size][u32 param_count]` (head=24, используются 20 байт) `| bc bytes | name bytes | cp entries`; cp entry = framed block: строки tag 8/13 (байты), f64 tag 9 (8 байт), raw tag 10 (8 байт). FuncDefBuilder::Build собирает cp через AppendBlock, затем blob.
- **Meta blob layout** (:290-330): `[u16 n_bytecodes][i32 reg_file_start_offset]`, на каждый bytecode: `name\0 u8 n_ops u8 flags u8 acc_use`, затем 3 scale × (`u8 total_size`, n_ops × (`u8 operand_type`, `u8 operand_offset`)); в конце `[u16 n_runtime_fns]` и `name\0` на каждую. MetaBuilder: Begin/Opcode/Scale/Operand/RuntimeNames/RuntimeName.
- **EmitSplit<EmitFn>(base_hdr, payload, n, offset_is_position, emit)** (:337-360): cap = kSinkRecordCap - 72; n<=cap → одна часть без kFlagCont; иначе части по cap, все кроме последней с kFlagCont, при offset_is_position hdr.offset = позиция части (blob'ы), иначе логический offset сохраняется на всех частях (инструкции).

### interpreter-assembler.cc — ДВЕ точки хука (патч :415-454)
1. **Конструктор InterpreterAssembler** (hunk @@ -48,6 +48,18, патч :419-437): в тело конструктора (после инициализации made_call_/reloaded_frame_ptr_/bytecode_array_valid_) вставлен
   `CallRuntime(Runtime::kAfeyeTraceBytecodeEntry, GetContext(), BytecodeArrayTaggedPointer(), SmiTag(BytecodeOffset()), GetAccumulatorUnchecked(), SmiTag(IntPtrConstant(operand_scale_)))`.
   Почему здесь: конструктор вызывается ГЕНЕРАТОРОМ для каждого bytecode-handler — CallRuntime компилируется ВНУТРЬ каждого handler'а; диспетчеризация прыгает в handler → запись на каждую инструкцию. `operand_scale_` — codegen-константа handler'а, поэтому Wide/ExtraWide несут настоящий scale. Ранний выход runtime-функции при выключенном sink = одна загрузка + branch (комментарий :428-429).
2. **InlineShortStar** (hunk @@ -1381,6 +1393,16, патч :438-454): тот же CallRuntime, scale жёстко `OperandScale::kSingle`.
   Почему ВТОРОЙ хук обязателен: Star0-Star15 инлайнятся в ПРЕДЫДУЩИЙ handler через StarDispatchLookahead и через конструктор НЕ проходят — без второго хука самые частые инструкции JS (присваивания в локальные регистры) слепые. Стоковый V8_TRACE_UNOPTIMIZED стоит в тех же двух точках по той же причине (SERIES.md:83; в патче оба хука вставлены непосредственно перед `#ifdef V8_TRACE_UNOPTIMIZED`-блоками).

### runtime.h — intrinsic (патч :901-928)
`FOR_EACH_INTRINSIC_AFEYE(F, I) = F(AfeyeTraceBytecodeEntry, 4, 1, RuntimeCallProperty::kCannotTriggerGC)` под V8_AFEYE, иначе пусто; добавлен в FOR_EACH_INTRINSIC_TRACE (hunk @@ -215,7 +223,8). 4 аргумента, 1 возвращаемое, GC не триггерит (внутри — DisallowGarbageCollection).

### runtime-trace.cc — реализация (патч :455-899; hunk @@ -114,6 +132,416)
Includes (:463-480): bcrec.h, sink.h, bytecode-decoder.h, bytecode-operands.h, bytecode-register.h, fixed-array-inl.h, heap-number.h, script-inl.h, shared-function-info.h, string-inl.h, trusted-object.h.

Вспомогательные (анонимный namespace, целевые строки runtime-trace.cc ≈135-547):
- `AfeyeBcOff()` (:501-507): env **AFEYE_TRACE_BYTECODE**=0 — выключает ТОЛЬКО трейс (весь остальной afeye жив).
- `AfeyeVclockOn()` (:509-515): env **AFEYE_VIRTUAL_CLOCK** — ВКЛ если задан, непуст, первый символ != '0' (дефолт ВЫКЛ).
- `AfeyeVclockNsPerInstr()` (:517-524): env **AFEYE_VCLOCK_NS_PER_INSTR**, strtoull, <=0 → **дефолт 10 нс**.
- `AfeyeIsoTag(isolate)` (:526-529): `(u32)((uintptr(isolate) >> 3) & 0xffffffff)` — тег изолейта (Hrd.line).
- **Dedupe func-def**: `AfeyeSeenKey {u32 id; u32 len;}` + hash (id<<32|len), `thread_local std::unordered_set g_afeye_seen` (:531-549) — ТОЧНЫЙ, неограниченный (не 16k-слотовая таблица которая молча скипает — SERIES.md:86); перекомпиляция с той же (id, bc_len) не ре-эмитит, с другой длиной — эмитит.
- `AfeyeStringBytes(obj, out, *utf16, no_gc)` (:551-575): String → FlatContent → 8-bit (memcpy) или two-byte (**UTF-16LE побайтово PutU16**), ПОЛНАЯ длина без cap; возвращает число байт; не-String/не-flat → 0.
- `AfeyeEmit(isolate, hdr, payload, n)` (:577-587): thread_local scratch vector (resize 72+n, без 1-МиБ стековых буферов, ноль heap-аллокаций кроме роста scratch), memcpy hdr+payload → `v8::afeye::Emit(kBytecodeTrace=40, NowNs(), buf, size)`.
- **`AfeyeEmitMeta(isolate)`** (:589-656): ОДИН РАЗ НА ПРОЦЕСС (atomic CAS done). MetaBuilder: n_bytecodes = Bytecodes::kBytecodeCount, reg_file_start = Register::kRegisterFileStartOffset. На каждый bytecode b: nops = NumberOfOperands; флаги opf: bit0=IsJump; **подтип прыжка в битах 3-4**: JumpLoop → 2<<3, IsJumpImmediate → 1<<3, IsJumpConstant → 3<<3, иначе (switch) → 4<<3; bit5 = условный (все jump кроме Jump и JumpLoop); bit1 = Returns; bit2 = MakesCallAlongCriticalPath; acc_use = GetImplicitRegisterUse(bc) (биты: 1 читает acc, 2 пишет acc, 4 clobbers, 8 short-star — по bctrace.rs:48-49). Затем 3 scale (kSingle/kDouble/kQuadruple) × (Size(bc,scale), на каждый операнд (GetOperandType, GetOperandOffset)). Затем runtime-таблица: RuntimeNames(kNumFunctions) + имена FunctionForId ("" если null). Эмит: Hdr{opcode=kOpMeta, acc=blob size} → EmitSplit(offset_is_position=true).
  Порядок байт meta-blob: `[u16 n_bc][i32 reg_start] (name\0 n_ops flags acc_use (u8 size (u8 type u8 off)*n_ops)*3)*n_bc [u16 n_rt] (name\0)*n_rt`.
- **`AfeyeEmitFuncDef(isolate, arr, sfi, func_id, no_gc)`** (:658-746): bc_len<=0 → выход. Script: line=GetLineNumber(StartPosition) (clamp 0), script_id=sc->id(), имя скрипта → AfeyeStringBytes (ПОЛНЫЕ байты). **Constant pool**: `arr->raw_constant_pool()` — Union<Smi, TrustedFixedArray>: **guard `if (!IsSmi(raw_pool))`** (пустой пул — Smi; deref как массива крэшит release-рендерер — комментарий :680-681 и SERIES.md:86). На каждый элемент: String → tag 8/13 + байты; HeapNumber → tag 9 + 8 бит f64 (memcpy); иначе → tag 10 + 8 байт `cv.ptr()` (raw tagged word). CpSpan-массив (tag/data/len) собирается из scratch-буферов (cp_off/cp_tags/cp_lens). FuncDefBuilder::Build(bc = GetFirstBytecodeAddress(), bc_len, name, frame_size(), parameter_count(), spans). Hdr{opcode=kOpFuncDef, flags=kFlagFuncDef, func_id, line=start line, acc=blob size} → EmitSplit(position=true).
  Blob: `[u32 bc_len][u32 name_len][u32 cp_bytes][i32 frame_size][u32 param_count] | ВЕСЬ байткод сырыми байтами | имя скрипта | cp-блоки`.

**RUNTIME_FUNCTION(Runtime_AfeyeTraceBytecodeEntry)** (патч :750-894; runtime-trace.cc ≈397-541) — по шагам:
1. `!Enabled()` → return undefined (early-out = одна загрузка+branch на инструкцию при выключенном sink).
2. `AfeyeBcOff()` → return undefined.
3. `DisallowGarbageCollection no_gc`; DCHECK_EQ(4, args.length()); аргументы: [0] BytecodeArray (CheckedCast), [1] bytecode_offset smi, [2] accumulator Object, [3] scale_raw smi.
4. **Если AfeyeVclockOn() → VclockTick(AfeyeVclockNsPerInstr())** — инкремент виртуальных часов на каждую инструкцию (0034 читает). ВНИМАНИЕ: шаг 2 РАНЬШЕ — при AFEYE_TRACE_BYTECODE=0 vclock НЕ тикает (см. дырки).
5. AfeyeEmitMeta(isolate) (одноразово).
6. `offset = bytecode_offset - BytecodeArray::kHeaderSize + kHeapObjectTag`; вне [0, arr->length()) → return (BytecodeOffset() — Smi-позиция внутри объекта, перевод в логический offset).
7. `pc = GetFirstBytecodeAddress() + offset`; `op_byte = *pc`; `bc = FromByte(op_byte)`. Комментарий (:782-783): scale — codegen-константа handler'а; на pc стоит РЕАЛЬНЫЙ опкод, Wide/ExtraWide prefix'ы уже съедены диспетчером.
8. Кадр: `JavaScriptStackFrameIterator` → `UnoptimizedJSFrame` → `fn = frame->function()` → `sfi = fn->shared()`; iso_tag; script_id (IsScript ? id : -1); **func_id = MakeFuncId(script_id, sfi->function_literal_id(), sfi->StartPosition(), iso_tag)**.
9. Dedupe: `g_afeye_seen.insert({func_id, arr->length()})` — при успехе AfeyeEmitFuncDef (один раз на функцию/поток).
10. `InstrBuilder ib; ib.Begin(op_byte, scale_raw, offset, func_id, iso_tag, acc.ptr())` — сырое tagged-слово аккумулятора в Hdr.acc.
11. **Операнды — ДЕКОДИРУЕТ ДВИЖОК** (:811-869): на каждый i из NumberOfOperands(bc): OperandType ot; operand_start = pc + GetOperandOffset(bc,i,scale).
    - **Регистровый input-тип**: `BytecodeDecoder::DecodeRegisterOperand` → first Register; count: для kRegList — следующий операнд декодится как kRegCount (DecodeUnsignedOperand), иначе GetNumberOfRegistersRepresentedBy(ot). На каждый регистр j: `frame->ReadInterpreterRegister(ridx)` → `ib.Reg(ridx, val.ptr())` (сырое слово; первые 6 также в Hdr.regs) + если IsString → **ib.RegStr полные байты** (str_scratch thread_local), IsHeapNumber → ib.RegF64 (биты), IsSmi → ib.RegSmi. Затем `ib.Operand(i, first.index())` — сам декодированный индекс регистра (signed).
    - **Не-регистровый**: DecodeUnsignedOperand + DecodeSignedOperand; эмитится **signed-значение** `ib.Operand(i, sv)` (uv вычислен и выброшен, `(void)uv`).
    - Никаких итераторов — статические таблицы движка, O(1) на операнд.
12. **Аккумулятор полностью** (:871-885): IsString → AccStr (полные байты, 8/16 тег); IsHeapNumber → AccF64 (биты); IsSmi → AccSmi. (Произвольный HeapObject — только raw word в Hdr.acc, SERIES.md:86 огр.3.)
13. `hdr = ib.FinishHdr()`; **EmitSplit(hdr, payload, len, offset_is_position=false, AfeyeEmit)** — все части несут тот же логический offset (glue key), kFlagCont на всех кроме последней.
14. return undefined.

Лимиты: **НИКАКИХ cap'ов на число записей** (SERIES.md:86; противоречие с :85 «50M backstop / AFEYE_BC_CAP» — в коде их нет). Единственный предел — ring 8 МиБ: при переполнении drop + witness kind 39 (0023). Строки НЕ режутся (в отличие от остальных kind'ов с их 64-960 байт cap'ами).

### Внешние доказательства формата
- `tools/bcrec_main.cc` — g++-сборка против bcrec.h+sink.cc из патчей; эмитит meta+func-def+инструкции через ТЕ ЖЕ билдеры.
- `tests/bcrec_roundtrip.rs` — round-trip через продакшн collect.rs и bctrace::run (5 записей, 3 инструкции, мёртвый блок [4,6) по факту, LdaConstant→cp→"secret-key", результат = acc следующей записи).

---

## patches/0034-v8-blink-virtual-clock.patch — виртуальные часы для страницы (blink + v8 Date)

Файлы: `third_party/blink/renderer/core/timing/performance.cc`, `v8/src/objects/js-objects.cc`.

### performance.cc Performance::now() (патч :1-44; hunks @@ -37 и @@ -1373,6 +1380,25)
- Объявление `extern "C" uint64_t afeye_vclock_ns(void);` под BLINK_AFEYE (:15) — renderer-бинарник общий для blink и v8, символ v8 sink линкуется напрямую (комментарий :10-14).
- В `Performance::now() const`, ПОСЛЕ телеметрия-блока 0012 (который логирует сам факт вызова "clock performance-now" kind 33 blink) и ДО реального `MonotonicTimeToDOMHighResTimeStamp`:
  - `blink::afeye::Enabled()` && static g_afeye_vclock (env **AFEYE_VIRTUAL_CLOCK**: ВКЛ если задан, непуст, != '0'; дефолт ВЫКЛ).
  - static **g_afeye_origin_ms** = `base::TimeTicks::Now().since_origin().InMillisecondsF()` — фиксируется ОДИН раз на процесс (эпоха-база, правдоподобные абсолютные значения).
  - return `origin_ms + afeye_vclock_ns() / 1e6`.
- Итог: performance.now() монотонно растёт от числа исполненных инструкций (тик из 0033), гладко независимо от тормозов трейсинга; тайминг-детекторы не видят аномалии (комментарий :26-28).

### js-objects.cc JSDate::CurrentTimeValue (патч :45-85; hunk @@ -5914,6 +5918,25)
- Include-блок V8_AFEYE (cstdlib + sink.h) вставлен после `#include "src/objects/js-objects.h"` (hunk @@ -3,6 +3,10) — независимо от include-блока 0022 (тот после <optional>); оба применяются, дубли закрываются include-guard.
- В CurrentTimeValue, после log_timer_events/correctness_fuzzer_suppressions и ДО реального пути: тот же env-гейт AFEYE_VIRTUAL_CLOCK; static **g_afeye_epoch_ms** = `V8::GetCurrentPlatform()->CurrentClockTimeMilliseconds()` один раз на процесс; return `epoch_ms + (int64)(afeye_vclock_ns() / 1000000ull)` — **миллисекундная гранулярность** (целочисленное деление).
- Покрытие: Date.now() (builtin 0004 возвращает CurrentTimeValue), new Date() (0022 DateConstructor тоже зовёт CurrentTimeValue), любой Date-конструктор от чисел не затрагивается.

Чего НЕТ: `src/base/platform/time.cc` не тронут ни одним патчем (grep) — TimeTicks::Now(), таймеры blink, rAF, сетевые таймстемпы остаются РЕАЛЬНЫМИ; виртуализированы только две JS-видимые поверхности (performance.now, Date). Оговорки SERIES.md:89: vclock глобальный на процесс (вкладки делят счётчик); при 10нс/инструкцию тик Date.now() ≈ каждые 100k инструкций.

---

## Сводные таблицы

### Wire-kind'ы v8-слоя и потребители

| kind | имя в collect.rs KINDS | эмитенты (патч:место) | Rust-потребитель |
|------|------------------------|------------------------|------------------|
| 0 | sink-hello | 0001 EmitHello (DrainLoop) | collect.rs индекс; liveness слоя |
| 1 | script-source | 0002 eval/script/streamed; 0022 wrapped | sinkfilter.rs:1189,1448 (цепочки, base64/hex-алфавиты) |
| 2 | bytecode-entry | — (мёртв) | — |
| 3 | wasm-module | 0003 Sync/AsyncCompile; 0020 OnFinishedStream/Deserialize("cached") | sinkfilter.rs:1284 (атрибуция инстансов по okну time+pid 5с) |
| 4 | wasm-memory | 0026 wasm-mem-content; 0028 wasm-shadow-* (фактически только rekey) | sinkfilter.rs:1419 payload_kinds (content-match граф) |
| 5 | wasm-table | — (мёртв) | — |
| 6 | microtask-enqueue | — (мёртв в v8) | — |
| 7 | microtask-run | — (мёртв в v8) | — |
| 8 | call-completed | 0003 Invoke ("call argc=... script=...:line"); 0022 lazy-compile | sinkfilter.rs:876-878 entry-index (lazy-compile ИСКЛЮЧЕНЫ), BATCHED part-файлы |
| 9 | atomics | — (мёртв, SERIES.md:6) | — |
| 10 | sab-backing | — (мёртв, SERIES.md:6) | — |
| 16 | fingerprint | 0021 json-stringify; 0022 gopd; 0025 gopd-proxy; 0027 taint-sink; 0031 causality; 0032 taint-swept/deadend | sinkfilter.rs:1095,1102,1713,1716,1719,1745; **causality НЕ парсится** |
| 30 | microtask | 0004 drain start/end | BATCHED; границы drain |
| 31 | wasm-instance | 0001 mem-grow; 0003 instantiate/import; 0020 trap/firstcall | sinkfilter.rs:1139-1148 (firstcalls/traps/mem_grows) |
| 32 | fn-tostring | 0004 | sinkfilter.rs:1082 |
| 33 | clock | 0004 date-now; 0022 date-ctor | sinkfilter.rs:1087 clock_ts; BATCHED |
| 34 | isolate | 0003 isolate-new; 0025 exec jit/byte | sinkfilter.rs:1109-1137 (compile-счётчики, per-script) |
| 38 | error-stack | 0021 | sinkfilter.rs:1150 (automation markers), 1736 |
| 39 | sink-drop | 0023 WriteDropReport (прямой fd-запись) | sinkfilter.rs:1088→405 drops_witnessed→2056 dead_end_witness |
| 40 | bytecode-trace | 0033 | BATCHED part-файлы → bctrace.rs (main.rs:547-558): filtered/bctrace/{func}.json, sem/{func}.jsonl, filtered/bctrace.json |

### Env-переменные v8-стороны

| env | семантика | где |
|-----|-----------|-----|
| AFEYE_SINK | мастер-гейт: вкл если задан, непуст, первый символ != '0' | 0001 sink.cc EnvOn |
| AFEYE_RAW_DIR | каталог .rec, дефолт /tmp/afeye-raw | 0001 RawDir; browser.rs:126-131,163-166 пробрасывает в chrome |
| AFEYE_SOURCE=0 | выкл дамп script-source | 0002 |
| AFEYE_TRACE_CALLS=0 | выкл Invoke-лог | 0003 (cap 4M) |
| AFEYE_TRACE_WASMMEM=0 | выкл wasm-mem grow | 0001 EmitWasmMemGrow (cap 100k) |
| AFEYE_TRACE_CLOCK=0 | выкл DateNow/DateConstructor clock-события | 0004, 0022 (cap 2M каждый) |
| AFEYE_TRACE_JSON=0 | выкл JSON.stringify capture | 0021 (cap 2M) |
| AFEYE_TRACE_STACK=0 | выкл Error.stack capture | 0021 (cap 2M) |
| AFEYE_TRACE_GOPD=0 | выкл GOPD-хуки (обычный и proxy) | 0022, 0025 (cap 2M каждый) |
| AFEYE_TRACE_EXEC=0 | выкл JIT/exec-лог + handler-инсталляцию | 0025 (cap 4M) |
| AFEYE_TRACE_WASMMEMDUMP=0 | выкл дампы содержимого wasm-памяти | 0026 (cap 512) |
| AFEYE_TAINT=0 | выкл taint-ядро | 0027 |
| AFEYE_WASM_SHADOW=0 | выкл wasm shadow (compile-time гейт codegen) | 0028 |
| AFEYE_TRACE_WASMSHADOW=0 | выкл shadow-эмиты | 0028 (cap 100k + per-thread sig-dedup) |
| AFEYE_CAUSALITY=0 | выкл async causality | 0031 |
| AFEYE_TRACE_BYTECODE=0 | выкл ТОЛЬКО bytecode-трейс | 0033 |
| AFEYE_VIRTUAL_CLOCK | вкл vclock если задан, непуст, != '0' (дефолт ВЫКЛ) | 0033 tick + 0034 readers |
| AFEYE_VCLOCK_NS_PER_INSTR | шаг vclock, дефолт 10 нс | 0033 |
| AF_JITLESS=1 | Rust-сторона: --jitless + --js-flags (browser.rs:93-103) | не читается в C++ |
| AFEYE_BC_CAP | заявлен SERIES.md:85 — **В КОДЕ ОТСУТСТВУЕТ** | — |

### Счётчики/лимиты (cap = static atomic, после порога эмит молча прекращается)

| хук | cap |
|-----|-----|
| Invoke calls (0003) | 4 000 000 |
| lazy-compile (0022) | 4 000 000 |
| exec jit/byte log (0025) | 4 000 000 |
| DateNow / DateConstructor (0004/0022) | 2 000 000 каждый |
| fnts (0004), json (0021), errstack (0021), gopd (0022), gopd-proxy (0025), wasm-trap / wasm-firstcall (0020) | 2 000 000 каждый |
| wasm-mem grow (0001) | 100 000 |
| wasm-mem-content dumps (0026) | 512 |
| shadow-эмиты (0028) | 100 000 (+dedup одинаковых Sig подряд) |
| ring-записи | без cap на число; ring 8 МиБ, drop → kind 39 |
| bytecode-трейс (0033) | **без cap вообще**; dedupe func-def thread_local unordered_set |
| script-source (0002) | без cap (только env) |

---

## Взаимодействия

Внутри v8-слоя:
- Все патчи зависят от 0001 (sink.{h,cc}: Enabled/NowNs/Emit*). 0023 расширяет sink drop-witness'ом, 0026 — EmitWasmMemContent, 0033 — vclock + kBytecodeTrace=40.
- 0027 BUILD.gn пред-регистрирует sources 0031 (causality) и 0032 (gc_witness); 0028 добавляет wasm_shadow — серия применима только целиком, порядок по именам файлов.
- 0021 JSON.stringify → 0027 тейнтит результат → Factory-швы (0027) распространяют через concat/substring → 0032 GCEpilogueWitness (heap.cc) сверяет TaintLiveHeapTagUnion vs TaintSunkUnion (taint-swept/taint-deadend) и зовёт TaintOnGCEpilogue.
- 0033 VclockTick → 0034 afeye_vclock_ns (performance.now, Date). 0033 meta/func-def/instr → tools/bcrec_main.cc (тот же bcrec.h) → tests/bcrec_roundtrip.rs → src/bctrace.rs.
- 0003 Invoke + 0022 lazy-compile делят kind 8; sinkfilter.rs:878 различает их по префиксу "lazy-compile".
- 0025 exec-лог и 0003 isolate-new делят kind 34; различаются по префиксу ("exec " vs "isolate-new").

С Rust-стороной:
- **collect.rs**: парсит wire-заголовок (16 байт) из `<RawDir>/{v8,blink,net}-<pid>.rec` (DEFAULT_RAW_DIR=/tmp/afeye-raw, collect.rs:11); KINDS[41] (collect.rs:15-57) — имена для всех kind'ов трёх слоёв; валидация kind<=40, flags<=1, байты 6-7==0 (:294-299); BATCHED_KINDS (8 штук, :59-68) включая call-completed/clock/microtask/bytecode-trace → part-файлы (PartWriter, roll 8 МиБ), остальные → raw/<layer>-<kind>-<seq>.bin; индекс jsonl {ts,l,pid,k,len,f,h(blake3-16),p,o,txt}.
- **sinkfilter.rs**: kind 1 script-source → цепочки скриптов + алфавиты (extract_alphabets, :1448-1458); kind 3 → wasm-атрибуция (:1284); kind 8 → entry-join caller-атрибуция (:876-878, script_at); kind 16 → json-stringify/taint-sink/taint-swept/taint-deadend/gopd/cookie-storage arms (:1095-1102, :1713-1748); kind 31/32/33/34/38/39 → счётчики и witness'ы (:1082-1160); kind 39 → dead_end_witness (:2056); payload_kinds графа (:1414-1421) включает kind 4 и 16 — content-match против net-стороны (byte identity, blake3 h из collect).
- **bctrace.rs** (kind 40): decode Hdr 72 байта (:21), parse_blocks tag-driven (:133-167), parse_meta (:170-238), parse_func_def_blob (:240-292), cont-склейка по (opcode,func_id) (:433-520), per-function отчёты cfg/dead/live (:528-590), semantic pass: cp-разрешение операндов (:640-665), api_calls ключи "global X"/"prop X"/"call X"/"runtime X" (:676-702), результат = acc следующей записи того же (pid,iso) когда acc_use&2 (:592-606, :668-674), sem/{func:08x}.jsonl {ts,off,op,args,acc,res,regs} (:711-750), filtered/bctrace.json (:763-780). Вызов: main.rs:547-558, bin/bcrec-dump.rs.
- **browser.rs**: запускает chrome с AFEYE_SINK/AFEYE_RAW_DIR (:126-131, :163-166), AF_JITLESS=1 → --jitless + --js-flags (:93-103).
- **НЕ потребляется никем**: kind 16 "causality ..." (0031) — grep 'causality' по src/ пуст; kind 4 "wasm-shadow-*" (0028) — специального парсера нет (только общий content-match).

---

## АУДИТ СООТВЕТСТВИЯ ЭТАЛОНУ

### 1. jitless / no-opt / no-sparkplug
- `src/browser.rs:93` — гейт: `std::env::var("AF_JITLESS") == "1"` (только эта env, дефолт ВЫКЛ).
- `src/browser.rs:98` — `--jitless` (chrome-switch).
- `src/browser.rs:102` — `--js-flags=--jitless --no-opt --no-sparkplug` (v8-флаги).
- **Соответствует эталону**: все три v8-флага присутствуют (browser.rs:102), плюс дубль --jitless на уровне chrome (:98). Комментарий :99-101 прямо ссылается на «analysis contract».
- Замечания: (а) вне AF_JITLESS=1 не передаётся НИ ОДНОГО детерминирующего флага — обычный прогон идёт с полным JIT; (б) --jitless в V8 сам по себе запрещает генерацию кода, --no-opt/--no-sparkplug при нём избыточны, но безвредны (belt-and-suspenders); (в) строки 99-102 отсутствуют в git-истории до текущей сессии [INFERENCE: файл правился параллельно другим агентом во время моего чтения — первое чтение :93-99 показывало только --jitless].

### 2. Патч диспетчера Ignition
- Эталон: хук в `GENERATE_BYTECODE_HANDLER` в `src/interpreter/interpreter-generator.cc`.
- Реально: `src/interpreter/interpreter-generator.cc` НЕ тронут. Хуки в `src/interpreter/interpreter-assembler.cc`: (1) конструктор InterpreterAssembler (0033 патч :419-437, hunk @@ -48,6 +48,18), (2) InlineShortStar (патч :438-454, hunk @@ -1381,6 +1393,16). Обработчик выполнения — `RUNTIME_FUNCTION(Runtime_AfeyeTraceBytecodeEntry)` в `src/runtime/runtime-trace.cc` (патч :750-894).
- **Не совпадает по месту, превосходит по покрытию**: конструктор InterpreterAssembler вызывается генератором для каждого handler'а, т.е. CallRuntime вкомпилирован в начало каждого bytecode-handler — функциональный эквивалент хука в GENERATE_BYTECODE_HANDLER, но additionally покрывает Star0-Star15, которые инлайнятся через StarDispatchLookahead МИМО конструктора (эталонная схема их бы потеряла; SERIES.md:83, стоковый V8_TRACE_UNOPTIMIZED стоит в тех же двух точках). DispatchTable не трогается (в Ignition этой ревизии её нет — таблица диспетча тут ни при чём) [INFERENCE по контексту патча].
- Фиксация vs эталон:
  - BytecodeOffset — соответствует: аргумент 2 CallRuntime `SmiTag(BytecodeOffset())` (патч :431), runtime конвертирует в логический offset (патч :773).
  - опкод — соответствует: читается из `*pc` в runtime (патч :786-787), не передаётся аргументом.
  - аргументы/имя свойства из пула констант — соответствует и шире: операнды декодирует ДВИЖОК (BytecodeDecoder, патч :822-867), значения регистров dump'ятся полностью (Reg/RegStr/RegF64/RegSmi), constant pool целиком уходит в func-def (патч :687-725); cp-индексные операнды разрешаются в bctrace.rs:640-655.
  - регистры источника и приёмника — соответствует: Hdr.regs[6] + kTagReg-блоки (bcrec.h, патч :55, :171-178).
  - SharedFunctionInfo — соответствует: frame→JSFunction→shared() (патч :789-793), но в wire уходит не указатель SFI, а func_id=FNV(script_id, literal_id, start_pos, iso_tag) (патч :797-798) — намеренно: GC двигает SFI (SERIES.md:86).
  - имя исходного скрипта — соответствует: полные байты в func-def blob (патч :664-678) + start line в Hdr.line.
- Отличие формата: эталон предполагал лог на каждый handler в C-макросе; реально — CallRuntime-трамплин в сгенерированный код + runtime-функция (дороже на вызов, но единственный способ безопасно читать heap-объекты под DisallowGarbageCollection).

### 3. Виртуализация таймингов
- Эталон: `src/base/platform/time.cc` ИЛИ `Performance::now`; формула `virtual_time += kBaseInstructionCost * instruction_count`.
- Реально: `src/base/platform/time.cc` НЕ тронут (grep по всем 34 патчам — отсутствие). `Performance::now` пропатчен: 0034 патч :19-44 (performance.cc, hunk @@ -1373,6 +1380,25). Дополнительно `JSDate::CurrentTimeValue` (js-objects.cc, патч :60-82, hunk @@ -5914,6 +5918,25) — эталон этого не требовал.
- Формула: не инкрементальная, а вычисляемая — `origin_ms + afeye_vclock_ns()/1e6`, где vclock инкрементируется на КАЖДУЮ инструкцию в Runtime_AfeyeTraceBytecodeEntry: `VclockTick(AfeyeVclockNsPerInstr())` (0033 патч :768-770), шаг env AFEYE_VCLOCK_NS_PER_INSTR дефолт 10 нс (патч :517-524), счётчик g_vclock_ns в sink.cc (патч :375-383). Математически эквивалентно `cost × count` — **соответствует по сути**.
- Чего не хватает относительно эталона: (а) time.cc не тронут — TimeTicks::Now(), blink-таймеры, rAF, сетевые timestamp'ы остаются реальными: виртуализированы только 2 JS-видимые поверхности; (б) **опасный interlock**: при AFEYE_TRACE_BYTECODE=0 runtime выходит ДО VclockTick (патч :754-756) — с включённым AFEYE_VIRTUAL_CLOCK часы страницы ЗАМРУТ на эпохе; (в) vclock процесс-глобальный, не per-isolate (SERIES.md:89 признаёт).
- Соответствует частично: performance.now ✓, Date ✓ (сверх эталона), time.cc ✗ (и не нужен при выбранной схеме).

### 4. WebIDL / DOM биндинги
- Эталон: патч `src/bindings/core/v8/` (V8DOMConfiguration); логировать геттер/сеттер интерфейса + аргументы + тип возвращаемого значения.
- Реально: `src/bindings/core/v8/` НЕ тронут. Хук — `third_party/blink/renderer/platform/bindings/idl_member_installer.cc` (0008, 0024): `CreateFunctionTemplate`/`CreateFunction` — funnel, через который ВСЕ сгенерированные V8DOMConfiguration-темプレートы получают callback; callback подменяется на `AfeyeDomApiThunk`, идентичность (Interface, get|set|call, prop) хранится в data-slot External → AfeyeApiCell (таблица 64k слотов, 0008 патч :19-83).
- Что эмитит: kind 29 dom-api, текст `"dom <Interface>.<get|set|call> <prop>"` (0008) + `" val=<значение>"` (0024, cap 150 символов в тексте, буфер 160). Значение через `AfeyeCaptureValue` (0024): undefined/null/bool(0|1)/number(%.17g)/string(WriteUtf8 + санитария printable)/`[array len=N]`/`[object]`. Гейт AFEYE_TRACE_DOM_VALUES=0 → только "dom ..." без значения; cap 8 000 000 вызовов. 0027 дополнительно тейнтит возвращённые строки (kSrcFingerprint).
- 0019 — НЕ биндинг-хук: точечные пробы конкретных реализаций (css_computed_style_declaration.cc, font_face_set.cc, media_query_list.cc, local_dom_window.cc, base_rendering_context_2d.cc, notification.cc, permissions.cc) — см. blink-часть документа.
- Сравнение с эталоном:
  - конкретный геттер/сеттер интерфейса — **соответствует** (idl_member_installer.cc thunk, вид get/set/call в тексте).
  - аргументы — **НЕ соответствует**: thunk НЕ читает `info[i]` — аргументы вызовов DOM-методов не эмитятся (в 0024 патче только GetReturnValue). Компенсация: аргументы видны на уровне байткода через 0033 (CallProperty-операнды + значения регистров), но без привязки «вот этот DOM-вызов — вот эти аргументы».
  - тип возвращаемого значения — **частично**: тип НЕ эмитится полем; он лишь неявно различим по рендеру (число vs строка vs "[array len=N]" vs "[object]"); массивы/объекты/функции/DOM-обёртки деградируют до "[array len]"/"[object]".
  - Место хука отличается от эталонного (platform/bindings вместо bindings/core/v8), но idl_member_installer — более узкий funnel:/generated/ V8DOMConfiguration-код сам зовёт его Install*-функции. Ограничение SERIES.md:44: Fast-API overloads (NoAllocDirectCall) обходят thunk при совпадении типов; SERIES.md:46: getComputedStyle camelCase named-getter ставится через SetHandler мимо thunk'а (ловится только 0019).

### 5. Финальный формат лога (эталон: timestamp_virtual, script_id, function_name, bytecode_op, target_property, arguments_hash)

| поле эталона | реально | где | что делать если нет |
|---|---|---|---|
| timestamp_virtual | **НЕТ** — ts записей = CLOCK_MONOTONIC реальное время | sink.cc MonoNs (0001 патч :92-97), NowNs (:235); collect.rs index "ts"; bctrace.rs:715 "ts" | vclock существует (0033 g_vclock_ns), но в wire НЕ штампуется; опция: доп. payload-блок или замена Hdr-поля (есть запас в 4 байта head func-def, в Hdr — нет) |
| script_id | **ЧАСТИЧНО** — сырой script_id не эмитится; он входит в FNV-хэш func_id; func-def несёт ПОЛНОЕ имя скрипта + line | MakeFuncId (0033 патч :120-133); AfeyeEmitFuncDef (:664-678, :739); bctrace.rs FuncDef (:63-71) без поля script_id | в func-def blob header 4 байта из 24 зарезервированы (head=24, использовано 20, патч :269-276) — script_id влезет без ломки формата-версии только новым тегом/полем |
| function_name | **ЕСТЬ** | func-def name (полные байты, 0033 патч :664-678); bctrace.rs:569-570 report "name" | — |
| bytecode_op | **ЕСТЬ** | Hdr.opcode + meta-таблица имён из движка (0033 патч :601-639); bctrace.rs:717-718 sem "op" = m.name | — |
| target_property | **ЕСТЬ** (богаче эталона) | cp-разрешение операндов bctrace.rs:640-665 (LdaGlobal cp[0] → литерал строки); api_calls ключи "global navigator"/"prop x"/"call f"/"runtime f" (:676-702, summary :752-760) | — |
| arguments_hash | **НЕТ хэша** — вместо него ПОЛНЫЕ значения аргументов (engine-decoded) | kTagOperand + Reg*/Acc* блоки (bcrec.h PayloadTag, 0033 патч :67-83); bctrace.rs args (:632-665), regs (:728-748) | хэш не нужен: значения строже хэша; при необходимости — blake3 от args в bctrace.rs (collect.rs уже считает h=blake3(payload)[..16] на запись, :360-363) |

Итог п.5: 3 из 6 полей эталона есть полностью (function_name, bytecode_op, target_property), 1 частично (script_id — через имя+хэш), 2 заменены более сильными/слабыми аналогами: timestamp_virtual отсутствует (ts реальный), arguments_hash заменён полными значениями (усиление).

### Прочие дырки и несоответствия (сводно)

1. **0028 known-unwired** (SERIES.md:2, подтверждено grep): WasmShadowPushStoreTaint/ShadowSetRange/WasmShadowConsumeLoadTaint не имеют вызовов ни в одном патче → t_store_taint≡0 → эмиты wasm-shadow-store/load/fill/init/copy невозможны; достижим только wasm-shadow-rekey. Отсутствие этих записей — НЕ провал захвата.
2. **0031 не потребляется Rust-стороной**: "causality ..."-записи kind 16 пишутся, но sinkfilter.rs не имеет arm'а для них (grep 'causality' src/ → 0). Witness-счётчики (dropped/imbalance/misses/minted) тоже никто не читает, хотя SERIES.md:4 называет их семантически важными.
3. **SERIES.md:85 vs код 0033**: «50M инструкций backstop, AFEYE_BC_CAP» — в патче нет ни счётчика, ни env; SERIES.md:86 сам себе противоречит («НИКАКИХ ЛИМИТОВ»). Реальность: лимитов нет.
4. **Мёртвые kind'ы v8-enum**: 2 (kBytecodeEntry), 5 (kWasmTable), 6 (kMicrotaskEnqueue), 7 (kMicrotaskRun), 9 (kAtomics), 10 (kSabBacking) — определены в sink.h, в KINDS collect.rs названы, не эмитируются НИ ОДНИМ патчем (grep подтверждает: только строки определения). SERIES.md:6 перечисляет лишь 9/10 (+blink 13/20/21), про 2/5/6/7 молчит.
5. **Truncation-несоответствия**: Emit (0003/0020 сырые wasm-модули) clamp'ит до 1МиБ-16 с флагом 1 — модули >1 МиБ урезаны (cap 0xFFFFF0 недостижим); EmitSpan (0020 Deserialize "cached", 0026 wasm-mem-content, 0028 shadow) clamp'ит до 64 КиБ. В отличие от kind 40 (EmitSplit, полное покрытие) эти kind'ы теряют хвосты. collect.rs считает stats.truncated по флагу.
6. **0021 non-afeye сборка сломана**: messages.cc переименовывает GetFormattedStack→GetFormattedStackImpl БЕЗ #ifdef (патч :150-151), а объявление Impl в messages.h — только под V8_AFEYE (:200-203). Без макроса определение члена класса без объявления = compile error. Сборка поддерживается только с v8_enable_afeye=true (build-chromium.sh:63) [INFERENCE — не компилировалось в рамках этой задачи].
7. **vclock-interlock**: AFEYE_VIRTUAL_CLOCK=1 + AFEYE_TRACE_BYTECODE=0 → Date/performance.now заморожены (VclockTick недостижим, 0033 патч :754-770).
8. **Битые blob-хэши в index-строках**: 0033 sink.h `index f1b2b2b..` при том что 0026 оставил `9ab7d6e`; 0034 js-objects.cc `index 90dfb8d..` при post-0025 `2cedfe0`. Для `git apply` без --3way/--index хэши игнорируются, контекст совпадает — косметика, но признак того, что патчи перегенерировались не по линейной цепочке.
9. **Kind-перегрузки**: 34 = isolate-new И exec-лог; 8 = Invoke-calls И lazy-compile; 16 = json/gopd/taint/causality/swept — всё различается только текстовыми префиксами, парсеры завязаны на starts_with.
10. **WriteDropReport считает только g_dropped** (ring-дропы), g_write_err (ошибки записи в fd) в witness не входят, хотя SinkDropped() суммирует оба — расхождение между «сколько потеряно» и «сколько засвидетельствовано».
11. **kTagOperand всегда signed** (runtime эмитит DecodeSignedOperand, unsigned-значение вычисляется и выбрасывается, 0033 патч :861-867) — для беззнаковых операндов >2^63 значение отрицательное; bctrace.rs:663 печатает signed as-is.
12. **0002 не имеет cap'а** на число script-source дампов (все остальные хуки — с cap'ами); на странице с тысячами мелких eval это потенциал ring-шторма (компенсируется drop-witness).
