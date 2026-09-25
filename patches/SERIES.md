МОЖЕТ НЕ АКТУАЛЬНО КОРОЧЕ НАХУЙ ТЫ ВООБЕЩ ЧИАТЕШЬ ДОЛБАЕБ ДИ КОД ЧИТАЙ ЧМО.
0028 wasm shadow: никто не вызывает WasmShadowPushStoreTaint. JS typed-array store в wasm-память не имеет C++ funnel на этой ревизии. t_store_taint = 0, wasm-shadow-* НЕ эмитятся. Это known-unwired, не сбой. Отсутствие этих записей — не dead-end и не провал захвата.

0031 async causality: witness-каунтеры (dropped/imbalance/misses/minted) ненулевые = async-дерево НЕПОЛНОЕ. Не молчит — но неполно.

Dead enums (kPerfEntry 13, kClientHints 20, kAtomics 9, kSabBacking 10, kSwCache 21): определены, названы коллектором, НЕ эмитятся.

perf timing VALUES всё же идут через 0024 (kind 29).

client-hints: sync getters — через 0024; getHighEntropyValues resolved UADataValues — только частично.

Atomics/SAB per-op — JIT-generated, C++ funnel нет.

Границы, которые НЕ закрыты и нельзя додумать
Cross-chain closure handoff. fp собран в 200ms, в замыкании, шлётся в 30с ДРУГОЙ цепью. C++-границы между collect и send нет → байты не линкуются. Single-chain proven, two-chain — нет.

Pure-JS transforms. charCodeAt → manual Uint8Array.push → custom-alphabet encoder → DEFLATE/RSA. Не касается TextEncoder/btoa/subtle.crypto ни одной hooked границы. Между collect и wire ничего. Самый жёсткий реальный лимит.

Wasm linear memory CONTENTS. Grow-паттерн захвачен (0025), per-access содержимого — нет. Нужны CSA-хуки, которых на 153 нет. Input/output видны только если пересекают hooked границу.

Per-call wasm export dispatch — сгенерированный машинный код per-arch. C++ funnel не существует. Substitute — kind-31 firstcall (какие индексы ran, раз).

JS→JS вызовы не пересекают Invoke. Interpreter hooks больше нет.

Proxy birth/traps — CSA/Torque. C++ fallback даст лживую частичную картину. GOPD-хук ловит только descriptor-трапы через special-receiver dispatch.

DefineOwnProperty НЕ захвачен (audit R4, deferred): funnel — JSReceiver::DefineOwnProperty, но Error ctor сам дефинит (stack accessor), bootstrapper — сотни. Без шумового фильтра хук топит стрим. Нужен фильтр против реального объёма .rec, не угаданный.

Intl resolvedOptions timeZone НЕ захвачен. ICU/CppGCManaged. Полу-хук, выглядящий полным, хуже отсутствия. Значение всё же уходит через захваченные границы: JSON.stringify (0021) / TextEncoder (0016).

G6 caller-edges НЕ гуляются на lazy-compile. Frame-walk на КАЖДОМ первом вызове функции, bug без compile-verify забрикейдит весь захват. Вместо: callee first-execution (0022) + caller chains из Error.stack (0021) + Invoke entries (0003). Caller-frame edge — follow-up, только с compile-loop.

gzip resp-body (kind 18) — RAW WIRE байты, script-source — DECOMPRESSED. Байт-матч невозможен → kind 18 намеренно вне графа (иначе жрёт node-budget на subresource-ответы, которые никогда не линкуются).

Custom-alphabet envelope. Cloudflare .post charset $+,-./0-9:A-Za-z{} без = нигде — vendor-specific, не base64. Variant runs покрывают только стандартные base64/hex. Custom-alphabet НЕ матчится → цепь unresolved, не гадать. Нужен алфавит из захваченного script-source + параметризованный декодер.

Wasm-instance атрибуция по time+pid окну (5с): два инстанса разных модулей в одном окне несут один resolved-import list. Bounded, recomputable.

Что структурно НЕ видит текущий код
net/ + services/network/ НЕ линкуют v8::afeye (нет //v8, -Wl,-z,defs, мультипроцесс). Cross-process proven = ТОЛЬКО Rust content-match wire-байт против renderer-захватов.

cookie-attach живёт в url_loader.cc (SetRawRequestHeadersAndNotify), НЕ в url_request_http_job.cc. В v12.2 текст говорит url_request_http_job.cc — фактически ложь, appendix 12.5 поправляет.

Fast-API overloads (NoAllocDirectCall) обходят 0008 thunk при совпадении типов аргументов — thunk видит slow path. getParameter и друзья НЕ fast-API, fp-sweep покрыт полностью.

getComputedStyle camelCase named-getter ставится через SetHandler, не IDLMemberInstaller → невидим для thunk. Ловится только 0019.

kind-29 чтения не имеют JS-caller identity в C++ (stack walk нет). Entry-join даёт ближайшую C++→JS границу, не точного читателя. Same-pid потоки интерливятся (tid в wire-формате нет), main+worker same-URL цепи в одном pid коллизят.

Payload уходит в query string без тела. net-request node включает method\0url — иначе пропустил бы analytics beacons с 500-1300-символьными query и пустым телом (proven этим же репо).

Что делает фильтр ЛОЖНЫМ сейчас
Fanout cap 4096: run, разделённый >4096 записей, скипается как boilerplate. Репортится как edges_dropped_by_fanout. Единственное место, где граф даёт честный false-negative — потому видно в отчёте, не молча. Sink-узлы обходят cap.

Edge-budget исчерпан: seed молча дропался → provenness всех upstream-цепей удалялась. Sink-first admission: бюджет гейтит ТОЛЬКО carriers, никогда sinks. Дропнутый sink = дропнутый BFS seed. Из-за ts-сортировки один cutoff теряет именно поздние token sends — тот самый 10-30s collect-then-send кейс, ради которого граф и построен.

Compile-provenance — направление ОДНОСТОРОННЕЕ ВВЕРХ. Taint НЕ наследуется вниз: деобфускатор легитимно эвалит и token pipeline, и горы библиотечного кода — downward inheritance затащит каждый template engine в filtered zip.

URL-identity (pass 1b) сам по себе цепь НЕ метит proven — атрибуция resp-body спана к URL требует per-request корреляции, которой wire-формат не несёт (конкурентные ответы интерливятся в одном pid). Только структурный факт: downloaded code, не inline.

Lazy-compile записи ИСКЛЮЧЕНЫ из entry-индекса — называют скомпилированную функцию, не исполняющую entry. Идут в per-chain executed_funcs (dead-code evidence).

AF_STRICT_GRAPH=1 режет filtered zip до proven only. Run zip не меняется.

Что делает runtime ложным
SIGKILL-only shutdown теряет хвост ring невидимо для kind-39 witness → ложный dead-end-proven. SIGTERM + 1.2s grace обязательны.

Raw-директория не подтёрта → старый .rec блендится с новым, sink-hello проходит от мёртвого прогона.

fork/zygote: дочерний рендерер наследует completed once_flag + ring без drain-потока. Ring 8 MiB забивается, всё дропается, .rec не создаётся, drop-witness не срабатывает.

Sink-drop пишется НАПРЯМУЮ в fd, НИКОГДА через ring — drop-репорт, который сам может дропнуться, бесполезен. Throttle ~10/s, только когда счётчик сдвинулся.

Per-TU атомики дают 500k реально при доке 100k (если регрессирует — один счётчик extern в blink sink).

PartWriter::push на неудаче НЕ должен возвращать выдуманный (rel, off) — строка индекса скипается (честное отсутствие).

Torn tail (chrome убит посреди drain timeout/SIGTERM) — warning, не corruption всего файла. Паритет с collect.rs starved-tail логикой.

0033 ignition bytecode trace: СЫРОЙ слепок исполнения, не обёртка. Runtime_AfeyeTraceBytecodeEntry вызывается из конструктора InterpreterAssembler — CallRuntime скомпилирован ВНУТРЬ каждого bytecode-handler, диспетчеризация прыгает в handler → запись. Запись на инструкцию бинарная, фиксированная раскладка 72 байта + payloads: opcode, scale (из codegen-константы handler — Wide/ExtraWide точные), logical offset, func_id (хэш SFI), СЫРОЕ tagged-слово аккумулятора, сырые слова 6 input-регистров (операнды декодятся прямо из pc статическими таблицами движка, O(1), ноль итераторов), значения String сырыми байтами (cap 256), HeapNumber f64-битами, Smi int32. func-def один раз на функцию: ВЕСЬ массив байткода сырыми байтами + constant pool (String байтами, HeapNumber f64, остальное raw-словами) + имя скрипта + строка + frame_size + param_count. meta один раз на процесс: таблицы опкодов ИЗ САМОГО ДВИЖКА — имена, n_ops, флаги (jump/return/call + подтип прыжка), на каждый scale размер инструкции и (тип, офсет) каждого операнда. Rust декодирует операнды и строит CFG по этим таблицам, ноль захардкоженных раскладок, ноль дрейфа при обновлении v8.
Семантика целей переходов — из движка (bytecode-array-iterator.cc): target = offset + imm; JumpLoop инвертирует; JumpIfTrueConstant берёт Smi из constant pool; switch-таблицы — Smis в пуле. В build_cfg ровно это, не догадки.
МЁРТВАЯ ВЕТКА = ПО ФАКТУ: инструкция из декодированного массива байткода чей offset НЕ встретился в потоке исполненных записей. Ноль эвристик, ноль тайм-окон, ноль предположений. bctrace.rs: per-function JSON (cfg_edges, live/dead блоки и байты), sem/*.jsonl — СЕМАНТИЧЕСКИЙ ПОТОК: каждая исполненная инструкция с разрешёнными операндами через constant pool (LdaGlobal cp[i] -> буквально "navigator"), входным значением аккумулятора и РЕЗУЛЬТАТОМ (результат = acc следующей записи того же (pid, isolate) когда опкод пишет аккумулятор — движковый факт из ImplicitRegisterUse, бит acc_use эмитится в meta), filtered/bctrace.json (сводка + api_calls: что дёргалось, сколько раз, с какими значениями — "global navigator" x1 values=["Mozilla/5.0"]). meta несёт из движка: имена опкодов, n_ops, флаги (jump/return/call + подтип прыжка), acc_use, размеры и (тип,офсет) операндов на все 3 scale, reg_file_start_offset для имён регистров r0/r1, таблицу имён рантайм-функций (CallRuntime операнд -> имя). Rust не хардкодит НИ ОДНОЙ раскладки или номера — всё из движка, ноль дрейфа при обновлении v8. атрибуция результата не пересекает изолейты: hdr.line на инструкционных записях = тег изолейта, (pid, iso) — ключ потока.
ПОКРЫТИЕ: хук стоит В ДВУХ местах — конструктор InterpreterAssembler (обычные инструкции) И InlineShortStar (Star0-Star15 инлайнятся в предыдущий handler через StarDispatchLookahead и НЕ проходят через конструктор — без второго хука самые частые инструкции слепые; стоковый V8_TRACE_UNOPTIMIZED стоит там же по той же причине).
wire-формат v4 (v8/src/afeye/bcrec.h — ЕДИНСТВЕННЫЙ источник правды, header-only без v8-зависимостей): Hdr 72 байта (opcode, scale, n_payload, flags, offset, func_id, line=isolate-тег, acc raw word, regs[6]) + payload-блоки [u8 tag][u32 len][bytes], тег 14 = kTagVclock ([u64] виртуальные нс на инструкцию, только при AFEYE_VIRTUAL_CLOCK=1 — timestamp_virtual из эталона). func-def blob v4: head 32 байта [u32 bc_len][u32 script_name_len][u32 fn_name_len][u32 cp_bytes][i32 frame_size][u32 param_count][i32 script_id][u32 reserved] + bc + script_name + FN_NAME (sfi->Name(), раньше НЕ эмитилось — отчёты показывали имя скрипта под видом имени функции) + cp. ПРИМЕЧАНИЕ СОВМЕСТИМОСТИ: v4 НЕ читает дампы v3 (head 24→32); старые запуски перечитать нельзя. bctrace sem-строка: {ts, vts?, off, op, args?, acc?, res?, regs?}; per-func отчёт: {func_id, script_id, script, fn, line, ...}. Все три отсутствовавших поля эталона закрыты: timestamp_virtual=vts, script_id, function_name=fn.
теги: 0=acc-str8, 1=acc-f64, 2=acc-smi, 3=reg-word, 4/12=reg-str8/16, 5=reg-f64, 6=reg-smi, 7=operand (engine-decoded значение), 8/13=cp-str8/16, 9=cp-f64, 10=cp-raw, 11=acc-str16. Тип значения из ТЕГА, никогда из длины. ОПЕРАНДЫ ДЕКОДИРУЕТ ДВИЖОК (BytecodeDecoder::DecodeSignedOperand/DecodeRegisterOperand) и эмитит готовые значения — Rust НЕ выводит layout операндов из массива байткода; статический walk использует только per-opcode размеры из meta для границ инструкций. func_id = FNV(script_id, function_literal_id, start_position, isolate_tag) — GC-стабильный, не от адреса SFI (GC двигает SFI, старый hash(sfi.ptr()) расщеплял поток функции на два id). записи больше одного sink-слота (>1MiB) режутся на части с kFlagCont, склеиваются по (opcode,func_id) в порядке offset — НИЧЕГО не теряется. constant pool: raw_constant_pool() это Union<Smi,TrustedFixedArray> — пустой пул это Smi, deref как массива крэшит рендерер в release; guard IsSmi. Строки пула и значения String/HeapNumber/Smi эмитятся ПОЛНОСТЬЮ (u32 len), без cap'ов.
Включение: AFEYE_SINK=1 (весь afeye) + AF_JITLESS=1 (--jitless --no-opt --no-sparkplug через --js-flags, всё в интерпретаторе, ноль инструкций мимо) + AFEYE_TRACE_BYTECODE=0 чтобы выключить только трейс. КВОТ НЕТ: ни cap'а на число инструкций, ни AFEYE_BC_CAP — wire v3 пишет каждую исполненную инструкцию без лимитов (единственная граница — ёмкость диска; при переполнении ring дропает и drop-witness 0023 это показывает). Записи batched в part-файлы (collect.rs), kind 40 (rec_census.py знает kind 40 = bytecode-trace).
НИКАКИХ ЛИМИТОВ: нет cap'ов на записи, нет truncation строк, нет 16k-слотовой dedupe-таблицы которая молча скипает (unordered_set по (func_id, bc_len), точный). Если диск не успевает — ring переполняется и drop-witness (0023) орёт в отчёт, НЕ молча. ПОКРЫТИЕ: хук в ДВУХ местах — конструктор InterpreterAssembler и InlineShortStar (Star0-Star15 инлайнятся в предыдущий handler, конструктор не проходят). ГОРЯЧИЙ ПУТЬ: thread_local scratch буферы, ноль heap-аллокаций на инструкцию кроме роста scratch, ноль 1MiB стековых буферов. ДОКАЗАТЕЛЬСТВО ФОРМАТА БЕЗ СБОРКИ ХРОМА: tools/bcrec_main.cc компилируется g++ против bcrec.h+sink.cc ИЗВЛЕЧЁННЫХ ИЗ ПАТЧЕЙ, эмитит meta+func-def+поток инструкций через те же C++ билдеры что runtime-trace.cc, tests/bcrec_roundtrip.rs прогоняет через продакшн-коллектор и продакшн-bctrace::run и проверяет: 5 записей, 3 инструкции, мёртвый блок [4,6) детекчен по факту, LdaConstant операнд разрешён через cp в "secret-key", результат = acc следующей записи ("Mozilla/5.0"), значение регистра доехало, Return без результата. зелёный = энкодер и декодер согласованы байт-в-байт. ОГРАНИЧЕНИЯ честно: (1) без --jitless горячая функция уйдёт в Maglev/TurboFan и ослепит трейс — AF_JITLESS=1 ОБЯЗАТЕЛЕН, цену закрывает 0034. (2) per-instruction line нет (line на func-def). (3) значения произвольных HeapObject — только raw tagged word, не содержимое. (4) switch-таблицы (subtype 4) не резолвятся в CFG-рёбра — мёртвость по executed offsets не зависит от рёбер.

0034 виртуальные часы: performance.now() и Date.now() тикают от счётчика исполненных инструкций, а не от системного таймера. Счётчик (afeye_vclock_ns) в v8 sink, инкремент в 0033 трейсе на каждую инструкцию (AFEYE_VIRTUAL_CLOCK=1, шаг AFEYE_VCLOCK_NS_PER_INSTR, дефолт 10нс). Blink performance.cc читает его через extern "C" — renderer-бинарник общий для blink и v8, символ с default visibility. Date: JSDate::CurrentTimeValue (js-objects.cc) возвращает эпоху-базу + vclock/1e6. Эпоха-база фиксируется один раз на процесс, абсолютные значения правдоподобные. Для страницы время идёт ровно и монотонно независимо от тормозов трейсинга — тайминг-детекторы не видят аномалии. Выключение: AFEYE_VIRTUAL_CLOCK=0 (или не задан) — реальные часы.
Честно: vclock глобальный на процесс, не на isolate — несколько вкладок делят счётчик. Для одновкладочного краула (наш кейс) не важно. Date.now() миллисекундная гранулярность: при 10нс/инструкцию ~100k инструкций на тик — достаточно для детекторов которые меряют «человек vs бот» по миллисекундам, не для sub-ms атак.


0033 value-provenance (низкоуровневая замена blake3-графу): src/valueflow.rs = Aho-Corasick многошаблонный матчер. bctrace собирает valuebook — байтовые последовательности которые исполненные инструкции байткода ДЕЙСТВИТЕЛЬНО несли (строки аккумулятора, строки регистров из 0033-трейса + строковые литералы constant pool из func-def блобов). sinkfilter прогоняет каждый sink/carrier payload одним AC-проходом против valuebook. Совпадение = это конкретное значение пересекло C++-границу, байт-в-байт, на байтовом смещении N, из bytecode-смещения B функции F (op O, src acc|reg|cp).
ПОЧЕМУ ЭТО НИЗКОУРОВНЕВО, А НЕ УГАДЫВАНИЕ: старый content-graph резал payload на 32-байтные blake3-окна с шагом 16, линковал по совпадению хэшей окон, с тайм-окнами 50мс/250мс/5с, BFS hop-cap 6, fanout-cut 4096, CONTENT_MAX_RECORDS 50k. Любая трансформация (xor с динамическим ключом, deflate, сдвиг ≥32 не кратный 16, префикс-конверт) рвала линк → глухой false-negative. AC матчит ТОЧНОЕ вхождение значения в payload на ЛЮБОМ смещении, за один проход, O(n+m+z): сдвиг на 37 байт, префикс-конверт, вложенное значение — всё матчится. Ноль окон, ноль страйдов, ноль хэш-коллизий, ноль тайм-окон, ноль hop-капов.
egress-дырка закрыта: is_ws_sink теперь матчит ws-frame-out + wt-stream-out + wt-datagram-out + rtc-datachannel-out + webgpu/write-buffer + webgpu/write-texture (0029/0030). раньше токен через WebTransport/RTC/WebGPU не давал proven вообще — эти теги были carriers не sinks.
выход: report.json "value_provenance" = {distinct_values_matched, scripts_with_proven_values, by_script: {script -> [{kind, off_in_payload, val_len, val_head_hex, src, op, bc_off}]}}. stats.value_proven_values/value_proven_scripts.
ДОКАЗАНО: value_provenance_matches_executed_value_in_sink — cp-литерал "TOKEN-abc123-xyz" находится байт-в-байт внутри req-body на смещении 9 (после "envelope:" — сдвиг который 16-страйдные окна бы пропустили), src=cp op=LdaConstant; value_provenance_no_false_positive_on_absent_value — отсутствующее значение = ноль матчей (матчер точный не fuzzy); 8 юнит-тестов AC (overlap, suffix-link, arbitrary-shift, binary с nul/high-bytes, long-pattern linear, duplicates).
ГРАНИЦА честно: value-provenance ловит значение которое ПЕРЕЖИЛО трансформацию неизменным (плейнтекст-токен, ключ, алфавит, формат-строка). если антифрод шифрует/сжимает значение ДО sink — байты меняются, точного вхождения нет (как и у blake3-окон, но AC хотя бы не врёт про hop-связи которых нет). для зашифрованного потока нужен крипто-funnel (0018 crypto-out уже ловит raw_data до шифрования) — valuebook матчится и там, потому что crypto-op в payload_kinds.

0035 DOM args + return type (низкоуровневое закрытие дыры эталона п.4): 0008/0024 писали только идентичность ("dom Navigator.get userAgent") и значение строкой — АРГУМЕНТЫ вызова и ТИП возврата не логировались (тип был неявен по форме рендера: "[object]" не отличал HTMLCanvasElement от Object). 0035 в том же AfeyeDomApiThunk (idl_member_installer.cc): argc=N, rtype=<undefined|null|bool|number|string|array|function|object> (AfeyeTypeOf — явный тип), args=[type:value,...] (до 8 аргументов, каждый type-tagged + значение до 72ch через тот же AfeyeCaptureValue). Формат записи kind 29: "dom <Iface>.<get|set|call> <prop> argc=N rtype=T args=[string:webgl2,...] val=<...>". Теперь видно ЧТО антифрод передаёт в вызовы: subtle.encrypt(algo,key,data), getContext("webgl2"), query(name), toDataURL(mime,quality) — аргументы байт-в-байт из info[i], не угаданные. Гейт: AFEYE_TRACE_DOM_ARGS=0 выключает только args (rtype остаётся). Cap прежний: 8M вызовов (g_afeye_api_calls). Ставит поверх 0008+0024, git apply --check зелёный на pristine 153.0.8010.52.
Rust-парсер: аргументы уже видны в txt-preview (первые 4096 байт) записей kind 29; отдельного разбора полей не требуется — dom-api строки и так уходят в per-kind ценз и raw.
FAST-PATH BYPASS (критично для «ловим всё»): 0008 подменял callback на AfeyeDomApiThunk, НО v8_cfunction_table_data продолжала передаваться в NewWithCFunctionOverloads. V8 NoAllocDirectCall диспатчит прямо в ОРИГИНАЛЬНЫЙ callback, минуя thunk — такие вызовы не логировались вообще (аудит PatchesBlinkNet finding 1, подтверждено кодом idl_member_installer.cc:291-294). 0035 обнуляет {v8_cfunction_table_data, v8_cfunction_table_size} когда thunk активен → все DOM-вызовы идут медленным путём через thunk → покрытие полное. Цена: fast-API DOM-вызовы теряют no-alloc путь пока трейсинг активен. InstallAttribute сеттеры (v8_cfunction_for_set) покрыты тем же фиксом — CreateFunction делегирует в CreateFunctionTemplate.

0036 importKey key material (низкоуровневое закрытие crypto-input дыры): 0018 ловит ВЫХОД каждого subtle-op (CryptoResultImpl::CompleteWithBuffer), 0007 ловит ВХОД encrypt/decrypt/sign/digest/verify (raw_data), но importKey/deriveBits/deriveKey/wrapKey/unwrapKey ВХОД не хукались (аудит: deriveBits-ханк в 0007 мёртвый — пустая строка). importKey key_data = точный std::vector<uint8_t> который move-ится в platform->Crypto()->ImportKey — СЫРЫЕ секретные байты ключа которые антифрод скармливает webcrypto. 0036 эмитит их байт-в-байт до move: kind 11 crypto-op, tag "crypto-keyin importKey extractable=N len=M", payload = key_data.data()[..size]. Гейт AFEYE_TRACE_CRYPTO_KEYIN=0, cap 200k. Ставит поверх 0007/0018, git apply --check зелёный на pristine 153.0.8010.52. exportKey/deriveBits выход уже покрыт 0018 (CompleteWithBuffer) — не дублирую.

0037 JWK key material out (низкоуровневое закрытие второй crypto-дыры): 0018 хукает CryptoResultImpl::CompleteWithBuffer — путь ArrayBuffer-результатов. НО exportKey("jwk") и wrapKey резолвятся через CompleteWithJson — ключевой материал как JSON. этот путь был СЛЕПОЙ: JWK-экспорт приватного ключа не захватывался вообще. 0037 эмитит utf8_data байт-в-байт: kind 11 crypto-op, tag "crypto-jwk-out", payload = JSON ключа (EmitSpan cap 64KiB с flags=1 при обрезке). Гейт AFEYE_TRACE_CRYPTO_JWKOUT=0, cap 200k. Ставит поверх 0018, git apply --check зелёный. Вместе 0018+0036+0037 закрывают crypto полностью: вход (encrypt/decrypt/sign/digest из 0007 + importKey из 0036), выход ArrayBuffer (0018), выход JWK (0037).
