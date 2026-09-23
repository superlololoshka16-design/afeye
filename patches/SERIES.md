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
