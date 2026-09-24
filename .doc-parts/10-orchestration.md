# Оркестрация: точка входа, контекст, запуск браузеров

Подсистема, которая собирает весь прогон: `main.rs` — полный жизненный цикл рана (аргументы → туннели → chrome → сессия сбора → остановка → упаковка), `ctx.rs` — разделяемые типы (Ctx, Cn, Tunnel, Target) и утилиты разбора URL/вендоров, `browser.rs` — флаги chrome, Xvfb, запуск в netns и подключение по CDP, `lib.rs` — крейт-библиотека с офлайн-пайплайном (collect/sinkfilter/bctrace/events), который использует и бинарь, и отдельные утилиты.

---

## src/lib.rs — декларация библиотечного крейта `afeye`

### pub mod (строки 1-4)
- назначение: делает четыре модуля доступными внешним потребителям (бинарю `main.rs` и утилитам в `src/bin/`).
- что внутри: ровно 4 строки, по одному `pub mod` на строку:
  - `pub mod bctrace;` (строка 1) — декодер wire-формата патча 0033 (трейс байткода Ignition);
  - `pub mod collect;` (строка 2) — сборщик сырых `.rec`-партов из raw-директории в `stage/collect`;
  - `pub mod events;` (строка 3) — типы событий (`FxEvent`, `Art`, `J`-билдер JSON, константы kind);
  - `pub mod sinkfilter;` (строка 4) — фильтрация sink-цепочек, построение `collect/filtered/report.json`.
- связи: `main.rs` импортирует `afeye::collect` и `afeye::sinkfilter` (main.rs:17-18) и вызывает `afeye::bctrace::run` (main.rs:552). `src/bin/afeye-collect.rs` использует `afeye::collect::DEFAULT_RAW_DIR` и `run_standalone`. Тесты `tests/bcrec_roundtrip.rs` и `tests/sink_roundtrip.rs` живут против этого крейта.

**Важная тонкость (дублирование):** `main.rs` отдельно объявляет `mod events;` (main.rs:7) и НЕ объявляет `mod collect/sinkfilter/bctrace` — они берутся из либ-крейта `afeye`. В результате `src/events.rs` компилируется дважды (в bin-крейте и в lib-крейте), и `crate::events::FxEvent` в main.rs и `afeye::events::J` в collect.rs — это разные типы для компилятора. Работает, потому что между ними нет обмена типами на границе (Collector получает только `&Path`), но это мина замедленного действия при рефакторинге.

## Взаимодействия (lib.rs)
- потребители: бинарь afeye (`src/main.rs`), утилита `src/bin/afeye-collect.rs`, интеграционные тесты `tests/*.rs`.
- lib не зависит от bin-модулей (ctx/browser/capture и т.д.); `collect.rs` внутри либа использует только `crate::events::J` (collect.rs:2).

---

## src/ctx.rs — общие типы контекста рана и разбор URL/вендоров

### const VENDORS (строки 9-39)
- назначение: таблица «суффикс хоста → имя антифрод-вендора», используется для классификации URL и стектрейсов.
- что внутри: срез из 27 пар `(&str, &str)`: cloudflare (challenges.cloudflare.com, cloudflare.com, cloudflareclient.com), datadome (datadome.co), kasada (kasada.io), human (perimeterx.net, px-cdn.net, px-client.net, humansecurity.com, humanbehavior.co, perfdrive.com), akamai (edgesuite.net, akamaiedge.net, akamai.com, akamaitech.net), fpjs (fpjs.io, fingerprintjs.com), seon (seon.io), arkose (arkoselabs.com, funcaptcha.com), hcaptcha (hcaptcha.com), recaptcha (recaptcha.net), imperva (incapsula.com, imperva.com, incapdns.net), threatmetrix (threatmetrix.net), iovation (iovation.com), shape (shapesecurity.com, shape.com).
- связи: читается в `vendor_of_url` (ctx.rs:104), `vendor_of_stack` (ctx.rs:114); main.rs:219-221 интернирует все имена вендоров в `Interner` на старте, чтобы id вендоров были стабильны в writer/capture.

### fn char_floor(s: &str, n: usize) -> usize (строки 41-51)
- назначение: безопасно отрезать префикс строки по байтам, не разрезая UTF-8 символ.
- что внутри: если `n >= s.len()` — вернуть `s.len()`. Иначе с байта `n` идти назад, пока байт является continuation-байтом UTF-8 (`b[i] & 0xc0 == 0x80`), вернуть границу символа.
- связи: используется только в `vendor_of_stack` для обрезки стектрейса до 600 байт. Тест `floor_boundaries` (ctx.rs:239-243) проверяет границы, включая кириллицу (`"abйd", 3 → 2`).

### fn host_of(url: &str) -> &str (строки 53-74)
- назначение: вытащить хост (без порта, без userinfo) из URL.
- что внутри: ищет `"://"`, если нет — возвращает `""`. Отрезает путь/query/fragment по первому из `['/', '?', '#']`. Отбрасывает userinfo по последнему `'@'`. Порт: если есть `':'` и левая часть не содержит `':'` (IPv4) или строка начинается с `'['` (IPv6) — отрезает порт; для IPv6 возвращает вместе со скобками `[...]`.
- связи: `endpoint_of`, `vendor_of_url`, `load_targets` в main.rs:152 (`Target.host`). Тест `host_extract` (ctx.rs:214-218): `accounts.x.ai`, `127.0.0.1` (порт отрезан), `ex.com` (userinfo отрезан).

### fn endpoint_of(url: &str) -> &str (строки 76-91)
- назначение: схема+хост+порт+путь без query/fragment (ключ «эндпоинта» для дедупликации/счётчиков).
- что внутри: если `host_of` пуст — `""`. Вычисляет конец authority (первый `/ ? #` после `://`) и конец URL (первый `? #` после authority), возвращает срез до него.
- связи: используется в writer/classify (по grep — через interner в writer.rs:322 для `ctx.endpoints`). Тест `endpoint_strip` (ctx.rs:246-251).

### fn vendor_of_url(url: &str) -> Option<&'static str> (строки 93-110)
- назначение: определить антифрод-вендора по URL.
- что внутри: 1) хост пуст → `None`; 2) URL содержит `/cdn-cgi/` или `/turnstile` → `"cloudflare"` (специальный путь, работает на любом хосте); 3) содержит `/recaptcha` → `"recaptcha"`; 4) обход VENDORS: точное совпадение хоста ИЛИ суффикс, отделённый точкой (`h.ends_with(suf)` и байт перед суффиксом `b'.'`).
- связи: capture.rs (интернирование vendor id для событий), writer.rs. Тест `vendors` (ctx.rs:221-228) покрывает все ветки включая `ex.com/cdn-cgi/trace → cloudflare` и `ok.com/app.js → None`.

### fn vendor_of_stack(s: &str) -> Option<&'static str> (строки 112-120)
- назначение: определить вендора по JS-стектрейсу.
- что внутри: обрезает строку до 600 байт через `char_floor` и ищет первое вхождение любого суффикса VENDORS как подстроки (не по границам хоста — грубее, чем `vendor_of_url`).
- связи: classify.rs (атрибуция скриптов). Тест `stack_multibyte_no_panic` (ctx.rs:231-236): 700 символов «й» не паникуют, datadome-URL внутри длинной строки находится.

### struct Cn (строки 122-137), impl Cn (строки 139-161)
- назначение: глобальные атомарные счётчики рана + флаги остановки. `#[repr(C, align(64))]` — выравнивание на кэш-линию.
- что внутри (поля):
  - `ev: AtomicU64` — всего событий отправлено (capture.rs:50,65);
  - `req/resp/body: AtomicU64` — сетевые запросы/ответы/тела (capture.rs:276,353,331,472);
  - `art: AtomicU64` — артефактов записано; в конце writer ПЕРЕЗАПИСЫВАЕТ его через `store` точным значением (writer.rs:502);
  - `scripts: AtomicU64` — scriptParsed-событий (capture.rs:544);
  - `batch: AtomicU64` — JS-батчей из binding-канала (capture.rs:609);
  - `drop: AtomicU64` — дропов (переполнение бюджета/очередей: capture.rs:135,487; writer.rs:277,284,299);
  - `bin/bout: AtomicU64` — байты артефактов внутрь/наружу; `bout` тоже финально проставляется writer'ом (writer.rs:503);
  - `poke: AtomicU64` — «тычки» human-драйвера (human.rs:151);
  - `stop: AtomicBool` — флаг «сессия закончена»: ставится в main.rs:484 (Release), читают relay.rs:159,173,233 и tg.rs:160,168,174 для выхода из своих циклов;
  - `dead: AtomicBool` — флаг «writer завершён, всё мертво»: ставится в main.rs:596 (Release), читают human.rs:170, writer.rs:481,487, relay/tg.
- `Cn::new()` (строки 140-156) — все нули/false. `Cn::inc(f)` (строки 158-160) — `fetch_add(1, Relaxed) + 1`, возвращает новое значение.
- связи: экземпляр живёт в `Ctx.cn`, создаётся в main.rs:262; финальные значения читаются в манифест (main.rs:690-700).

### struct Target (строки 163-166)
- назначение: одна цель-сайт для открытия.
- что внутри: `url: String` (полный URL), `host: String` (хост для интернирования).
- связи: `load_targets` (main.rs:142-163) строит список из `targets.json`; capture/human/writer используют `site = interner.intern(host)`.

### struct Tunnel (строки 168-186), #[derive(Clone)]
- назначение: описание одного WireGuard-туннеля + его netns-изоляции.
- что внутри (поля; значения присваиваются в `wg::parse_conf`, wg.rs:38-55):
  - `i: u32` — порядковый номер (1-based, от сортировки conf-файлов по имени);
  - `name: String` — имя conf-файла без расширения;
  - `user: String` — системный пользователь `fx{i}`, под которым запускается chrome (изоляция cookie/профилей);
  - `ns: String` — имя netns `afns{i}`;
  - `wg_if/h_if/n_if: String` — имена интерфейсов: wg-устройство `afwg{i}`, хостовый конец veth `afvh{i}`, ns-конец `afvn{i}`;
  - `host_ip/ns_ip: String` — `10.77.{i}.1` и `10.77.{i}.2` (адреса veth-пары);
  - `port: u16` — порт remote debugging `9400 + i`;
  - `endpoint: String` — `host:port` WG-пира из conf;
  - `pubkey/privkey: String` — ключи из conf (Peer/PublicKey, Interface/PrivateKey);
  - `addr: Vec<String>` — Interface/Address (список CIDR);
  - `dns: Vec<String>` — Interface/DNS;
  - `egress: Option<String>` — внешний IP, определённый `wg::verify` после поднятия (изначально None).
- связи: создаётся `wg::parse_conf` из `$AF_ROOT/wg/*.conf`; main хранит `Vec<Tunnel>` в `Ctx.tunnels`; browser.rs использует `ns/ns_ip/port/user/i` для запуска chrome в netns; `endpoint` (с `:` → `_`) служит именем туннеля в интернере (main.rs:415).

### struct Ctx (строки 188-207)
- назначение: единственный разделяемый контекст рана; живёт в `Arc<Ctx>`, передаётся во все подсистемы (writer, capture, human, relay, tg, browser).
- что внутри (поля, инициализация — main.rs:253-272):
  - `stage: PathBuf` — `/tmp/afeye/stage/<slot>` — корень выходных данных текущего рана;
  - `slot: String` — имя слота `timefmt::slot(t0ms, 30)` вида `DD.MM.YYYY_HH.MM-HH.MM`;
  - `t0ms: u64` — unix-мс старта; сид для human-rng (human.rs:155);
  - `deadline: Instant` — `t0 + hard` (AF_HARD_SECS); жёсткий дедлайн для human/relay/tg;
  - `browse: Duration` — AF_BROWSE_SECS; желаемая длительность сессии;
  - `tx: Sender<FxEvent>` — unbounded crossbeam-канал событий в writer;
  - `art: Sender<Art>` — канал артефактов (тела скриптов/ресурсов) в writer;
  - `interner: arena::Interner` — строки → u32-id (сайты, вендоры, туннели, имена);
  - `cn: Cn` — счётчики/флаги (см. выше);
  - `targets: Vec<Target>` — из `$AF_ROOT/targets.json`;
  - `tunnels: Vec<Tunnel>` — из `$AF_ROOT/wg/*.conf` (пусто в local-режиме);
  - `binding: String` — имя CDP Runtime.addBinding вида `_k{t0ms%997}z` (main.rs:222) — канал, через который инжектированный JS (inject.rs) шлёт батчи событий; подставляется в `inject::source(binding, gl_spoof)` (capture.rs:189-192), отфильтровывается в capture.rs:606;
  - `gl_spoof: bool` — `AF_GL_SPOOF` установлен (main.rs:271); включает WebGL-spoof в инжекте (inject.rs:1-7, маркер `__G__`);
  - `budget: AtomicU64` — накопленные байты артефактов; лимит — `Ctx::budget_limit()` (см. main.rs); проверка capture.rs:134, инкремент capture.rs:145;
  - `chrome: PathBuf` — найденный бинарь chrome (`find_chrome`);
  - `ua: String` — переопределённый User-Agent (`user_agent_for`);
  - `display: String` — X-display для chrome (`:99` от Xvfb или существующий `$DISPLAY`; в local — пустая);
  - `endpoints: DashMap<u32, u64>` — счётчик обращений по id эндпоинта (пишет writer.rs:323, читает human.rs:334, размер уходит в манифест main.rs:697).
- связи: создаётся один раз в `run()`; метод `budget_limit` определён в main.rs (см. ниже) — impl-блок вне родного модуля, это единственное место.

### mod tests (строки 209-252)
- `host_extract` (214-218): host_of для URL с путём/query, с портом, с userinfo.
- `vendors` (221-228): vendor_of_url по cloudflare/datadome/human/fpjs, по пути `/cdn-cgi/`, отрицательный кейс.
- `stack_multibyte_no_panic` (231-236): vendor_of_stack не паникует на 700 многобайтовых символах; находит вендора в URL внутри длинной строки.
- `floor_boundaries` (239-243): char_floor при n>len, точная граница, граница внутри многобайтового символа.
- `endpoint_strip` (246-251): endpoint_of режет query/fragment, сохраняет `/`.

## Взаимодействия (ctx.rs)
- ctx.rs — листовой модуль без зависимостей от других bin-модулей, кроме `crate::arena::Interner` (поле `interner`) и `crate::events::{Art, FxEvent}` (поля-каналы Ctx).
- потребители: main.rs (создание Ctx/Tunnel/Target, вендоры), browser.rs (читает `Ctx.ua/chrome/display/binding` через Flags и launch), capture.rs (binding, gl_spoof, interner, budget, cn), writer.rs (stage, slot, interner, endpoints, cn), human.rs (t0ms, deadline, endpoints, cn), relay.rs и tg.rs (stage, deadline, cn), wg.rs (парсит Tunnel), collect/sinkfilter/bctrace НЕ знают про Ctx (работают по путям).

---

## src/browser.rs — запуск chrome и подключение по CDP

### struct Flags<'a> (строки 10-16)
- назначение: параметры для сборки командной строки chrome.
- что внутри: `t: Option<&'a Tunnel>` (None = local-режим), `port: u16` (remote debugging), `bind: &'a str` (адрес для --remote-debugging-address), `ua: &'a str` (User-Agent), `headless_shell: bool` (бинарь — headless_shell, форсирует headless).
- связи: заполняется в `launch_chrome` (t=Some, port=t.port, bind=t.ns_ip) и `launch_chrome_local` (t=None, port=AF_LOCAL_PORT, bind=127.0.0.1).

### struct Xvfb (строки 18-21), impl Drop (строки 23-28)
- назначение: RAII-обёртка над процессом Xvfb.
- что внутри: `c: std::process::Child` (процесс), `display: String` (строка дисплея). Drop убивает и дожидается процесс (`kill()` + `wait()`, ошибки игнорируются).
- связи: создаётся в `spawn_xvfb`, хранится в `run()` main.rs:248-252; живёт до конца `run()`, то есть Xvfb умирает при выходе из функции.

### fn spawn_xvfb() -> Result<Xvfb, String> (строки 30-56)
- назначение: обеспечить X-дисплей для headed-chrome.
- что внутри: 1) если `$DISPLAY` уже задан и непуст — возвращается Xvfb-заглушка: процесс `true` (мгновенно завершается; нужен только чтобы занять поле `c`), display = значение `$DISPLAY`. 2) иначе удаляется stale-сокет `/tmp/.X11-unix/X99`, запускается `Xvfb :99 -screen 0 1920x1080x24 -ac -nolisten tcp -noreset` (stdout/stderr в null), затем до 10 секунд с шагом 100 мс ждётся появление сокета `/tmp/.X11-unix/X99`; таймаут → Err("Xvfb did not start").
- связи: вызывается из main.rs:251 только в НЕ-local режиме; `ctx.display` потом уходит в env chrome (browser.rs:124).

### fn chrome_flags(f: &Flags) -> Vec<String> (строки 58-106) — приватная
- назначение: собрать полный argv-хвост chrome.
- что внутри: profile-dir = `/tmp/afeye/p{t.i}` для туннеля, `/tmp/afeye/local` для local; `idx` = t.i (0 в local). Постоянные флаги (строки 64-81):
  1. `--no-first-run`
  2. `--no-default-browser-check`
  3. `--disable-session-crashed-bubble`
  4. `--hide-crash-restore-bubble`
  5. `--disable-search-engine-choice-screen`
  6. `--disable-features=IsolateOrigins,site-per-process,PrivacySandboxSettings4`
  7. `--disable-site-isolation-trials`
  8. `--enable-unsafe-swiftshader` (программный GL без GPU — нужен для WebGL-фингерпринта в VM)
  9. `--password-store=basic`
  10. `--use-mock-keychain`
  11. `--no-sandbox`
  12. `--remote-debugging-address={f.bind}` (туннель: ns_ip `10.77.{i}.2`; local: `127.0.0.1`)
  13. `--remote-debugging-port={f.port}` (туннель: `9400+i`; local: `AF_LOCAL_PORT`, дефолт 9600)
  14. `--user-data-dir={profile}`
  15. `--window-size=1280,832`
  16. `--window-position={(idx%4)*320},{(idx/4)*250}` — сетка окон 4 в ряд, чтобы разные chrome не перекрывали друг друга на одном X-дисплее
- условные (строки 82-103):
  17. `--user-agent={f.ua}` — если ua непустой (всегда непустой: main.rs подставляет `user_agent_for`);
  18. `--headless` + `--disable-gpu` — если задан env `AF_TEST_HEADLESS` (любое значение, строка 85);
  19. `--headless` + `--disable-gpu` — ещё раз, если `f.headless_shell` (бинарь называется `*headless_shell*`); возможна дублирующая пара флагов, chrome это терпит;
  20. `--jitless` — если env `AF_JITLESS == "1"` (строго строка "1", гейт строка 93, push строка 98). Комментарий (строки 94-97) относит это к патчу afeye 0033: без JIT весь JS остаётся в интерпретаторе Ignition, трейс байткода видит 100% исполненных инструкций, ничто не уходит в машинный код Sparkplug/Maglev/TurboFan; тайминговые аномалии jitless закрываются патчем 0034 (`AFEYE_VIRTUAL_CLOCK`).
  21. `--js-flags=--jitless --no-opt --no-sparkplug` — под тем же гейтом AF_JITLESS=1 (строки 99-102): v8-флаги явно пинят все три тира (комментарий: «--jitless already forbids code generation, but pin all three explicitly»). Добавлено в рабочем дереве 2026-09-24 (git diff против HEAD — 4 новые строки); в HEAD этого флага нет.
- замыкает список стартовый URL `about:blank` (строка 104).
- связи: зовётся из launch_chrome/launch_chrome_local; `AF_DEBUG_ARGS` печатает результат (см. launch_chrome_local).

### fn is_headless_shell(chrome: &std::path::Path) -> bool (строки 108-113)
- назначение: детект «это headless_shell, а не полный chrome» по имени файла.
- что внутри: `file_name()` содержит подстроку `"headless_shell"`.
- связи: оба launch'а передают результат в Flags; актуально для пути `/opt/afeye-chrome/headless_shell` из find_chrome.

### async fn launch_chrome(ctx: &Ctx, t: &Tunnel) -> Result<Child, String> (строки 115-155)
- назначение: запустить chrome ВНУТРИ netns туннеля под отдельным пользователем.
- что внутри: командная строка строится как `ip netns exec {t.ns} runuser -u {t.user} -- env HOME=/tmp/afeye/h{i} USER={t.user} DISPLAY={ctx.display} AFEYE_SINK={sink} AFEYE_RAW_DIR={raw_dir} {ctx.chrome} {flags...}`:
  - `ip netns exec` — изоляция сети (весь трафик chrome идёт через WG-туннель);
  - `runuser -u fx{i}` — сброс привилегий (root нужен только для netns);
  - env передаётся через аргументы `env`, потому что `ip netns exec` чистит окружение;
  - `AFEYE_SINK` — из env раннера, дефолт `"1"` (строки 133-135): включает afeye-синки в патченном chrome;
  - `AFEYE_RAW_DIR` — приоритет: `AFEYE_RAW_DIR` → `AF_RAW_DIR` → `/tmp/afeye-raw` (строки 130-132) — куда патченый chrome пишет сырые `.rec`-парты;
  - `HOME=/tmp/afeye/h{i}` — домашняя директория пользователя туннеля (создаётся `wg::prep_user_dirs`).
- stdout в null; stderr — append в `/tmp/afeye/chrome-{i}.log` (если файл не открылся — в null); `kill_on_drop(true)`; `spawn()` → tokio Child.
- связи: зовётся из `run_tunnel`; профили/hoм-директории готовит `wg::prep_user_dirs` (wg.rs:282-296: rm+mkdir+chown `/tmp/afeye/p{i}` и `/tmp/afeye/h{i}`).

### async fn launch_chrome_local(ctx: &Ctx, port: u16) -> Result<Child, String> (строки 157-190)
- назначение: local-режим без netns/runuser — chrome прямо в текущем окружении.
- что внутри: удаляет `/tmp/afeye/local` (строка 158, чистый профиль на каждый запуск); Flags{t:None, port, bind:"127.0.0.1", ua, headless_shell}; `Command::new(&ctx.chrome)` напрямую; те же env `AFEYE_SINK` (дефолт "1") и `AFEYE_RAW_DIR` (та же цепочка приоритетов) ставятся через `c.env` (строки 167-170); если задан `AF_DEBUG_ARGS` — печатает флаги в stderr (`[afeye] chrome args: {flags:?}`, строки 175-177); stdout null, stderr → `/tmp/afeye/chrome-local.log`; `kill_on_drop(true)`.
- связи: main.rs:398 (local-ветка).

### async fn http_json_version(ip: &str, port: u16) -> Result<String, String> (строки 192-242) — приватная
- назначение: дождаться devtools-эндпоинта и вытащить `webSocketDebuggerUrl` БЕЗ http-библиотек, сырым TCP.
- что внутри: парсит `{ip}:{port}` в SocketAddr; цикл попыток: `TcpStream::connect_timeout(3s)`, read/write timeout 2s, отправляет рукописный `GET /json/version HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n`, читает ответ кусками по 4096 до EOF/ошибки/предела 1 MiB; `AF_DEBUG_HTTP` печатает номер попытки/результат write (строки 206-208) и размер ответа (222-224); в теле ищет `"webSocketDebuggerUrl"`, затем `ws://` и закрывающую кавычку — возвращает URL строкой (без JSON-парсера). Полный таймаут — 45 секунд (`"devtools endpoint not reachable"`, строка 238), между попытками sleep 250 мс (tokio).
- связи: вызывается только из `connect`.

### async fn connect(ctx: &Ctx, ip: &str, port: u16) -> Result<Browser, String> (строки 244-256)
- назначение: подключиться к chrome по CDP и вернуть `chromiumoxide::Browser`.
- что внутри: `let _ = ctx;` (строка 245) — ctx фактически НЕ используется (остаточный параметр); получает ws-URL через `http_json_version`, `Browser::connect(ws)`, спавнит фоновую tokio-задачу, которая вытягивает handler-поток (`handler.next()`) и печатает ошибки в stderr (`[afeye] handler: {e}`).
- связи: main.rs:400 (local, ip=127.0.0.1) и run_tunnel (ip=t.ns_ip).

### async fn run_tunnel(ctx: &Ctx, t: &Tunnel) -> Result<(Child, Browser), String> (строки 258-262)
- назначение: полный цикл «запустить chrome в netns + подключиться».
- что внутри: `launch_chrome` → `connect(ctx, &t.ns_ip, t.port)` → пара (Child, Browser).
- связи: main.rs:416 — единственная точка использования (FuturesUnordered по всем «good»-туннелям).

## Взаимодействия (browser.rs)
- зависит от: ctx (Ctx, Tunnel), chromiumoxide (Browser), tokio::process, simdutf8.
- потребители: main.rs (spawn_xvfb, launch_chrome_local, connect, run_tunnel, is_headless_shell косвенно).
- наружу (в процесс chrome) прокидывает env: `AFEYE_SINK`, `AFEYE_RAW_DIR`, `HOME`, `USER`, `DISPLAY` — их читают C++-патчи chromium (серия patches/, см. SERIES.md: AFEYE_SINK включает синки; AFEYE_TRACE_BYTECODE=0 выключает трейс 0033; AFEYE_BC_CAP переопределяет квоту 50M инструкций; AFEYE_VIRTUAL_CLOCK — патч 0034).
- файлы на диске: `/tmp/afeye/chrome-{i}.log`, `/tmp/afeye/chrome-local.log`, `/tmp/.X11-unix/X99`.

---

## src/main.rs — точка входа и полный жизненный цикл рана

### mod-объявления (строки 1-15)
bin-крейт объявляет приватные модули: arch, arena, browser, capture, classify, ctx, events, human, inject, relay, tg, timefmt, wg, writer, zipper. collect/sinkfilter/bctrace НЕ объявлены — берутся из крейта `afeye` (lib.rs).

### use (строки 17-28)
`afeye::collect`, `afeye::sinkfilter`, `crate::ctx::{Ctx, Cn, Target, Tunnel}`, `crate::events::{FxEvent, K_META}`, bytes::Bytes, futures (join_all, StreamExt), serde::Serialize, PathBuf, Ordering, Arc, Duration/Instant.

### struct MTun (строки 30-38), #[derive(Serialize)]
- назначение: запись о туннеле в манифесте.
- поля: `name`, `endpoint`, `ns`, `user`, `egress: Option<String>`, `ok: bool` (в main.rs:687 `ok = egress.is_some()`).

### struct MRun (строки 40-86), #[derive(Serialize)]
- назначение: итоговый манифест рана; пишется дважды — в `stage/manifest.json` (внутри zip) и в `dumps/<stem>.manifest.json` (снаружи).
- поля (44 штуки): `started` (run_id, ISO8601 UTC), `slot`, `browse_secs` (фактическая длительность сессии), `chrome` (путь), `binding` (имя CDP-биндинга), `targets` (URL'ы), `runner_ip`, `tunnels: Vec<MTun>`, счётчики `events/requests/responses/bodies/scripts/batches/pokes/endpoints/artifacts/art_bytes/dropped/budget_used` (из Cn и budget), `relay` (число выполненных relay-задач), `tg_sent`, блок классификации `cls_af/cls_garbage/cls_neutral/cls_scripts/cls_kept/cls_dup/cls_art_rm/cls_bytes_rm`, `zip` (имя zip), `zip_bytes`, `filtered` (имя filtered-архива), `filtered_bytes`, блок collect `collect_records/collect_bytes/collect_truncated/collect_corrupt`, `sink_alive: bool`, блок sinkfilter `sink_chains/sink_hot/sink_cold/sink_wasm`, `test: bool` (флаг --test).

### fn env_u64(k: &str, d: u64) -> u64 (строки 88-90)
- назначение: прочитать u64 из env с дефолтом (невалидное значение молча = дефолт).
- связи: используется для AF_BROWSE_SECS, AF_HARD_SECS, AF_LOCAL_PORT, AF_BUDGET_MB. Точно такая же функция продублирована в tg.rs:20 и relay.rs:22.

### impl Ctx::budget_limit (строки 92-96)
- назначение: лимит суммарных байт артефактов на ран.
- что внутри: `env_u64("AF_BUDGET_MB", 350) * 1024 * 1024` — то есть дефолт 350 МиБ. Читает env при КАЖДОМ вызове (capture.rs:134 зовёт на каждой проверке) — не кэшируется.
- связи: impl на чужом типе из ctx.rs; при переполнении capture дропает артефакт и инкрементит `cn.drop`.

### fn now_ms() -> u64 (строки 98-103)
- unix-мс (SystemTime → as_millis; ошибка → 0). Дублируется в tg.rs:13, relay.rs, writer и др.

### const TAB_UP: Duration (строка 105)
- 90 секунд — таймаут на создание вкладки (`new_page`) и на `capture::instrument` (main.rs:376,389).

### fn meta_ev(ctx: &Ctx, tun: u32, d: Bytes) (строки 107-119)
- назначение: отправить meta-событие (kind=K_META=17, events.rs:19) в канал writer'а.
- что внутри: FxEvent{t: now_ms, site:0, tun, tab:0, vendor:0, name:0, kind:K_META, _pad:0, d}; результат send игнорируется.
- связи: вызывается при verify туннелей (main.rs:342,357); аналогичные meta_ev есть в tg.rs и relay.rs (там tun=0).

### fn dummy_tunnel() -> Tunnel (строки 121-140)
- назначение: заглушка Tunnel с i=0, всеми строковыми полями "local", ip 127.0.0.1, port 0.
- **мёртвый код**: единственный вызов — main.rs:365 `let _dummy = Arc::new(dummy_tunnel());`, переменная `_dummy` дальше нигде не используется. Судя по имени, осталась от старой схемы, где local-режим шёл через «нулевой туннель».

### fn load_targets(p: &PathBuf) -> Result<Vec<Target>, String> (строки 142-163)
- назначение: прочитать `targets.json`.
- что внутри: читает файл, проверяет UTF-8 (simdutf8), парсит JSON, берёт массив `v["targets"]`, оставляет только строки, начинающиеся с `"http"`, для каждой — Target{host: ctx::host_of(u), url}. Пустой результат → Err("targets.json: no http targets").
- формат входа: `{"targets": ["https://...", ...]}` — файл `$AF_ROOT/targets.json` (в корне репо он есть).

### async fn main (строки 165-171), #[tokio::main]
- назначение: обёртка; `run().await`, при Err печатает `[afeye] fatal: {e}` и `exit(1)`. Успех → код возврата 0. Других кодов возврата нет.

### async fn run() -> Result<(), String> (строки 173-740) — ядро
Порядок выполнения по шагам:

1. **Аргументы и режим** (174-184):
   - `test` = наличие `--test` или `-test` в argv (единственные CLI-флаги; парсера аргументов нет);
   - `t0 = Instant::now()`, `t0ms = now_ms()`;
   - `root = $AF_ROOT` (дефолт `.`);
   - `local = $AF_LOCAL задан ИЛИ test`;
   - если НЕ local и euid != 0 → Err("run as root or set AF_LOCAL=1");
   - `browse = AF_BROWSE_SECS` (дефолт: test → 200, иначе 2280 = 38 мин);
   - `hard = AF_HARD_SECS` (дефолт: test → 320, иначе 39*60 = 2340 c).
2. **Пути и каналы** (185-189): `stage = /tmp/afeye/stage`, `out = $root/dumps`; два unbounded crossbeam-канала: `tx/rx` (FxEvent) и `atx/arx` (Art); `load_targets($root/targets.json)` — ошибка фатальна.
3. **Туннели** (190-214): только если !local — читает каталог `$root/wg`, собирает все `*.conf` (имя = stem файла, содержимое = строка), сортирует по (имя, содержимое), парсит каждый через `wg::parse_conf(i = номер+1, name, raw)`; ошибка парсинга — пропуск с логом `[afeye] skip {name}: {e}`.
4. **Интернер** (215-221): интернируются хосты таргетов и все имена вендоров из VENDORS (стабильные id 1..N).
5. **Идентификаторы рана** (222-226): `binding = "_k{t0ms%997}z"`; `slot = timefmt::slot(t0ms, 30)`; `rid = timefmt::run_id(t0ms)`; `stage_run = stage/<slot>`; create_dir_all(stage_run) — ошибка фатальна.
6. **Raw-директория** (227-244): `raw_dir = $AF_RAW_DIR` (дефолт `/tmp/afeye-raw`); mkdir; на unix выставляет права 0777 (chrome-процессы разных пользователей fx{i} пишут туда); удаляет ВСЕ старые `*.rec` — чистый старт.
7. **Коллектор** (245): `collect::Collector::spawn(&stage_run)` — отдельный поток `afeye-collect`, который каждые 200 мс (первые 10 тиков) / 2000 мс сканирует `$AF_RAW_DIR` и перекладывает записи в `stage_run/collect`. Важно: Collector::spawn сам читает `AF_RAW_DIR` (collect.rs:415-420, дефолт DEFAULT_RAW_DIR=/tmp/afeye-raw) — согласован с шагом 6 по одному и тому же env.
8. **Chrome и UA** (246-247): `find_chrome()` (ошибка фатальна: "chrome binary not found"); `user_agent_for(&chrome)`.
9. **Xvfb** (248-252): local → None; иначе `browser::spawn_xvfb()?` (ошибка фатальна).
10. **Ctx** (253-275): конструируется `Arc<Ctx>` со всеми полями (см. ctx.rs); `display` = display Xvfb или "" ; `gl_spoof = $AF_GL_SPOOF задан`; после создания интернируются endpoint'ы туннелей с заменой `:` → `_` (main.rs:273-275) — те же id, что в шаге 17.
11. **Writer** (276): `writer::spawn(rx, arx, ctx)` — поток `afeye-writer` (пиннится на последнее ядро, writer.rs:436-440), потребитель обоих каналов; пишет meta.jsonl/lexicon.json/artifacts в stage.
12. **Sink-probe** (277-293): поток `afeye-sink-probe` спит 30 с, зовёт `collector.hellos_handle()` (сумма per-счётчиков `v8/sink-hello`, `blink/sink-hello`, `net/sink-hello`); 0 → WARN «sink layer DEAD: chrome has no afeye sinks (stock build?) - deep v8/blink/net raw records missing, CDP layer only»; иначе «sink layer alive: {n} sink-hello records».
13. **Runner IP** (294-298): local → "local"; иначе `wg::runner_ip()` — curl `https://www.cloudflare.com/cdn-cgi/trace`, парсит строку `ip=`; неуспех → "unknown".
14. **Лог старта** (299-303): `[afeye] run {rid} slot {slot} runner {ip} targets N tunnels M`.
15. **Поднятие туннелей** (304-362, только !local):
    - work dir `/tmp/afeye/wg`;
    - параллельно (join_all) для каждого туннеля: `wg::prep_user_dirs(t)` (пересоздать и chown `/tmp/afeye/p{i}`, `/tmp/afeye/h{i}`) && `wg::setup(t, work)` (netns add, veth-пара, wg-устройство, маршруты, `/etc/netns/<ns>/resolv.conf`); провал → лог + немедленный `wg::teardown`;
    - затем параллельно `wg::verify(t)`: внутри netns под пользователем curl `https://www.cloudflare.com/cdn-cgi/trace` (--max-time 15) → строка `ip=`; успех: `t.egress = Some(ip)`, meta-событие `{"egress":"<ip>","endpoint":"<ep>","ok":true}`, туннель (уже Arc) в список `good`; провал: meta-событие с `"ok":false,"err":"..."` + teardown.
16. **spawn_tabs-замыкание** (363-395): `let _dummy = Arc::new(dummy_tunnel());` (мёртвый, см. выше); замыкание `spawn_tabs(b: Browser, tun: u32)` — на каждый таргет: `b.new_page("about:blank")` с таймаутом TAB_UP (90 c), провал → None (вкладка молча теряется); `site = intern(tg.host)`; строит `capture::Tb{ctx, tun, site, tab: i, page, meta: default}`; `capture::instrument(tb, url)` под таймаутом TAB_UP — навешивает CDP-биндинг `ctx.binding`, инжектирует `inject::source` на каждый новый документ, включает Network/Debugger/Runtime/Page-домены и auto-attach; результат Some(tb).
17. **Запуск браузеров**:
    - local (396-409): `port = AF_LOCAL_PORT` (дефолт 9600); `browser::launch_chrome_local(&ctx, port)`; child в `children`; `browser::connect(&ctx, "127.0.0.1", port)`; `tun = intern("local")`; `spawn_tabs` через join_all, успешные Tb — в `tbs`;
    - туннельный (410-431): FuturesUnordered по `good`: `tun_id = intern(endpoint с ':' → '_')`, `browser::run_tunnel` → (child, browser); ok — child в children, `join_all(spawn_tabs(b, tun_id))` в tbs; err — лог `[afeye] {name} browser: {e}`.
18. **Расчёт длительности сессии** (432-444):
    - лог `[afeye] browsing tabs={} setup={}s`;
    - `left = (deadline - now) - reserve`, где reserve = 420 c если hard > 600 c, иначе 90 c; floor 30 c — резерв на финализацию/упаковку до жёсткого дедлайна;
    - `want = browse - elapsed`;
    - `session = min(want, left)`; `end = now + session` (tokio Instant).
19. **Фоновые задачи сессии** (445-478):
    - `tabs: Vec<capture::Tab>` — облегчённые копии (page/site/tun/tab) для human/relay;
    - `hb = tokio::spawn(human::drive(ctx, tabs))` — эмуляция человека: клики/движение мыши/скроллы/периодические reload (AF_RELOAD_SECS, дефолт 70);
    - relay: включается только если `$AFEYE_QUEUE_URL` начинается с "http" → `tokio::spawn(relay::run(ctx, tabs))` — поллинг внешней очереди JS-заданий (GitHub API или сырой URL), исполнение во всех вкладках, state в `stage_run/relay-state.jsonl` и `$AF_ROOT/dumps/relay-state.jsonl`;
    - tg: включается если `!test && $AFEYE_TG_TOKEN непуст && $AFEYE_TG_CHAT непуст` → отдельный std-поток `afeye-tg` с СОБСТВЕННЫМ current-thread tokio-рантаймом, внутри `tg::run(ctx)`: каждые `AFEYE_TG_EVERY` (дефолт 300 c, минимум 5) копирует stage (hardlink-копия в `/tmp/afeye/tg/ck{N}`), прогоняет classify::run, пакует 7z с томами по 49 МБ (лимит Telegram 50 МБ) или zip, шлёт sendDocument'ами, логирует meta-событиями.
20. **Ожидание конца** (479-482): `tokio::select!` между `sleep_until(end)` и `ctrl_c()`. **Обрабатывается только SIGINT (ctrl_c); SIGTERM-хендлера нет** — SIGTERM убьёт процесс без финализации (zip не соберётся).
21. **Финализация** (483-531):
    - лог `[afeye] session end, finalizing`;
    - `cn.stop = true` (Release) — relay/tg начинают выходить;
    - `hb.abort()` + await (human-драйвер убивается жёстко);
    - relay: await handle → RelayOut (паник/ошибка → {0,0});
    - tg: `join()` потока → TgOut (нет потока/ошибка → {0,0});
    - все Tb параллельно (tokio::spawn) → `capture::finalize(tb)`: снимает outerHTML (`.final.html`), скриншот PNG (`.shot.png`), cookies.json, localStorage/sessionStorage (`.storage.json`) — каждый с 5-секундным таймаутом;
    - убийство chrome (508-519): на каждом child — `start_kill()` + `wait()`, затем `pkill -TERM -f <путь chrome>` (по всей машине!), и `c.kill()`;
    - sleep 1200 мс (520) — grace-период, чтобы chrome дописал `.rec`-парты;
    - `pkill -KILL -f <путь chrome>` (521-526) — добить всех;
    - !local: `wg::teardown(t)` для КАЖДОГО туннеля из ctx.tunnels (netns del, link del, pkill -KILL -u fx{i}) — включая уже упавшие на шаге 15.
22. **Остановка коллектора и sink_alive** (532-546): `collector.stop()` (флаг stop, join потока, финальный scan, Stats{records, bytes, truncated, corrupt, files, per}); `sink_alive` = сумма счётчиков `v8/sink-hello`+`blink/sink-hello`+`net/sink-hello` > 0; если false — финальный WARN «zip carries CDP-layer capture only (chrome is not afeye-patched)»; лог collect-статистики.
23. **bctrace** (547-559): `afeye::bctrace::run(&stage_run.join("collect"))` — декодирует сырой поток инструкций Ignition (патч 0033), строит CFG на функцию, помечает мёртвые блоки «по факту» (смещений нет в исполненном потоке). Запускается ДО sinkfilter, потому что sinkfilter при успехе удаляет collect/raw, а трейс-записи лежат в part-файлах там же (комментарий 547-551). Успех с instructions>0 → лог `instructions/funcs/blocks live/dead/bytes live/dead`; Ok с 0 инструкций → тишина; Err → лог.
24. **sinkfilter** (560-584): `sinkfilter::run(&stage_run.join("collect"))` — фрагменты/цепочки/hot/cold/wasm/net/token/dead-end/verdicts/graph; при успехе печатает 3 лога (фрагменты+цепи, вердикты+граф, dead-end split); если `sf.records > 0` — удаляет `stage_run/collect/raw` (сырьё больше не нужно, filtered-отчёт остаётся); при Err — raw сохраняется «for debug».
25. **Закрытие writer'а** (585-599): meta-событие `{"end":true}` в tx; `cn.dead = true` (Release); `drop(tx); drop(atx)` — каналы закрываются, writer дорабатывает очереди и выходит; `writer.join()`.
26. **classify** (600-611): `classify::run(&stage_run)` → ClsOut{af, garbage, neutral, scripts, kept, dup, art_rm, bytes_rm}; лог `[afeye] classify: ...`.
27. **Filtered-архив** (612-669):
    - `out` = `$root/dumps` (mkdir, фатально при ошибке); `stem = timefmt::zip_stem(t0ms)` = `afeye-YYYYMMDD-HHMMSS`;
    - копия stage_run в `/tmp/afeye/filtered` через `arch::copy_tree` (hardlink-first, fallback copy);
    - `classify::strict(&fdir)` — строгий режим дорезает мусор;
    - читает `fdir/collect/filtered/report.json`: если есть массив `prune` — удаляет перечисленные `path` (относительно `fdir/collect`); иначе если есть массив `chains` — удаляет все цепи с `token_forming != true`; счётчик dropped; лог `[afeye] filtered zip: {dropped} dead-end chains removed (token-only)`;
    - упаковка: если `arch::have_7z()` (проба `7z i`/`7zz i`/`7za i`) — `arch::sz_pack(&fdir, out/<stem>-filtered.7z, 0)` (volume 0 = один файл); иначе `zipper::pack` в `<stem>-filtered.zip`; размер/имя — в filtered_bytes/filtered_name; fdir удаляется.
28. **Манифест и главный zip** (670-738):
    - MRun заполняется из счётчиков Cn (Relaxed-load), endpoints.len(), relay_out.executed, tg_out.sent, cls.*, cstats.*, sink_alive, sf_stats.{chains,hot_chains,cold_chains,wasm_modules}, test;
    - `stage/manifest.json` = pretty-JSON MRun с `zip_bytes: 0` (пишется ДО упаковки — внутри zip поле zip_bytes всегда 0; актуальное значение — только во внешнем манифесте, шаг ниже);
    - **`zipper::pack(&stage, &zp)`** — пакуется ВЕСЬ корень `/tmp/afeye/stage` (все слоты, если их несколько), не только stage_run; `zp = dumps/<stem>.zip`; ошибка фатальна (единственный `?` на этом этапе);
    - размер > 95 МБ → WARN «zip > 95MB, lower AF_BUDGET_MB»;
    - `dumps/<stem>.manifest.json` = тот же MRun, но с реальным `zip_bytes`;
    - логи `[afeye] ZIP {path} files={n} bytes={size}` и `[afeye] done in {N}s`; Ok(()).
- **Коды возврата**: 0 — нормальное завершение (включая ctrl-C во время сессии: select ловит его и проводит полную финализацию); 1 — любая Err из run() (нет root/AF_LOCAL, нет targets, нет chrome, mkdir/zip-ошибки, Xvfb-таймаут).

### fn is_root() -> bool (строки 742-744)
- `unsafe { geteuid() == 0 }`.

### unsafe fn geteuid() -> u32 (строки 746-758)
- назначение: euid без зависимости от libc-крейта (хотя libc в Cargo.toml есть и используется другими модулями).
- что внутри: на unix — `extern "C" { fn geteuid() -> u32; }` и прямой вызов; на не-unix — константа 1 (то есть «не root»; non-unix без AF_LOCAL не запустится).

### fn user_agent_for(chrome: &PathBuf) -> String (строки 760-780)
- назначение: построить UA под реальную версию chrome, без токена HeadlessChrome.
- что внутри: запускает `chrome --version`, ловит stdout; ищет токен версии — слово, у которого ≥3 частей по точке и все части непустые ASCII-цифры; версия не найдена → хардкод-fallback `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36`; иначе лог `[afeye] chrome {ver} -> UA override (no HeadlessChrome token)` и UA с этой версией.
- связи: результат в `Ctx.ua` → `--user-agent` во всех launch'ах.

### fn find_chrome() -> Option<PathBuf> (строки 782-815)
- назначение: найти бинарь chrome.
- что внутри: 1) `$AF_CHROME` — если путь существует, возвращается как есть; 2) иначе обход списка в порядке приоритета: `google-chrome-stable`, `google-chrome` (через `which`), `/tmp/cft/chrome-linux64/chrome` (по exists), `chromium-browser`, `chromium` (через which), `/opt/afeye-chrome/chrome`, `/opt/afeye-chrome/headless_shell` (по exists); 3) ничего → None.
- связи: None фатален в run() («chrome binary not found»).

## Сводка: CLI-флаги
| Флаг | Действие | Дефолт |
|---|---|---|
| `--test` / `-test` | test-режим: local=да, browse=200 c, hard=320 c, tg-поток выключен, в манифесте `test:true` | выкл |

Других CLI-флагов нет (argv просто сканируется на эти две строки).

## Сводка: env-переменные (читаемые Rust-стороной)
| Переменная | Где | Дефолт | Действие |
|---|---|---|---|
| `AF_ROOT` | main.rs:178, relay.rs | `.` | корень: targets.json, wg/, dumps/ |
| `AF_LOCAL` | main.rs:179 | не задан | local-режим без root/netns; включается также --test |
| `AF_BROWSE_SECS` | main.rs:183 | 2280 (test: 200) | желаемая длительность сессии сбора |
| `AF_HARD_SECS` | main.rs:184 | 2340 (test: 320) | жёсткий дедлайн (ctx.deadline) |
| `AF_RAW_DIR` | main.rs:227, collect.rs:417, browser.rs:131,168 | `/tmp/afeye-raw` | куда патченый chrome пишет `.rec`, откуда читает Collector |
| `AFEYE_RAW_DIR` | browser.rs:130,167 | см. AF_RAW_DIR | приоритетный alias, пробрасывается в chrome |
| `AFEYE_SINK` | browser.rs:133,169 | `1` | пробрасывается в chrome; включает afeye-синки (патчи) |
| `AF_CHROME` | main.rs:783 | автопоиск | путь к бинарю chrome |
| `AF_GL_SPOOF` | main.rs:271 | не задан (false) | WebGL-spoof в инжекте (inject.rs) |
| `AF_BUDGET_MB` | main.rs:94 | 350 | лимит байт артефактов на ран |
| `AF_LOCAL_PORT` | main.rs:397 | 9600 | CDP-порт local-chrome |
| `AF_TEST_HEADLESS` | browser.rs:85 | не задан | `--headless --disable-gpu` (тестовый) |
| `AF_JITLESS` | browser.rs:93 | не задан | `=1` → `--jitless` + `--js-flags=--jitless --no-opt --no-sparkplug` (весь JS в Ignition для патча 0033) |
| `AF_DEBUG_ARGS` | browser.rs:175 | не задан | печатать argv chrome (local) |
| `AF_DEBUG_HTTP` | browser.rs:206,222 | не задан | отладка handshake devtools |
| `DISPLAY` | browser.rs:31-34 | — | если задан — Xvfb не поднимается, используется он |
| `AFEYE_QUEUE_URL` | main.rs:455, relay.rs | — | URL очереди relay (вкл. только если начинается с http) |
| `AFEYE_QUEUE_TOKEN` | relay.rs | — | Bearer-токен для очереди |
| `AFEYE_RELAY_POLL` | relay.rs | 30 (мин 5) | период поллинга очереди, сек |
| `AFEYE_TG_TOKEN` | main.rs:462, tg.rs | пусто | Telegram bot token (вкл. tg-поток только в не-test режиме) |
| `AFEYE_TG_CHAT` | main.rs:463, tg.rs | пусто | chat_id |
| `AFEYE_TG_EVERY` | tg.rs | 300 (мин 5) | период чекпоинтов в TG, сек |
| `AF_RELOAD_SECS` | human.rs:158 | 70 | период reload страниц human-драйвером |

Env, читаемые патченым chrome (C++-сторона, пробрасываются/документируются в patches/SERIES.md): `AFEYE_SINK`, `AFEYE_RAW_DIR`, `AFEYE_VIRTUAL_CLOCK` (патч 0034 — виртуальные часы, скрывают тайминговые аномалии jitless), `AFEYE_TRACE_BYTECODE` (=0 выключает трейс 0033), `AFEYE_BC_CAP` (переопределяет квоту 50M инструкций на процесс).

## Сводка: chrome-флаги (chrome_flags, browser.rs:58-106)
Постоянные: `--no-first-run`, `--no-default-browser-check`, `--disable-session-crashed-bubble`, `--hide-crash-restore-bubble`, `--disable-search-engine-choice-screen`, `--disable-features=IsolateOrigins,site-per-process,PrivacySandboxSettings4`, `--disable-site-isolation-trials`, `--enable-unsafe-swiftshader`, `--password-store=basic`, `--use-mock-keychain`, `--no-sandbox`, `--remote-debugging-address=<ns_ip|127.0.0.1>`, `--remote-debugging-port=<9400+i|AF_LOCAL_PORT=9600>`, `--user-data-dir=</tmp/afeye/p{i}|/tmp/afeye/local>`, `--window-size=1280,832`, `--window-position=<(i%4)*320>,<(i/4)*250>`, `about:blank`.
Условные: `--user-agent=<ua>` (ua непуст), `--headless --disable-gpu` (AF_TEST_HEADLESS задан ИЛИ бинарь headless_shell — возможна дублирующая пара), `--jitless` + `--js-flags=--jitless --no-opt --no-sparkplug` (AF_JITLESS=1; js-flags-строка добавлена в рабочем дереве, в HEAD её нет).

## Взаимодействия (main.rs)
- использует все bin-модули: wg (parse_conf/setup/verify/teardown/runner_ip/prep_user_dirs), browser (spawn_xvfb/launch_chrome_local/connect/run_tunnel), capture (Tb/Tab/instrument/finalize), human (drive), relay (run/RelayOut), tg (run/TgOut), writer (spawn), classify (run/strict), timefmt (slot/run_id/zip_stem), arch (copy_tree/have_7z/sz_pack), zipper (pack), arena (Interner), ctx, events, inject (косвенно через capture).
- из lib-крейта: afeye::collect (Collector), afeye::sinkfilter (run/SinkFilterStats), afeye::bctrace (run).
- данные: канал tx/atx → writer → файлы в stage_run; `.rec` из AF_RAW_DIR → Collector → stage_run/collect; bctrace/sinkfilter/classify пост-обрабатывают stage_run; zipper/arch пакуют в `$AF_ROOT/dumps/`; tg параллельно шлёт копии в Telegram; relay читает внешнюю очередь и исполняет JS во вкладках.
- потоки/задачи: tokio-рантайм main + std-потоки afeye-writer, afeye-collect, afeye-sink-probe, afeye-tg (со своим мини-рантаймом) + tokio-задачи human::drive и relay::run.

## Замеченные дырки и подозрительные места (orchestration)
1. **Мёртвый код**: `dummy_tunnel()` + `_dummy` (main.rs:121-140, 365) — создаётся и не используется.
2. **connect() игнорирует ctx** (browser.rs:245 `let _ = ctx;`) — параметр-рудимент.
3. **SIGTERM не обрабатывается** — только SIGINT через `tokio::signal::ctrl_c()`. При `kill` (TERM) раннер умрёт без финализации: zip/манифест не соберутся, netns/пользователи могут остаться (teardown не выполнится).
4. **`pkill -TERM/-KILL -f <путь chrome>`** (main.rs:514-516, 523-525) бьёт по ВСЕМ процессам chrome с этим путём на машине — два параллельных рана прибьют браузеры друг друга.
5. **`zipper::pack(&stage, ...)` пакует весь `/tmp/afeye/stage`**, а не только текущий слот — при нескольких ранах подряд zip включает чужие слоты; `stage/manifest.json` перезаписывается каждым раном.
6. **manifest.json внутри zip имеет `zip_bytes: 0`** (пишется до упаковки, main.rs:713, 727-728); реальное значение только в `dumps/<stem>.manifest.json`.
7. **Дублирующая пара `--headless --disable-gpu`** возможна, если задан AF_TEST_HEADLESS и бинарь — headless_shell (browser.rs:85-92). Ещё один дубль: при AF_JITLESS=1 и chrome-level `--jitless` v8 получает `--jitless` дважды (chrome-флаг + внутри `--js-flags`), browser.rs:98-102.
8. **`budget_limit()` читает env на каждый вызов** (main.rs:93-95, вызов в capture.rs:134) — getenv в горячем пути на каждый артефакт.
9. **events.rs компилируется дважды** (bin + lib, см. раздел lib.rs) — типы несовместимы между крейтами, пересечение только по wire-форматам файлов.
10. **spawn_xvfb при заданном DISPLAY запускает процесс `true`** как placeholder (browser.rs:33) — работает, но неочевидно.
11. **В local-режиме `/tmp/afeye/local` удаляется только в launch_chrome_local** (browser.rs:158), profile туннелей `/tmp/afeye/p{i}` чистит wg::prep_user_dirs — симметрично, но в разных местах.
12. **Тихая потеря вкладок**: если `new_page`/`instrument` не уложились в TAB_UP=90 c, вкладка просто не попадает в tbs (main.rs:376-390), без лога.
13. **`AF_HARD_SECS` дефолт записан как `39 * 60`** (main.rs:184), а `AF_BROWSE_SECS` — 2280; резерв финализации 420 c (main.rs:440) подобран под hard=2340: browse+reserve = 2700 > hard — фактическая сессия всегда режется по `left`, т.е. browse ≈ hard - setup - 420.

---

## АУДИТ СООТВЕТСТВИЯ ЭТАЛОНУ

Сравнение реального кода репо с эталонной архитектурой «тотального инспектора JS-движка» (4 пункта + формат лога). Номера строк патчей — строки самих `.patch`-файлов в `patches/`.

### 1. Отключение JIT: --jitless / --no-opt / --no-sparkplug

- `--jitless`: **ЕСТЬ**, src/browser.rs:93-103 (рабочее дерево). Гейт: `std::env::var("AF_JITLESS") == "1"` (строка 93, строгое равенство строке "1"), push флага — строка 98. Комментарий browser.rs:94-97: interpreter-only mode, «nothing escapes to Sparkplug/Maglev/TurboFan machine code», тайминги закрывает AFEYE_VIRTUAL_CLOCK (0034).
- `--no-opt` и `--no-sparkplug`: **ЕСТЬ в рабочем дереве, НЕТ в HEAD**. git diff (2026-09-24, +4 строки в browser.rs) добавил под тем же гейтом `--js-flags=--jitless --no-opt --no-sparkplug` (browser.rs:99-102) с комментарием «pin all three explicitly per the analysis contract». Все три флага эталона теперь передаются (jitless как chrome-флаг, остальные — через --js-flags в v8).
- Итог: **соответствует (в рабочем дереве)**. Оговорки: (а) правка не закоммичена — в HEAD эталонных `--no-opt`/`--no-sparkplug` нет; (б) проверить на реальном бинаре, что тир-генерация действительно выключена, из этого репо нельзя — **не нашёл** ни теста, ни метрики покрытия (bctrace.rs:568-582 считает мёртвые блоки CFG по факту исполнения, а не «утечки» в JIT-код).
- Риск-факт: AF_JITLESS по умолчанию НЕ задан → ран без него исполняет JS с JIT, и трейс 0033 видит только интерпретаторные инструкции — горячие циклы после оптимизации в лог не попадают вообще. Никакого WARN на этот случай в main.rs/browser.rs нет (в отличие от sink-probe, main.rs:277-293).

### 2. Патч диспетчера Ignition (патч 0033)

Файлы патча (0033-v8-ignition-bytecode-trace.patch, 929 строк): `v8/src/afeye/bcrec.h` (новый, строки 1-366), `v8/src/afeye/sink.cc` (367-387), `v8/src/afeye/sink.h` (388-414), `v8/src/interpreter/interpreter-assembler.cc` (415-454), `v8/src/runtime/runtime-trace.cc` (455-900), `v8/src/runtime/runtime.h` (901-929).

- Точка хука: **НЕ соответствует эталону по месту, соответствует по покрытию**. Эталон: `GENERATE_BYTECODE_HANDLER` в `src/interpreter/interpreter-generator.cc`. Реально: `interpreter-generator.cc` не тронут; хук в ДВУХ местах `v8/src/interpreter/interpreter-assembler.cc`:
  1. конструктор `InterpreterAssembler::InterpreterAssembler` (патч 419-436): `CallRuntime(Runtime::kAfeyeTraceBytecodeEntry, GetContext(), BytecodeArrayTaggedPointer(), SmiTag(BytecodeOffset()), GetAccumulatorUnchecked(), SmiTag(operand_scale_))` — патч 430-432. Комментарий патч 421-427: конструктор компилируется генератором ВНУТРЬ каждого bytecode handler, т.е. каждый dispatch исполняет вызов; operand_scale — codegen-константа на handler, Wide/ExtraWide несут истинный scale.
  2. `InterpreterAssembler::InlineShortStar` (патч 438-453): тот же CallRuntime с `OperandScale::kSingle` (патч 446-449) — потому что Star0-Star15 инлайнятся в предыдущий handler через StarDispatchLookahead и конструктор не проходят (комментарий патч 440-443). Подтверждено в patches/SERIES.md:86.
- Регистрация рантайм-функции: `FOR_EACH_INTRINSIC_AFEYE` → `F(AfeyeTraceBytecodeEntry, 4, 1, kCannotTriggerGC)` (патч 910-914), вклеен в FOR_EACH_INTRINSIC_TRACE (патч 923-927). Под `#ifdef V8_AFEYE`.
- Что фиксируется реально (RUNTIME_FUNCTION, патч 750-898) vs эталон:
  - `BytecodeOffset`: **ЕСТЬ** — arg1 (Smi), конвертация в логический offset `bytecode_offset - kHeaderSize + kHeapObjectTag` (патч 780-783), bounds-check (784-786), пишется в Hdr.offset (InstrBuilder::Begin, патч 149-161; bcrec.h Hdr патч 36-57).
  - опкод: **ЕСТЬ** — реальный байт по pc после consumption Wide-префиксов (патч 792-796), Hdr.opcode.
  - аргументы (операнды): **ЕСТЬ и полнее эталона** — декодируются САМИМ ДВИЖКОМ (`BytecodeDecoder::DecodeRegisterOperand/DecodeUnsignedOperand/DecodeSignedOperand`, патч 822-878), эмитятся блоками kTagOperand=[u8 idx][u64 value] (bcrec.h патч 75-77, InstrBuilder::Operand патч 163-169). Для register-операндов дополнительно дампятся ЗНАЧЕНИЯ регистров: raw word (kTagReg), полная строка 8-bit/UTF-16LE (kTagRegStr/kTagRegStr16), f64 (kTagRegF64), Smi (kTagRegSmi) — патч 838-863; RegList раскрывается по count (патч 830-836).
  - имя свойства из пула констант: **ЕСТЬ** — весь constant pool эмитится в func-def блобе (AfeyeEmitFuncDef, патч 658-745: CpSpan kCpTagStr/kCpTagStr16/kCpTagF64/kCpTagRaw, патч 681-724); на Rust-стороне операнды LdaConstant/GetNamedProperty/CallProperty/... резолвятся через cp (bctrace.rs:638-663).
  - регистры источника и приемника: **частично** — входные регистры дампятся (см. выше); «приемник» как отдельное поле отсутствует, но аккумулятор в КАЖДОЙ записи: raw word в Hdr.acc (передается GetAccumulatorUnchecked, патч 430-432; ib.Begin acc_word, патч 800-803) + полное значение блоками kTagAccStr/kTagAccF64/kTagAccSmi с флагом kFlagAccPayload (патч 879-895; bcrec.h 200-217). Результат write-acc инструкций выводится на Rust-стороне как acc следующей записи того же (pid, iso) — bctrace.rs:741-750, 768-774, правило зафиксировано в summary["rule"] (bctrace.rs:780).
  - SharedFunctionInfo: **ЕСТЬ** — `frame->function()->shared()` через JavaScriptStackFrameIterator (патч 804-808); идентичность func_id = FNV-1a(script_id, function_literal_id, StartPosition, isolate_tag)>>16 — детерминированная, GC-стабильная (MakeFuncId, патч 120-134; использование патч 810-812).
  - имя скрипта: **ЕСТЬ** — байты имени скрипта в func-def блобе (патч 663-679 + FuncDefBuilder патч 255-292), плюс стартовая line-номер функции (патч 667-669, Hdr.line func-def-записи). **Имя самой ФУНКЦИИ (SFI name) не эмитится** — в FuncDef.name лежит имя СКРИПТА (bctrace.rs:570 `"name": def.name`). Эталон требует «имя исходного скрипта» — это есть; function_name как отдельное поле — нет (см. п.5).
- Дополнительно сверх эталона: полный байткод функции в func-def (fb.Build с GetFirstBytecodeAddress, bc_len, frame_size, parameter_count — патч 727-732); meta-запись с именами/размерами/флагами всех опкодов и таблицей runtime-имён (AfeyeEmitMeta, патч 589-655); сплит записей >1 MiB через kFlagCont с побайтовой склейкой (EmitSplit, патч 338-361; Rust-склейка bctrace.rs:433-521).
- Гейты: `v8::afeye::Enabled()` (AFEYE_SINK) — ранний выход (патч 751-753); `AFEYE_TRACE_BYTECODE=0` — полное выключение трейса (AfeyeBcOff, патч 501-507).
- Дедупликация func-def: thread_local `unordered_set<(func_id, bc_len)>` g_afeye_seen (патч 541-549, 813-816) — точная, без лимита размера.
- **Расхождение с docs**: patches/SERIES.md:85 заявляет «Квоты: 50M инструкций на процесс (backstop), AFEYE_BC_CAP переопределяет». В патче 0033 НИ `AFEYE_BC_CAP`, НИ 50M-квоты НЕТ (grep по патчу: только kSinkRecordCap=1MiB-16 для сплита записей, патч 89). Комментарий патча прямо говорит «No caps, no truncation» (патч 495). SERIES.md устарел/противоречит коду.

### 3. Виртуализация таймингов (патч 0034)

Файлы патча (0034-v8-blink-virtual-clock.patch, 85 строк): `third_party/blink/renderer/core/timing/performance.cc` (строки 1-50) и `v8/src/objects/js-objects.cc` (строки 51-85).

- `src/base/platform/time.cc`: **НЕ тронут**. Физический `Clock::Now()`/`base::TimeTicks` глобально НЕ заменялся.
- `Performance::now()`: **ЕСТЬ** — патч 19-43 (hunk @@ -1373,6 +1380,25 performance.cc). Под `#ifdef BLINK_AFEYE` + `blink::afeye::Enabled()` + env `AFEYE_VIRTUAL_CLOCK` (вкл если задан и не начинается с '0', патч 30-33): возвращает `g_afeye_origin_ms + afeye_vclock_ns()/1e6` (патч 38-39), где origin = `base::TimeTicks::Now().since_origin().InMillisecondsF()`, захваченный один раз (static, патч 35-37). Stock-ветка `MonotonicTimeToDOMHighResTimeStamp` сохраняется как fallback (патч 43).
- `Date.now()` / `new Date()`: **ЕСТЬ** — `JSDate::CurrentTimeValue` в v8/src/objects/js-objects.cc, патч 61-85 (hunk @@ -5914,6 +5918,25): `g_afeye_epoch_ms + afeye_vclock_ns()/1e6` (патч 78-79), epoch = `V8::GetCurrentPlatform()->CurrentClockTimeMilliseconds()` один раз (патч 75-77), гейт тот же (патч 70-73).
- Формула `virtual_time += kBaseInstructionCost * instruction_count`: **соответствует по сути, реализована иначе**. Инкремент не в 0034, а в 0033: `v8::afeye::VclockTick(AfeyeVclockNsPerInstr())` на КАЖДУЮ исполненную инструкцию внутри RUNTIME_FUNCTION (патч 0033:768-770). Стоимость: env `AFEYE_VCLOCK_NS_PER_INSTR`, дефолт **10 нс/инструкция** (AfeyeVclockNsPerInstr, патч 0033:517-524). Счётчик: `std::atomic<uint64_t> g_vclock_ns` + `extern "C" afeye_vclock_ns()` + `VclockTick()` в v8/src/afeye/sink.cc (патч 0033:375-383), декларации sink.h (патч 0033:409-410); blink линкуется напрямую, т.к. renderer-бинарь содержит и v8, и blink (комментарий патч 0034:9-14).
- Чего НЕ хватает относительно эталона («физический Clock::Now() заменяется»):
  - `performance.timeOrigin` — не патчился (только now());
  - прочие источники времени (base::TimeTicks в Blink scheduler, таймеры, CDP-таймстемпы) — физические;
  - **ts самих sink-записей — реальное монотонное время**: `NowNs() = MonoNs() = CLOCK_MONOTONIC` (патч 0001:92-97, 235; emit 0033 использует `v8::afeye::NowNs()`, патч 0033:582-583). Виртуальное время видно ТОЛЬКО странице через now()/Date, в логе его нет.

### 4. WebIDL/DOM-биндинги (патчи 0008, 0024, 0019)

- Место: **НЕ `src/bindings/core/v8/`**, а `third_party/blink/renderer/platform/bindings/idl_member_installer.cc` (0008:1-3, 0024:1-4). Эталонный V8DOMConfiguration не тронут; перехват на уровне установки IDL-членов.
- 0008-blink-dom-api.patch (202 строки): механизм обёртки. `AfeyeApiCell{orig: v8::FunctionCallback, prop, what[104]}` (патч 24-28), таблица 65536 ячеек с линейным пробингом по `(orig>>4)` (патч 29-31, 57-79), `AfeyeWrapDomApi` формирует строку-идентификатор `"dom {interface}.{get|set|call} {property}"` (snprintf, патч 69-71) и возвращает External в data-слот; `CreateFunctionTemplate/CreateFunction` подменяют callback на `AfeyeDomApiThunk` (патч 83-146); подключено в `InstallAttribute` (get И set, патч 151-179) и `InstallOperation` (патч 181-202) — т.е. ВСЕ IDL-атрибуты и операции всех интерфейсов. Thunk эмитит `EmitStr(kDomApi=29, NowNs(), cell->what)` и зовёт оригинал (патч 34-50). Лимит: 8 000 000 вызовов на процесс (g_afeye_api_calls, патч 32, 41-43).
- 0024-blink-dom-api-values.patch (93 строки): **значение возврата — ЕСТЬ**. `AfeyeCaptureValue` (патч 25-73): undefined/null/булево 0|1/число `%.17g`/строка UTF-8 (управляющие символы → '?', обрезка по буферу 160)/`[array len=N]`/`[object]`. Порядок: СНАЧАЛА оригинальный callback, ПОТОМ захват `info.GetReturnValue().Get()` (патч 84-86), эмит `"dom X.get Y val=<...>"` (snprintf `"%s val=%.150s"`, буфер 320, патч 81-88). Гейт отключения: `AFEYE_TRACE_DOM_VALUES=0` (патч 20-23).
- АРГУМЕНТЫ вызова: **НЕТ** — thunk логирует только идентичность (интерфейс.доступ.свойство) и возвращаемое значение; JS-аргументы вызова (`info[0..]`) не захватываются ни в 0008, ни в 0024. Эталон требует «геттер/сеттер с переданными аргументами» — для операций (методов) это НЕ соответствует; для get/set атрибутов аргументов нет по природе (кроме значения setter'а, которое тоже НЕ логируется — GetReturnValue после set = undefined).
- ТИП возвращаемого значения: **явного поля типа нет**; тип восстанавливается из формы рендера значения ("undefined"/"null"/0|1/число/строка/`[array len]`/`[object]`, патч 0024:29-72). Частично соответствует.
- 0019-blink-fp-values.patch (341 строка): точечные value-синки (kind kFingerprint=16, 0005-blink-sink.patch:390) внутри конкретных реализаций, МИМО idl_member_installer: `CSSComputedStyleDeclaration::GetPropertyCSSValue` → `"css/get-computed prop=.. val=.."` (лимит 2M, патч 33-49), `FontFaceSet::check` → `"fonts/check font=.. text=.."` (лимит 200K, патч 83-97), `MediaQueryList::matches` → `"media/matches q=.. m=.."` (патч 133-145), `LocalDOMWindow::matchMedia` → `"media/query q=.."` (патч 181-193), `BaseRenderingContext2D::DrawTextInternal` → `"canvas/draw-text op=fill|stroke text=.. font=.. xy=.."` (лимит 2M, патч 222-240), `Notification::permission` → `"perm/notification value=granted|denied|prompt[|default] [ctx=insecure|prerender]"` (3 точки, БЕЗ лимита, патч 255-305), `Permissions::query` → `"perm/query name=.."` (патч 327-339). Здесь аргументы ЕСТЬ (prop, font/text, query, name, xy), значение ЕСТЬ — но только для этого фиксированного списка API, не для всех биндингов.
- Потребление: collect.rs маппит kind 29 → "dom-api" (collect.rs:45,60), 16 → "fingerprint" (collect.rs:32); sinkfilter парсит суффикс `" val="` (sinkfilter.rs:331) и использует dom-api/fingerprint как seed-категории (sinkfilter.rs:1694, 1728).

### 5. Финальный формат лога: эталон vs факт

Реальный wire (три уровня): (a) sink-запись = 16-байтный заголовок `[u32 total][u8 kind@4][u8 flags@5][2 байта @6-7][u64 ts@8 = CLOCK_MONOTONIC ns]` + payload (патч 0001:135-143; парсинг collect.rs:323-328); (b) payload bytecode-trace (kind 40) = 72-байтный bcrec::Hdr `[u8 opcode][u8 scale][u8 n_payload][u8 flags][u32 offset][u32 func_id][u32 line/iso_tag][u64 acc][u64 regs[6]]` (bcrec.h, патч 0033:36-57; static_assert 72 байта — патч 0033:57; Rust-константы bctrace.rs:21-25: HDR_LEN=72, OP_META=0xfe, OP_FUNC_DEF=0xff, FLAG_CONT=2, FLAG_ACC_PAYLOAD=4) + framed-блоки `[u8 tag][u32 len][bytes]` (патч 0033:70-90); (c) выход bctrace.rs: per-функция `collect/filtered/bctrace/{func_id:08x}.json` (bctrace.rs:568-588) и `collect/filtered/bctrace/sem/{func_id:08x}.jsonl` (bctrace.rs:711-750), summary `collect/filtered/bctrace.json` (bctrace.rs:766-786).

| Поле эталона | Есть ли реально | Где именно (файл:строка) | Что делать если нет |
|---|---|---|---|
| `timestamp_virtual` | НЕТ (ts записей = реальный CLOCK_MONOTONIC ns) | ts кладётся в sink: патч 0001:92-97 (MonoNs), 140; парсится collect.rs:325-328; в sem-jsonl как `"ts"` bctrace.rs:716. Виртуальный счётчик существует (g_vclock_ns, патч 0033:375-383), но в записи НЕ пишется | либо эмитить afeye_vclock_ns() вторым u64 в Hdr/payload instr-записи, либо считать на Rust-стороне: vts = vts0 + 10нс * порядковый номер инструкции (стоимость = AFEYE_VCLOCK_NS_PER_INSTR, патч 0033:517-524) |
| `script_id` | НЕТ в явном виде (входит в хэш func_id); имя скрипта есть | MakeFuncId(script_id, literal_id, start_pos, iso_tag) — патч 0033:120-134, вызов 810-812; script_id читается патч 809-810 но не эмитится; имя скрипта — func-def blob (патч 663-679), FuncDef.name → `"name"` отчёта bctrace.rs:570 | добавить i32 script_id в func-def blob (FuncDefBuilder.Build, патч 255-292) и в parse_func_def_blob (bctrace.rs:250-292) |
| `function_name` | НЕТ (есть только имя СКРИПТА и стартовая line функции) | FuncDef.name = script name (патч 0033:670-679); line = GetLineNumber(StartPosition) патч 667-669 → Hdr.line func-def → FuncDef.line → `"line"` bctrace.rs:571. sfi->Name() нигде не эмитится | эмитить `sfi->Name()` строкой в func-def blob рядом с script name |
| `bytecode_op` | ДА | Hdr.opcode патч 0033:37; имя опкода из meta-таблицы (AfeyeEmitMeta патч 589-655) → `"op": m.name` bctrace.rs:718 | — |
| `target_property` | ДА (не полем, а резолвингом операнда) | kTagOperand патч 0033:75-77, 163-169; cp-резолвинг GetNamedProperty/CallProperty/... bctrace.rs:638-663; агрегат-ключи `"prop {n}"`/`"call {n}"` bctrace.rs:676-699; плюс полный constant pool в func-def (патч 681-724) | — |
| `arguments_hash` | НЕТ как хэш; вместо него ПОЛНЫЕ значения (строже эталона) | engine-decoded операнды патч 0033:822-878; строки/f64/Smi регистров и аккумулятора патч 838-895; в sem-jsonl `"args"` bctrace.rs:720-722, `"acc"` 723-725, `"res"` 726-728, `"regs"` 730-748 | если нужен именно хэш — blake3 от args на Rust-стороне (blake3 уже в зависимостях, collect.rs:360) |

Дополнительно: реальная sem-запись jsonl (bctrace.rs:715-750) = `{ts, off, op, args?, acc?, res?, regs?}` на КАЖДУЮ исполненную инструкцию; per-func отчёт (bctrace.rs:568-588) = `{func_id, name, line, frame_size, param_count, bc_len, instructions, blocks, executions, live_blocks, dead_blocks, dead_ranges, first_ts}` — CFG/dead-blocks «по факту» (правило в summary["rule"], bctrace.rs:780). Формат — JSONL, как эталон и требует; protobuf нет.

### Сводка аудита

1. JIT-режим: в рабочем дереве соответствует — `--jitless` (browser.rs:98) + `--js-flags=--jitless --no-opt --no-sparkplug` (browser.rs:102) под гейтом AF_JITLESS=1; в HEAD последних двух нет (правка от 2026-09-24 не закоммичена). Дефолтный ран БЕЗ AF_JITLESS трейсит только интерпретатор, без предупреждения.
2. Диспетчер Ignition: по покрытию соответствует эталону и превосходит его (значения операндов/регистров/аккумулятора, constant pool, полный байткод, meta-таблица), но точка внедрения другая (constructor InterpreterAssembler + InlineShortStar, а не GENERATE_BYTECODE_HANDLER в interpreter-generator.cc). Функции-имени (function_name) не хватает.
3. Виртуальный clock: соответствует по формуле (10 нс × инструкция, AFEYE_VCLOCK_NS_PER_INSTR), но точечно: только Performance::now и JSDate::CurrentTimeValue; time.cc не тронут; ts в логе физический.
4. DOM-биндинги: место другое (platform/bindings/idl_member_installer.cc, не core/v8), покрытие полное по get/set/call всех IDL-членов, значение возврата есть (0024), ТИП явным полем нет, АРГУМЕНТЫ вызова не логируются.
5. Формат лога: JSONL есть; из шести эталонных полей полностью присутствуют bytecode_op и target_property, arguments_hash заменён полными значениями, timestamp_virtual/script_id/function_name отсутствуют (пути добавления указаны в таблице).
6. Прямое противоречие docs↔code: SERIES.md:85 обещает квоту 50M инструкций и env AFEYE_BC_CAP — в патче 0033 их нет (только сплит 1MiB-записей, kSinkRecordCap патч 0033:89).
