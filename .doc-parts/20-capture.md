# Сбор через CDP, инжект в страницу, relay-исполнение и эмуляция человека (capture.rs / relay.rs / inject.rs / human.rs)

Общий конвейер: `main.rs` поднимает Chrome (в netns через WireGuard-туннель или локально), создаёт по странице на target, для каждой страницы строит `capture::Tb` и вызывает `capture::instrument` → страница инжектится JS-харнессом (`inject::source`), включаются домены CDP, подписываются 17 обработчиков событий и выполняется `Page.navigate`. Всё, что приходит, превращается в `FxEvent` и уходит в unbounded-канал `ctx.tx`, который читает отдельный поток `writer`. Бинарные тела (JS/WASM/JSON/HTML/CSS/POST) уходят вторым каналом `ctx.art` с blake3-хэшем и бюджетом. Параллельно `human::drive` гоняет мышь/клавиатуру через `Input.dispatch*`, а `relay::run` (если задан `AFEYE_QUEUE_URL`) поллит очередь JS-снипетов и исполняет их во всех вкладках через `Runtime.evaluate`.

---

## src/capture.rs — сбор телеметрии страницы через Chrome DevTools Protocol

Импорты (строки 1-15): `crate::arena::fx64`, `crate::ctx::{char_floor, vendor_of_stack, vendor_of_url, Cn, Ctx}`, `crate::events::*`, `crate::inject`, `base64::Engine`, `bytes::{BufMut, Bytes}`, четыре домена CDP-типов (`network::*`, `page::*`, `debugger::*`, `runtime::*`), `chromiumoxide::{IntoEventKind, Page}`, `dashmap::DashMap`, `Arc`, `SystemTime`.

### type Meta = Arc<DashMap<u64, (u8, bool)>>  (строка 17)
- назначение: карта «request_id (fx64-хэш) → (код типа тела, флаг)» для отбора тел, которые надо скачать после `Network.loadingFinished`.
- что внутри: ключ — `fx64(e.request_id.as_ref().as_bytes())`; значение — `.0` = код `E_*` из events.rs, `.1` = `true` (ставится всегда `true`, см. on_resp:422; читается только `.0`).
- связи: поле `Tb.meta`, заполняется в `on_resp` (420-423), читается в `on_fin` (451).

### struct Tab  (строки 19-25, `#[derive(Clone)]`)
- назначение: облегчённый хэндл вкладки для `human` и `relay` (без `Ctx` и без `meta`).
- поля: `page: Page` (chromiumoxide), `site: u32` (interned host), `tun: u32` (interned имя туннеля), `tab: u32` (индекс target).
- связи: строится в `main.rs:445-453` из `Tb`; потребляется `human::drive` и `relay::run`.

### struct Tb  (строки 27-35, `#[derive(Clone)]`)
- назначение: полный контекст вкладки-сборщика.
- поля: `ctx: Arc<Ctx>` (общий контекст: каналы, interner, счётчики, binding, budget), `tun: u32`, `site: u32`, `tab: u32`, `page: Page`, `meta: Meta`.
- связи: создаётся в `main.rs:381-388`; `instrument(tb.clone(), url)` (main.rs:389) под таймаутом `TAB_UP = 90s`; `finalize(&tb)` (main.rs:502) в конце сессии.

### impl Tb — метод fn emit(&self, kind: u16, d: Bytes)  (строки 38-51)
- назначение: послать событие без vendor.
- что внутри: `ctx.tx.send(FxEvent { t: now_ms(), site, tun, tab, vendor: 0, name: 0, kind, _pad: 0, d })`, результат игнорируется (`let _ =`); затем `Cn::inc(&ctx.cn.ev)`.
- связи: канал unbounded (`main.rs:187`), поэтому backpressure нет — падение writer'а приводит к росту очереди в памяти, а не к блокировке сборщика.

### impl Tb — метод fn emit_v(&self, vendor: u32, kind: u16, d: Bytes)  (строки 53-66)
- то же, что `emit`, но заполняет `vendor` (interned id вендора антифрода из `ctx::VENDORS`). writer при `vendor != 0` дублирует строку в `sites/<site>/antifraud/<vendor>/timeline.jsonl` (writer.rs:422-428).

### impl Tb — метод fn file(&self, path: &str, data: Vec<u8>)  (строки 68-81)
- назначение: передать файл (HTML/скриншот/cookies/storage) в writer через тот же канал событий.
- что внутри: `nm = ctx.interner.intern(path)`; `FxEvent { kind: K_FILE, name: nm, d: Bytes::from(data), vendor: 0 }`. Счётчик `cn.ev` НЕ инкрементируется (в отличие от emit/emit_v).
- связи: writer.rs:365-375 — при `K_FILE` резолвит `name` обратно в строку, `create_dir_all(parent)`, `fs::write(stage/<path>, data)`. Вызывается только из `finalize`.

### fn now_ms() -> u64  (строки 84-89)
- `SystemTime::now() - UNIX_EPOCH` в миллисекундах, при ошибке `0`. Это wall-clock, а не монотонные часы sink'а.

### fn storable(mime: &str, resource: &str) -> Option<u8>  (строки 91-112)
- назначение: решить по MIME-типу и CDP-типу ресурса, сохранять ли тело и с каким кодом.
- что внутри: mime приводится к нижнему регистру, проверка `contains` в фиксированном порядке приоритета: `wasm`→`E_WASM`; `javascript`/`ecmascript` или `resource == "Script"`→`E_JS`; `json` или `resource` ∈ {`Xhr`,`Fetch`,`Preflight`}→`E_JSON`; `html`/`xhtml` или `Document`→`E_HTML`; `css`→`E_CSS`; `text/plain`/`xml`/`svg`/`form-urlencoded`→`E_TXT`; иначе `None`.
- связи: вызывается из `on_resp` (356).

### fn sniff(b: &[u8]) -> u8  (строки 114-127)
- назначение: определить тип тела по первым байтам, когда MIME не дал ответа (`E_BIN`).
- что внутри: magic `\0asm` (0x00,'a','s','m') → `E_WASM`; иначе считает ведущие пробелы/`\n`/`\r`/`\t`, первый значащий байт: `{` или `[` → `E_JSON`, `<` → `E_HTML`, всё остальное → `E_TXT`.
- связи: `on_fin` (470), только если `code == E_BIN`.

### fn post_art(ctx: &Ctx, code: u8, data: Vec<u8>) -> Option<([u8; 32], u64)>  (строки 129-148)
- назначение: единая точка отправки артефакта (тела) в writer с дедупликацией по хэшу и контролем бюджета.
- что внутри (по шагам):
  1. `n = data.len()`; отбой если `n == 0` или `n > 16_777_216` (16 MiB) — без инкремента drop.
  2. Бюджет: `ctx.budget.load(Relaxed) + n > ctx.budget_limit()` → `Cn::inc(&ctx.cn.drop)`, `None`. `budget_limit()` определён в `main.rs:92-95` как `env_u64("AF_BUDGET_MB", 350) * 1024 * 1024`.
  3. `h = blake3::hash(&data)`, `hb = *h.as_bytes()` — 32 байта.
  4. `ctx.art.send(Art { code, hash: hb, data: Bytes::from(data) })` (unbounded, main.rs:188).
  5. `ctx.budget.fetch_add(n, Relaxed)`; `Cn::inc(&ctx.cn.bin)`.
  6. Возврат `Some((hb, n))`.
- связи: вызывается из `on_req` (POST-тело), `on_fin` (response body), `on_script` (исходник/wasm). writer.rs:467-479 дедуплицирует по `seen: HashSet<[u8;32]>` и пишет `stage/artifacts/<hex32>.<ext>`.
- дырка: бюджет только растёт (`fetch_add`), никогда не уменьшается — дубликаты, отброшенные writer'ом, всё равно тратят бюджет.

### fn hdrs(j: &mut J, k: &str, h: &Headers)  (строки 150-177)
- назначение: сериализовать CDP-заголовки в JSON-объект внутри `J`.
- что внутри: `j.key(k)`; если `h.inner()` — `Value::Object`, пишет `{`, перебирает пары, `j.s(hk)` + `:` + значение (строка как есть, иначе `hv.to_string()`), разделитель `,` между парами, закрывает `}`; любой другой вариант → литерал `{}`.
- связи: `on_req` (320), `on_resp` (417), `on_rhdr` (435), `on_qhdr` (446).

### pub async fn instrument(tb: Tb, url: &str)  (строки 179-239)
- назначение: полная подготовка страницы к сбору и навигация.
- что внутри (строго по порядку):
  1. `page.execute(AddBindingParams::new(tb.ctx.binding.clone()))` — **CDP `Runtime.addBinding`**. Ошибка → `eprintln!("[afeye] addbinding: {e}")` (строки 180-186). Binding — имя функции `window[B]`, через которую JS-харнесс шлёт батчи; имя формируется в `main.rs:222` как `format!("_k{}z", t0ms % 997)`.
  2. `page.execute(AddScriptToEvaluateOnNewDocumentParams::new(inject::source(&tb.ctx.binding, tb.ctx.gl_spoof)))` — **CDP `Page.addScriptToEvaluateOnNewDocument`**, источник = харнесс из inject.rs (строки 187-196). Ошибка → `eprintln!("[afeye] addscript: {e}")`.
  3. Блок включения доменов (строки 197-215), локальные алиасы `NEnable`/`PEnable`/`DEnable`/`REnable`/`SetAutoAttachParams`:
     - `Target.setAutoAttach` с `flatten(true)`, `auto_attach(true)`, `wait_for_debugger_on_start(false)` — собирается builder'ом, при `Ok` исполняется (`let _ =`), при `Err` постройки пропускается (203-210).
     - `Network.enable` (211), `Debugger.enable` (212), `Runtime.enable` (213), `Page.enable` (214) — все `::default()`, все через `let _ =` (ошибки молча игнорируются).
  4. Подписка 17 обработчиков через `spawn_ev` (строки 216-232), порядок: `on_req`, `on_resp`, `on_rhdr`, `on_qhdr`, `on_fin`, `on_fail`, `on_wsc`, `on_wsf`, `on_wsr`, `on_script`, `on_bind`, `on_console`, `on_exc`, `on_ctxt`, `on_nav`, `on_dcl`, `on_load`.
  5. `tokio::time::timeout(60s, tb.page.goto(url.to_owned()))` — **CDP `Page.navigate`** (chromiumoxide `goto` = `NavigateParams`; при `error_text` в ответе возвращает `Err`). Ветки (233-238): `Ok(Ok(_))` — ничего; `Ok(Err(e))` — `eprintln!("[afeye] goto err (kept alive): {e}")`; `Err(_)` (таймаут) — `eprintln!("[afeye] goto slow (kept alive): {url}")`. В обоих ошибочных случаях страница НЕ закрывается — сессия продолжается.
- связи: вызывается из `main.rs:389` под таймаутом `TAB_UP = 90s`; использует `inject::source`, `ctx.binding`, `ctx.gl_spoof`.
- примечание: `Page.enable` и `Runtime.enable` здесь дублируют то, что chromiumoxide сам шлёт при создании frame-manager'а (`chromiumoxide-0.9.1/src/handler/frame.rs:216-229` — `Page.enable`, `Page.getFrameTree`, `Page.setLifecycleEventsEnabled(true)`, `Runtime.enable`) и `handler/mod.rs:96` (`Target.setDiscoverTargets(true)`). Дубли безвредны, но фактически домены включаются дважды.

### Полный список CDP-вызовов репозитория (имена wire-методов проверены по `chromiumoxide_cdp-0.9.1/src/cdp.rs`, константы `IDENTIFIER`)
Команды (отправляем):
| CDP-метод | где | параметры |
|---|---|---|
| `Runtime.addBinding` | capture.rs:182 | `name = ctx.binding` |
| `Page.addScriptToEvaluateOnNewDocument` | capture.rs:189 | `source = inject::source(binding, gl_spoof)` |
| `Target.setAutoAttach` | capture.rs:203-209 | `flatten=true, autoAttach=true, waitForDebuggerOnStart=false` |
| `Network.enable` | capture.rs:211 | default |
| `Debugger.enable` | capture.rs:212 | default |
| `Runtime.enable` | capture.rs:213 | default |
| `Page.enable` | capture.rs:214 | default |
| `Page.navigate` | capture.rs:233 (`page.goto`) | `url` |
| `Network.getRequestPostData` | capture.rs:327 | `requestId` |
| `Network.getResponseBody` | capture.rs:458 | `requestId` |
| `Debugger.getScriptSource` | capture.rs:570 | `scriptId` |
| `Runtime.evaluate` | capture.rs:731 (`eval_str`), relay.rs:108 (`eval_tab`), human.rs:145-149 (`poke`) | `expression`, `returnByValue=true` (в capture/relay) |
| `Page.captureScreenshot` | capture.rs:771 | `format=Png` |
| `Network.getCookies` | capture.rs:782 (`page.get_cookies()` → chromiumoxide-0.9.1/src/page.rs:901-906) | default |
| `Input.dispatchMouseEvent` | human.rs:34 | `x,y,type[,button][,clickCount][,deltaY,deltaX]` |
| `Input.dispatchKeyEvent` | human.rs:52-59 (key), 73-86 (enter) | `type,key[,text][,code][,windowsVirtualKeyCode,nativeVirtualKeyCode]` |
| `Page.reload` | human.rs:197 | default |

События (подписываем через `page.event_listener::<E>()`):
| CDP-событие | обработчик | подписка |
|---|---|---|
| `Network.requestWillBeSent` | `on_req` | capture.rs:216 |
| `Network.responseReceived` | `on_resp` | capture.rs:217 |
| `Network.responseReceivedExtraInfo` | `on_rhdr` | capture.rs:218 |
| `Network.requestWillBeSentExtraInfo` | `on_qhdr` | capture.rs:219 |
| `Network.loadingFinished` | `on_fin` | capture.rs:220 |
| `Network.loadingFailed` | `on_fail` | capture.rs:221 |
| `Network.webSocketCreated` | `on_wsc` | capture.rs:222 |
| `Network.webSocketFrameSent` | `on_wsf` | capture.rs:223 |
| `Network.webSocketFrameReceived` | `on_wsr` | capture.rs:224 |
| `Debugger.scriptParsed` | `on_script` | capture.rs:225 |
| `Runtime.bindingCalled` | `on_bind` | capture.rs:226 |
| `Runtime.consoleAPICalled` | `on_console` | capture.rs:227 |
| `Runtime.exceptionThrown` | `on_exc` | capture.rs:228 |
| `Runtime.executionContextCreated` | `on_ctxt` | capture.rs:229 |
| `Page.frameNavigated` | `on_nav` | capture.rs:230 |
| `Page.domContentEventFired` | `on_dcl` | capture.rs:231 |
| `Page.loadEventFired` | `on_load` | capture.rs:232 |

### async fn spawn_ev<E, F>(tb: &Tb, f: F)  (строки 241-257)
- назначение: универсальная подписка на один тип CDP-события + отдельная tokio-задача на поток.
- сигнатура/трейты: `E: IntoEventKind + Send + Unpin + 'static`, `F: Fn(&Tb, Arc<E>) + Send + Sync + Clone + 'static`.
- что внутри: `tb.clone()`; `page.event_listener::<E>().await` — при `Err` функция молча выходит (`return`), т.е. неподписанный домен = тихая потеря всего потока событий; при `Ok(s)` — `tokio::spawn` с циклом `while let Some(e) = s.next().await { f(&tb, e) }`.
- связи: 17 вызовов из `instrument`. Обработчики синхронные (`Fn`), поэтому тяжёлые CDP-запросы внутри них уходят в `tokio::spawn` (см. on_req/on_fin/on_script).

### fn frame_str(out: &mut String, name: &str, url: &str, ln: i64)  (строки 259-273)
- назначение: добавить один кадр стека инициатора в компактную строку.
- что внутри: жёсткий стоп при `out.len() > 700`; разделитель `;`; если `name` непуст — `name[..char_floor(name,48)]` + `@`; затем `url[..char_floor(url,120)]` + `:` + номер строки.
- связи: `on_req` (308, 312) для `initiator.stack.call_frames` (до 10 кадров) и `stack.parent.call_frames` (до 4).

### fn on_req(tb: &Tb, e: Arc<EventRequestWillBeSent>)  (строки 275-350)
- назначение: событие `Network.requestWillBeSent` → `K_REQ` (+ асинхронно POST-тело).
- что внутри:
  1. `Cn::inc(&tb.ctx.cn.req)`.
  2. `vendor = vendor_of_url(&e.request.url)` → interned id или 0.
  3. `J::new(384)`; поля: `rid` (request_id), `m` (method), `u` (url), `ty` (тип ресурса, если есть), `ini` (`initiator.type`), `iniu` (`initiator.url`, если есть), `wt` (`wall_time` как f64), `red` (`redirect_response.status`, если есть), `stk` (строка стека из `frame_str`, если `initiator.stack` есть), `h` (заголовки через `hdrs`).
  4. `tb.emit_v(vendor, K_REQ, j.fin())`.
  5. Если `e.request.has_post_data == Some(true)` (322): клонирует `tb`, `rid`, урезает url до 300 байт по границе символа; `tokio::spawn` → `Network.getRequestPostData`; при успехе и `0 < pd.len() <= 8_388_608` (8 MiB) → `post_art(ctx, E_POST, pd.into_bytes())`; при `Some((h,n))`: `Cn::inc(cn.body)`, `J::new(192)` с полями `rid`,`u`,`a` (hex32 хэша), `x` = `"post"` (литерал, не `code.ext()`), `n`; `emit(K_BODY, ...)`.
- связи: writer пишет строку в `sites/<site>/tunnels/<tun>/<slot>/timeline.jsonl` (+ antifraud-копия при vendor≠0).

### fn on_resp(tb: &Tb, e: Arc<EventResponseReceived>)  (строки 352-424)
- назначение: `Network.responseReceived` → `K_RESP` + отметка в `meta` для последующего скачивания тела.
- что внутри: `Cn::inc(cn.resp)`; `code = storable(&r.mime_type, tys)`; `vendor` по url; `J::new(512)` с полями: `rid`, `u`, `st` (status i64), `ct` (mime, если непуст), `pr` (protocol), `rip` (remote_ip_address), `rpt` (remote_port i64), `tls` — вложенный объект `{v: protocol, c: cipher, k: key_exchange, kg: key_exchange_group|""}` (385-397), `tm` — вложенный объект `{dns: dns_end-dns_start, con: connect_end-connect_start, ssl: ssl_end-ssl_start, snd: send_end-send_start}` (398-410), `size` = `encoded_data_length` (f64), `cache: true` если `from_disk_cache`, `h` (hdrs). `emit_v(vendor, K_RESP, ...)`.
- далее (419-423): `xhr = (tys == "Xhr" || tys == "Fetch")`; если `code.is_some() || xhr` → `meta.insert(fx64(rid), (code.unwrap_or(E_BIN), true))`. То есть XHR/Fetch сохраняются всегда (с `E_BIN` при неопознанном MIME, позже уточняется через `sniff`).
- связи: `meta` читает `on_fin`.

### fn on_rhdr(tb: &Tb, e: Arc<EventResponseReceivedExtraInfo>)  (строки 426-437)
- `K_HDR` с полями `rid`, `ph: "resp_ex"`, `st` (status_code), `h`. Это «сырые» заголовки ответа от сетевого стека (включая то, что Chrome не показывает в `responseReceived`).

### fn on_qhdr(tb: &Tb, e: Arc<EventRequestWillBeSentExtraInfo>)  (строки 439-448)
- `K_HDR` с полями `rid`, `ph: "req_ex"`, `h`. Сырые заголовки запроса (в т.ч. проставленные сетевым стеком, например Cookie).

### fn on_fin(tb: &Tb, e: Arc<EventLoadingFinished>)  (строки 450-490)
- назначение: скачать тело запроса, помеченного в `on_resp`.
- что внутри: `meta.get(&fx64(rid))` → `code = value().0`, при отсутствии записи — ранний `return` (тела не помеченных запросов не скачиваются вообще). Далее `tokio::spawn`:
  1. `Network.getResponseBody(rid)`.
  2. `body: String = rr.body`; проверка `!body.is_empty() && body.len() <= 16_777_216` (16 MiB, по длине String, т.е. до base64-декода).
  3. `raw`: если `rr.base64_encoded` → `base64 STANDARD.decode(body)` (при ошибке — `return`), иначе `body.into_bytes()`.
  4. `code2 = if code == E_BIN { sniff(&raw) } else { code }`.
  5. `post_art(ctx, code2, raw)` → при `Some((h,n))`: `Cn::inc(cn.body)`, `J::new(160)` с `rid`, `a` (hex32), `x` = `code2.ext()` (js/wasm/json/html/css/txt/bin), `n`; `emit(K_BODY, ...)`.
  6. Ветка `else` у `if let Ok(res)` (486-488): `Cn::inc(&ctx.cn.drop)` — ошибка `getResponseBody` считается дропом.
- связи: артефакт уходит в `stage/artifacts/<hex32>.<ext>`, событие-указатель — в timeline.

### fn on_fail(tb: &Tb, e: Arc<EventLoadingFailed>)  (строки 492-500)
- `K_FAIL` с полями `rid`, `err` (`e.error_text`).

### fn on_wsc(tb: &Tb, e: Arc<EventWebSocketCreated>)  (строки 502-516)
- `vendor` по `e.url`; `K_WS` с `rid`, `f: "created"`, `u`.

### fn on_wsf(tb: &Tb, e: Arc<EventWebSocketFrameSent>)  (строки 518-520)
- делегирует в `ws_line(tb, &e.request_id, "sent", e.response.opcode, &e.response.payload_data)`.

### fn on_wsr(tb: &Tb, e: Arc<EventWebSocketFrameReceived>)  (строки 522-524)
- делегирует в `ws_line(..., "recv", ...)`.

### fn ws_line(tb: &Tb, rid: &RequestId, dir: &str, op: f64, payload: &str)  (строки 526-541)
- `K_WS` с полями: `rid`, `f` (dir), `op` (opcode f64), `n` = `payload.len()` (u64, байты ДО обрезки), `p` = `payload[..char_floor(payload, 2048)]` (обрезка по границе UTF-8 символа до 2048 байт).
- дырка: `n` — полная длина, `p` — обрезанный фрагмент; получатель не знает, что payload усечён (нет флага truncation).

### fn on_script(tb: &Tb, e: Arc<EventScriptParsed>)  (строки 543-603)
- назначение: `Debugger.scriptParsed` → `K_SCRIPT` + скачивание исходника → `K_SRC`.
- что внутри: `Cn::inc(cn.scripts)`; `vendor` по `e.url`; `J::new(256)`: `sid` (script_id), `u`, `hl` = `e.length` (i64) или литерал `null`, `ch` = `e.hash`; `emit_v(vendor, K_SCRIPT, ...)`.
- далее: если `e.url.starts_with("extensions://")` → `return` (исходники расширений не качаются). Иначе `tokio::spawn`:
  1. `Debugger.getScriptSource(sid)` → `x.result.script_source`, при `Err` — `return`.
  2. `wasm = url.starts_with("wasm://")`; `code = E_WASM | E_JS`.
  3. `raw`: для wasm — `base64 STANDARD.decode(src)` (при ошибке `return`), иначе `src.into_bytes()`.
  4. `raw.is_empty()` → `return`.
  5. `post_art(ctx, code, raw)` → `J::new(200)` с `sid`, `u` (обрезан до 300), `a`, `x` = `code.ext()`, `n`; `emit_v(vendor, K_SRC, ...)`.
- дырка: `vendor` захватывается в замыкание из внешнего скоупа и используется в spawn'е — корректно, но при `Err` в `getScriptSource` счётчик дропа НЕ инкрементируется (в отличие от `on_fin`).

### fn on_bind(tb: &Tb, e: Arc<EventBindingCalled>)  (строки 605-624)
- назначение: приём батча из JS-харнесса (главный канал данных инжекта).
- что внутри: фильтр `if e.name != tb.ctx.binding { return }` (отсекает чужие binding'и, например puppeteer'овские); `Cn::inc(cn.batch)`; zero-copy попытка `Arc::try_unwrap(e)` → `ev.payload`, иначе `a.payload.clone()`; `n = char_floor(&pl, 600)`; `vendor_of_stack(&pl[..n])` — поиск суффиксов вендоров в первых 600 байтах payload'а; `emit_v(vendor, K_BATCH, Bytes::from(pl))` при vendor≠0, иначе `emit(K_BATCH, ...)`. Payload уходит ЦЕЛИКОМ, без обрезки.
- связи: writer.rs:393 → `batch()` (writer.rs:272-...), который парсит плоский JSON-массив `[key, value, timestamp, ...]` токенами (`scan_arr`), режет на тройки и пишет по строке `{"t":..,"b":..,"j":..,"kk":<key>,"v":<value>}` на каждую запись; для `kk == "net:send"` дополнительно извлекает URL → `endpoint_of` → `ctx.endpoints[eid] += 1` (writer.rs:315-327) — этот счётчик потом используется `human::drive` для poke'ов.

### fn on_console(tb: &Tb, e: Arc<EventConsoleApiCalled>)  (строки 626-652)
- `K_CONSOLE` с полями: `ty` (`e.type`), `args` — массив строк (для каждого аргумента `description`, при пустом — `value.to_string()`), обрезка `s.truncate(512)` (строка 645), `ctx` = `execution_context_id` (i64).
- дырка: `String::truncate` паникует, если 512 не попадает на границу UTF-8 символа (в отличие от `char_floor`, который используется во всех остальных местах обрезки). Длинный не-ASCII вывод в `console.*` → паника внутри задачи `spawn_ev`; процесс выживает (tokio ловит панику задачи), но поток `Runtime.consoleAPICalled` для этой вкладки обрывается навсегда.

### fn on_exc(tb: &Tb, e: Arc<EventExceptionThrown>)  (строки 654-680)
- `K_EXC` с полями: `t` (`exception_details.text`), `u` (url, если есть), `ln` (line_number), `c` (column_number), `st` — склейка до 12 кадров `function_name@url\n` (без ограничения длины строки, в отличие от `frame_str`).

### fn on_ctxt(tb: &Tb, e: Arc<EventExecutionContextCreated>)  (строки 682-693)
- `K_CTX` с полями: `id` (i64), `o` (origin), `n` (name).

### fn on_nav(tb: &Tb, e: Arc<EventFrameNavigated>)  (строки 695-710)
- `K_NAV` с полями: `fid` (frame id), `u` (frame url), `n` (frame name, только если непуст).

### fn on_dcl(tb: &Tb, _e: Arc<EventDomContentEventFired>)  (строки 712-718)
- `K_LIFE` с единственным полем `ph: "dcl"`.

### fn on_load(tb: &Tb, _e: Arc<EventLoadEventFired>)  (строки 720-726)
- `K_LIFE` с `ph: "load"`.

### async fn eval_str(page: &Page, expr: &str) -> Option<String>  (строки 728-743)
- `Runtime.evaluate` с `return_by_value(true)`; возвращает `Some(String)` только если `result.result.value` — `Value::String`; таймаута НЕТ (в отличие от relay::eval_tab).

### pub async fn eval_list(page: &Page) -> Vec<(f64, f64, String)>  (строки 745-751)
- назначение: найти кликабельные элементы для `human::drive`.
- что внутри: однострочный JS (строка 746) — селектор `button:not([type=submit]),a[href],[role=button],[onclick],input:not([type=submit]):not([type=hidden]):not([type=checkbox]):not([type=radio]),select,textarea,[tabindex]:not([tabindex=-1])`; вьюпорт по умолчанию `1280x800`; отбор: `width>4 && height>4 && bottom>0 && top<h && right>0 && left<v`, `visibility!=='hidden'`, `display!=='none'`, `!disabled`; максимум 40 элементов; результат — `[Math.round(x+w/2), Math.round(y+h/2), tagName]`, сериализованный `JSON.stringify`; при исключении — `'[]'`.
- таймаут: `tokio::time::timeout(3s, eval_str(...))`; при неуспехе — пустой `Vec`.
- связи: вызывается из `human.rs:188`. Координаты — центры элементов в CSS-пикселях вьюпорта; `human` шлёт их как `Input.dispatchMouseEvent` x/y. Окно Chrome запускается с `--window-size=1280,832` (browser.rs:79), что согласуется с дефолтом 1280x800.

### pub async fn finalize(tb: &Tb)  (строки 753-802)
- назначение: финальный снапшот состояния вкладки.
- что внутри: `site_n`/`tun_n` — резолв interned id в строки; `t_short = 5s` на каждый шаг:
  1. `eval_str("document.documentElement.outerHTML")` → `tb.file("sites/<site>/tunnels/<tun>/tabs/<tab>.final.html")`.
  2. `CaptureScreenshotParams{format: Png}` (**CDP `Page.captureScreenshot`**) → base64-декод → `.../tabs/<tab>.shot.png`.
  3. `page.get_cookies()` (**CDP `Network.getCookies`**) → `serde_json::to_writer_pretty` → `sites/<site>/tunnels/<tun>/cookies.json` (общий на туннель, путь НЕ содержит `tab`).
  4. `eval_str` над `JSON.stringify([location.href, entries(localStorage), entries(sessionStorage)])` → `.../tabs/<tab>.storage.json`.
- связи: вызывается из `main.rs:501-503` в spawn'ах после остановки сессии; каждый шаг независимо проглатывает ошибки (`if let Ok(...)`).

### Wire-форматы capture.rs
`FxEvent` (events.rs, `#[repr(C, align(64))]`): `t:u64, site:u32, tun:u32, tab:u32, vendor:u32, name:u32, kind:u16, _pad:u16, d:Bytes`.
JSON-payload по kinds:
- `K_REQ`(1): `{"rid":..,"m":..,"u":..[,"ty":..],"ini":..[,"iniu":..],"wt":..[,"red":..][,"stk":..],"h":{...}}`
- `K_RESP`(2): `{"rid":..,"u":..,"st":..[,"ct":..][,"pr":..][,"rip":..][,"rpt":..][,"tls":{"v","c","k","kg"}][,"tm":{"dns","con","ssl","snd"}],"size":..[,"cache":true],"h":{...}}`
- `K_BODY`(3): `{"rid"|"sid":..[,"u":..],"a":"<hex64>","x":"<ext|post>","n":<u64>}`
- `K_FAIL`(4): `{"rid":..,"err":..}`
- `K_HDR`(5): `{"rid":..,"ph":"resp_ex"|"req_ex"[,"st":..],"h":{...}}`
- `K_WS`(6): `{"rid":..,"f":"created"|"sent"|"recv"[,"u":..][,"op":..,"n":..,"p":..]}`
- `K_SCRIPT`(7): `{"sid":..,"u":..,"hl":<i64|null>,"ch":..}`
- `K_SRC`(8): `{"sid":..,"u":..,"a":..,"x":..,"n":..}`
- `K_BATCH`(9): сырой плоский массив харнесса `[key,value,ts,key,value,ts,...]`
- `K_CONSOLE`(11): `{"ty":..,"args":[..],"ctx":<i64>}`
- `K_EXC`(12): `{"t":..[,"u":..],"ln":..,"c":..[,"st":..]}`
- `K_CTX`(13): `{"id":..,"o":..,"n":..}`
- `K_NAV`(14): `{"fid":..,"u":..[,"n":..]}`
- `K_LIFE`(15): `{"ph":"dcl"|"load"}`
- `K_FILE`(16): `d` = содержимое файла, `name` = interned путь.

---

## src/inject.rs — JS-харнесс, инжектируемый в каждый документ

### pub fn source(binding: &str, spoof: bool) -> String  (строки 1-7)
- назначение: подставить runtime-параметры в шаблон `SRC`.
- что внутри: `SRC.replacen("__B__", binding, 2).replacen("__G__", if spoof {"1"} else {"0"}, 2)`. Комментарий (2-4) объясняет: `__G__` встречается в шаблоне ДВАЖДЫ (гейт WebGL-спуфинга в `SGP` и флаг в записи `_boot`), поэтому лимит замен = 2; при `replacen(..,1)` boot-запись всегда рапортовала `spoof=0`.
- связи: единственный вызов — capture.rs:189. `spoof` приходит из `ctx.gl_spoof` = `std::env::var("AF_GL_SPOOF").is_ok()` (main.rs:271).
- факт: в шаблоне `__B__` встречается 1 раз (строка 12), `__G__` — 2 раза (строки 44 и 86); лимит 2 покрывает оба.
- валидация синтаксиса: `src/bin/jscheck.rs` извлекает raw-строку между `r#"` и `"#;`, заменяет `__B__`→`_k42z`, `__G__`→`1`, пишет во временный файл и гоняет `node --check`; при неуспехе exit(1). Требует `node` в PATH.

### const SRC: &str  (строки 9-87)
IIFE `(function(){ "use strict"; ... })()`, версия помечена `afeye-harness v12.1`. Маркер `var AFXH=1` (строка 11) — признак самоисключения: `sinkfilter.rs:372-376` по подстроке `afeye-harness` в теле или в имени записи считает запись «своей» и не классифицирует её как антифрод (`is_hot` возвращает false).

По строкам:

- **11** `var AFXH=1;` — маркер харнесса.
- **12** состояние: `B` (имя binding), `L` (очередь записей), `CAP=6000` (лимит элементов очереди — по 3 на запись, т.е. ~2000 записей), `DR` (счётчик дропов очереди), счётчики-лимиты `LN`(listen 200), `SN`(setattr 200), `EVN`(eval 40), `FNN`(Function 40), `PON`(po:obs 40), `WEN`(wasm:exp 40), `WMDD`(wasm-memory dumps 3), `MQN`(matchMedia 30), `WSN`(worker src 20), `SLN`(slow-записи 800); словари `AG` (счётчики вызовов), `MS` (суммы мс), `MM` (максимумы мс), `SLC` (счётчик slow на тег, ≤5), `ARM` (типы событий с уже навешанным диспетч-слушателем), `STK` (счётчик стеков на тег, ≤3), `SRCN` (счётчик исходников колбэков на тег, ≤3), `WMR` (WeakRef'ы на WebAssembly.Memory).
- **13** `TS=Function.prototype.toString`, `OWN=TS.call(TS)` (нативный исходник toString), `SYM=Symbol.for("afx"+B)`, `SH=null`.
- **14** `SH = window.parent[SYM]`, если есть кросс-фреймовый родитель (не `window`) — переиспользование WeakMap маскировки между фреймами.
- **15** `WK = SH ? SH.w : new WeakMap()`.
- **16** `function P(f,s){WK.set(f,s);return f}` — зарегистрировать поддельный исходник для прокси-функции.
- **17** подмена `Function.prototype.toString`: возвращает `WK.get(this)` если есть, иначе нативный `TS.call(this)`. Обёрнута через `P(..., OWN)` — сама выглядит нативно. Это антидетект: `proxy.toString()` возвращает оригинальный source.
- **18** `Object.defineProperty(window, SYM, {value:{w:WK}, writable:false, enumerable:false, configurable:false})` — публикация маскировки для дочерних фреймов.
- **19** `function T(){return performance.now()}` — все таймстампы харнесса в `performance.now()` (монотонные мс страницы). При `AFEYE_VIRTUAL_CLOCK` это виртуальные часы патча 0034.
- **20** `function W(k,v)` — главная запись: при `L.length > CAP` (6000) инкрементит `DR` и выходит; иначе `L.push(k, v, T())` (плоская тройка).
- **21** `function C(n)` — `AG[n] = (AG[n]||0)+1` (счётчик вызовов без payload).
- **22** `function M(n,d)` — `MS[n]+=d` (сумма мс), `MM[n]=max(MM[n],d)`; если `d>8` мс и `SLC[n]<5` и `SLN<800` — пишет `W("slow:"+n, [round(d*100)/100, T()])`.
- **23** `function A(a)` — компактный дамп до 6 аргументов: number → round до 2 знаков; string → `slice(0,80)`; ArrayBuffer → `byteLength`;对象 с `byteLength` → `byteLength`; с `length` → `String(length)`; иначе `0`.
- **24** `function BDY(b)` — дамп тела запроса: null/undefined → 0; string → `slice(0,512)`; number → как есть; `URLSearchParams` → `String(b).slice(0,512)`; объект с `.append` (FormData) → склейка `k=v&` с `v.slice(0,64)` до 512; иначе `byteLength` или 0. Всё в try/catch → 0.
- **25** `function ST(tag)` — сэмплированный стек: не более 3 на тег (`STK`), `W("stk:"+tag, [String(new Error().stack||"").slice(0,600), T()])`.
- **26** `function CB(cb,tag)` — обёртка колбэка: снимает `TS.call(cb)` (исходник), до 3 раз на тег пишет `W("src:"+tag,[src.slice(0,4000),T()])`; возвращает `P(function(){t0=T(); try{return Reflect.apply(cb,this,arguments)} finally{M(tag,T()-t0);C(tag)}}, src||OWN)` — т.е. измеряет длительность исполнения колбэка и маскирует его исходник.
- **27-28** тейнт-пул: `TN` (множество хэшей токенов), `TNC`, `TDEL` (очередь новых хэшей, ≤256), `TMAX=8192`, `DEL` (битовая таблица разделителей), `DLM=" \"',:;=&{}[]()<>?/\\+|*#%"`; заполнение `DEL`.
- **29** `function FNV(s)` — FNV-1a 32 по строке (`Math.imul(h,16777619)>>>0`).
- **30** `function TAS(h)` — добавить хэш в пул: если `TNC>=TMAX`, удаляет ОДИН произвольный ключ (`for..in` + break); `TN[h]=1`, `TNC++`, при `TDEL.length<256` — `TDEL.push(h)` (для отправки в Rust).
- **31** `function TT(s)` — токенизация строки: лимит 1024 символа; сначала `TAS(FNV(s.slice(0,1024)))` (хэш всей строки), затем прогон: байты `>32 && <127 && !DEL` накапливаются в FNV-хэш токена, на разделителе при `run>=3` → `TAS(h)`.
- **32** `function TTv(v)` — string → `TT(v)`; целое число `0<v<1e9` → `TT(String(v))`.
- **33** `function TCT(s)` — счётчик токенов строки, УЖЕ присутствующих в пуле (лимит 4096). Возвращает число совпадений — используется как «taint score» тела/URL перед отправкой.
- **34** `function FNV8(u)` — FNV-1a по байтам (Uint8Array).
- **35** `function B64(u)` — base64 через `String.fromCharCode.apply` чанками по 512 + `btoa`, при ошибке `""`.
- **36** `function WMD()` — дамп содержимого WebAssembly.Memory: не более `WMDD>=3` раз; перебирает `WMR` (WeakRef), мёртвые вычёркивает; для каждого buffer'а — `[byteLength, FNV8(первые 4096 байт), B64(первые 2048 байт)]`; при ненулевом результате `WMDD++`; возвращает массив или 0.
- **37** `function FL()` — флаш: собирает `AG`→`a` (плоские пары), `MS`→`m`, `MM`→`x` (с round до 2 знаков), обнуляет словари; пишет `W("_c",a)`, `W("_m",m)`, `W("_mm",x)`; при `DR` — `W("_dr",DR)` и сброс; при `TDEL.length` — `W("_th",TDEL)` и сброс; затем `p=JSON.stringify(L)` (при ошибке — `L.length=0`), `window[B](p)` в try/catch, `L.length=0`.
- **38** `setInterval(FL,700)` — батч каждые 700 мс.
- **39** `addEventListener("pagehide",FL)` — сброс при уходе со страницы.
- **40** `function GP(o,p)` — обёртка ГЕТТЕРА свойства: `Proxy` над `d.get`, при чтении `C("g:"+p)`, `TTv(r)`, `ST("g:"+p)`; маскировка `TS.call(d.get)`.
- **41** `function GC(o,p)` — обёртка МЕТОДА только со счётчиком: `C(p)`, `ST(p)`.
- **42** `function FP(o,p,cap)` — обёртка метода с записью АРГУМЕНТОВ: до `cap||120` вызовов пишет `W(p,[A(a),T()])` и `TTv(a[0])`, дальше только `C(p)`.
- **43** `function FT(o,p)` — обёртка метода с ТАЙМИНГОМ и значением возврата: `M(p,T()-t0)`, `C(p)`, `TTv(r)`, `ST(p)`.
- **44** `function SGP(o,p)` — `getParameter` с WebGL-спуфингом: `sp = "__G__"==="1"` (после подстановки — константа); при `sp && k===37445` (`UNMASKED_VENDOR_WEBGL`) возвращает `"Google Inc. (Intel)"`; при `sp && k===37446` (`UNMASKED_RENDERER_WEBGL`) — `"ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E92) (0x00008086) Vulkan 1.3.283 (0x040041C5), Vulkan)"`. Плюс `M`,`C`,`TTv(r)`,`ST`.
- **45** `function GS(o)` — `shaderSource`: `C("shaderSource")`, до 10 раз `W("gl:shader",[текст шейдера slice(0,1024), T()])`.
- **46** `function WC(n)` — обёртка КОНСТРУКТОРА/вызова глобального класса: `construct` → при `PerformanceObserver` оборачивает колбэк через `CB(a[0],"po:cb")`; при `Worker` с `blob:`/`data:` URL и `WSN<20` — `fetch(url).then(text)` и `W("worker:src",[len, s.slice(0,4096), T()])`; пишет `W("new:"+n,[A(a),T()])`; `apply` → `W("call:"+n,[A(a),T()])`.
- **47** дополнительно для `PerformanceObserver`: обёртка `prototype.observe` — пишет `W("po:obs",[entryTypes.join("|").slice(0,120) | type, T()])` при `PON<40`, иначе `C("po:obs")`; плюс `GC(prototype,"disconnect")`, `GC(prototype,"takeRecords")`.
- **48-50** `Navigator.prototype`: геттеры через `GP` — `webdriver, plugins, mimeTypes, languages, hardwareConcurrency, deviceMemory, platform, vendor, userAgent, doNotTrack, maxTouchPoints, cookieEnabled, onLine, connection, pdfViewerEnabled, globalPrivacyControl, mediaDevices, storage, credentials, geolocation, permissions`; методы через `GC` — `getBattery, vibrate, getGamepads, requestMIDIAccess, share`.
- **51** `Screen.prototype`: `GP` над `width, height, availWidth, availHeight, colorDepth, pixelDepth, availLeft, availTop`.
- **52-55** canvas: `FT(HTMLCanvasElement.prototype,"toDataURL")`, `FT(...,"toBlob")`, `FP(...,"getContext",80)`, `GC(...,"transferControlToOffscreen")`; `FT(CanvasRenderingContext2D.prototype,"getImageData")`; `FT(OffscreenCanvasRenderingContext2D.prototype,"getImageData")`; `FT(OffscreenCanvas.prototype,"convertToBlob")`, `FP(...,"getContext",80)`, `GC(...,"transferToImageBitmap")`.
- **56** WebGL: `SGP(WebGLRenderingContext.prototype,"getParameter")`; `FT` над `getExtension, getSupportedExtensions, getShaderPrecisionFormat, getAttachedShaders, getProgramInfoLog`; `GS(WebGLRenderingContext.prototype)`; для WebGL2 — `SGP(...,"getParameter")`, `FT(...,"getExtension")`, `GS(...)`.
- **57** audio: `FT(AnalyserNode.prototype,"getFloatFrequencyData")`, `FT(OfflineAudioContext.prototype,"startRendering")`.
- **58** `Storage.prototype`: `GC` над `getItem, setItem, removeItem, clear, key`.
- **59-60** `document.cookie`: обёртки геттера (`C("cookie:get")`) и сеттера (`C("cookie:set")`) с сохранением `configurable:true, enumerable:true`.
- **61** `fetch`: `Proxy` над `window.fetch` — извлекает `o = a[1]||{}`, url (`a[0]` как строка или `.url`), `bs = BDY(o.body)`, `tn = TCT(bs) + TCT(url)` (taint score), вызывает оригинал; на промисе — `M("fetch", T()-t0)`, `C("fetch")`; пишет `W("net:send",[url.slice(0,300), method||"GET", bs, T(), tn, WMD()])`. Порядок полей `net:send` — это wire-контракт с writer.rs:315-327 (первый элемент = URL) и classify.rs:463,757,800.
- **62** `XMLHttpRequest`: `open` запоминает на инстансе скрытые `__afm` (method) и `__afu` (url, slice 300); `send` — `bs = BDY(a[0])`, `tn = TCT(bs)+TCT(uu)`, навешивает `loadend`-слушатель через сохранённый нативный `addEventListener` (`NAE`) для `M("xhr", T()-t0)`, пишет `W("net:send",[uu, __afm||"GET", bs, T(), tn, WMD()])`.
- **63** `Navigator.prototype.sendBeacon`: `W("net:send",[url.slice(0,300),"BEACON",bs,T(),tn,WMD()])`.
- **64** `SharedArrayBuffer`: конструктор пишет `W("sab",[a[0]||0,T()])`; `GC(SABC.prototype,"grow")`.
- **65** `Atomics`: `GC` над `store, load, add, sub, and, or, xor, exchange, compareExchange, wait, notify, waitAsync`.
- **66** `Performance.prototype`: `GC` над `getEntries, getEntriesByType, getEntriesByName, mark, measure`.
- **67** `WA` — список типов событий, за которыми харнесс ставит диспетч-наблюдатель: `mousemove mouseup mousedown click dblclick keydown keyup keypress wheel scroll touchstart touchmove touchend pointerdown pointermove pointerup input change focus blur copy paste contextmenu visibilitychange resize` (24 типа).
- **68** `EventTarget.prototype.addEventListener/removeEventListener/dispatchEvent`: `addEventListener` → `C("listen:"+ty)`; при `LN<200` пишет `W("listen",[ty, tagName|"window"|"document"|"*", capture?1:0, T()])`; если тип из `WA` и ещё не вооружён (`ARM[ty]`) — навешивает НА WINDOW capture-слушатель `P(function(){C("disp:"+ty)}, OWN)`, т.е. считает фактические диспетчи событий этого типа (это JS-сторона тех же событий, которые `human` шлёт через CDP `Input.dispatch*`); `removeEventListener` → `C("rm:"+ty)`; `dispatchEvent` → `GC`.
- **69** `requestAnimationFrame`: `C("rAF")`, колбэк через `CB(a[0],"raf:cb")`.
- **70** `setTimeout`/`setInterval`: `C("setTimeout")`/`C("setInterval")`, колбэки через `CB(...,"tmr:cb")`/`CB(...,"ivl:cb")`.
- **71** `Performance.prototype.now`: подмена геттера на `Proxy` с `C("performance.now")` — счётчик чтений часов.
- **72** `Date.now`: `Proxy` с `C("Date.now")`, `configurable:false`.
- **73** `Math.random`: `Proxy` — `C("Math.random")` и `TT(String(r))` (результат уходит в тейнт-пул как токен).
- **74** `eval`: при `EVN<40` — `W("call:eval",[A(a),T()])`, иначе `C("call:eval")`; всегда `ST("call:eval")`.
- **75** `Function` (конструктор и вызов): при `FNN<40` — `W("new:Function"|"call:Function",[args.map(x=>String(x).slice(0,96)),T()])`, иначе счётчик; всегда `ST`.
- **76** `WebAssembly`: `instantiate, compile, instantiateStreaming, compileStreaming, validate` — `M("wasm:"+p, dt)`, `C("wasm:"+p)`, при ненулевом размере `W("wasm",[sz,T()])`; для `instantiate*` на промисе — до 40 раз `W("wasm:exp",[Object.keys(exports).slice(0,40).join(",").slice(0,300), T()])`. Также `WebAssembly.Memory` конструктор: `WMR.push(new WeakRef(r))` при `WMR.length<8`, `W("wmem:new",[initial||0, max||0, T()])`; `Memory.prototype.grow` → `W("wmem:grow",[delta, byteLength после, T()])`.
- **77** точечные `GC`: `FontFaceSet.check`, `Intl.DateTimeFormat.resolvedOptions`, `Geolocation.getCurrentPosition/watchPosition`, `Permissions.query`, `MediaDevices.enumerateDevices`, `StorageManager.estimate`, `CredentialsContainer.get/create`, `History.pushState/replaceState`, `SubtleCrypto.digest`, `SpeechSynthesis.getVoices`, `ServiceWorkerContainer.register`, `Clipboard.readText/writeText`, `RTCPeerConnection.createOffer/createDataChannel`, `Window.postMessage`; `GP(Document.prototype,"visibilityState")`, `GP(Document.prototype,"hidden")`.
- **78** `WC` для: `AudioContext, OfflineAudioContext, Worker, SharedWorker, WebSocket, RTCPeerConnection, Notification, EventSource, OffscreenCanvas, PerformanceObserver`.
- **79-80** `Element.prototype.setAttribute`: для `src|srcdoc|data` при `SN<200` — `W("setattr:"+n,[value.slice(0,160),T()])`, иначе `C("setattr")`; `GC(Element.prototype,"getBoundingClientRect")`; `GC` над `HTMLElement.prototype` `offsetWidth, offsetHeight, offsetLeft, offsetTop, clientWidth, clientHeight` (через `GC`, хотя это геттеры — `GC` требует `typeof d.value === "function"`, для accessor-свойств он выйдет по `return`; фактически эти свойства в Blink — accessor'ы, поэтому обёртка, вероятно, не срабатывает — не проверено на рантайме).
- **81** `getComputedStyle`: `C("getComputedStyle")`.
- **82** `matchMedia`: `C("matchMedia")`, при `MQN<30` — `W("mq:query",[q.slice(0,120),T()])`.
- **83-84** `HTMLIFrameElement.prototype.src`: обёртки get/set с `C("iframe.src:get"|"iframe.src:set")`.
- **85** `GP(window,"localStorage")`, `GP(window,"sessionStorage")`, `GP(window,"indexedDB")`.
- **86** `W("_boot",[navigator.userAgent.slice(0,160), String(location.href).slice(0,200), T(), SH?1:0, "__G__"==="1"?1:0])` — первая запись: UA, URL, время, флаг «общая маска с родителем», флаг spoof.
- **87** закрытие IIFE.

Ключи записей харнесса (потребляются writer.rs/classify.rs; в classify.rs:235-236 перечислены как значимые): `_boot, _c, _m, _mm, _dr, _th, slow:<name>, stk:<tag>, src:<tag>, net:send, listen, setattr:<attr>, mq:query, gl:shader, wasm, wasm:exp, wmem:new, wmem:grow, sab, po:obs, po:cb, worker:src, new:<Class>, call:<Class>, call:eval, new:Function, call:Function, <methodName> (для FP-обёрток), disp:<type> (только в счётчиках AG)`.

### Тесты
В `inject.rs` модуля тестов НЕТ. Синтаксис шаблона проверяется отдельным бинарником `src/bin/jscheck.rs` (не `#[test]`), который требует `node`.

---

## src/relay.rs — исполнение внешних JS-снипетов во всех вкладках по HTTP-очереди

Импорты (1-13): `crate::arch`, `crate::capture::Tab`, `crate::ctx::Ctx`, `crate::events::{FxEvent, K_META}`, `base64::Engine`, `bytes::{BufMut, Bytes, BytesMut}`, `chromiumoxide::cdp::js_protocol::runtime::EvaluateParams`, `serde_json::Value`, `HashSet`, `PathBuf`, `Ordering`, `Arc`, `Duration`.

### fn now_ms() -> u64  (строки 15-20)
- идентичен capture.rs:84-89 (дубль функции, а не переиспользование).

### fn env_u64(k: &str, d: u64) -> u64  (строки 22-24)
- `std::env::var(k).ok().and_then(parse).unwrap_or(d)`. Дубль main.rs:88-90.

### pub struct RelayOut  (строки 26-29)
- поля: `executed: u64` (сколько снипетов исполнено), `errors: u64` (сколько снипетов не дали ни одного `ok` при непустом списке вкладок).
- связи: возвращается из `run`, используется в main.rs:487-493 → `MRun.relay`.

### fn meta_ev(ctx: &Ctx, d: Bytes)  (строки 31-43)
- шлёт `FxEvent { site:0, tun:0, tab:0, vendor:0, name:0, kind: K_META, d }` с `t = now_ms()`. writer.rs:377-391 дописывает `{"t":<ts>,"d":<payload>}` и аппендит в `stage/meta.jsonl`.

### fn relay_line(kind: &str, id: &str, extra: &str) -> Bytes  (строки 45-59)
- назначение: собрать JSON-строку меты без serde.
- что внутри: `{"relay":"<kind>","id":"<id>"` + (если `extra` непуст) `,` + `&extra.as_bytes()[1..]` + `}`. ВАЖНО: `extra` всегда начинается с `,`, и первый байт СРЕЗАЕТСЯ — т.е. вызывающий обязан передать строку, начинающуюся с запятой; иначе первый символ полезного текста теряется.
- дырка: `kind` и `id` НЕ экранируются — значение `id` приходит из внешней очереди и вставляется в JSON как есть (инъекция JSON возможна, если id содержит кавычки). Ошибки curl'а в `poll-err` тоже подставляются сырыми (`format!(",\"e\":\"{e}\"...")`, строка 227).

### struct Item  (строки 61-64)
- поля: `id: String`, `js: String`.

### fn parse_items(body: &str, api_json: bool) -> Vec<Item>  (строки 66-98)
- назначение: разобрать ответ очереди в список снипетов.
- что внутри:
  1. Если `api_json` (URL содержит `api.github.com`): парсит JSON, берёт поле `content` (строка), base64-STANDARD-декодит в `String::from_utf8_lossy`. Любая ошибка → пустой `Vec`. Это формат GitHub Contents API (`GET /repos/<o>/<r>/contents/queue/pending.json`).
  2. Иначе текст = body как есть.
  3. Парсит JSON после `trim_start_matches('\u{feff}')` (снятие BOM).
  4. Берёт массив `items`; для каждого — `id` и `js` (строки, при отсутствии `""`); в результат попадают только оба непустых.
- связи: тест `parse_raw_and_api` (247-259). Формат очереди задаёт `tools/push-js.py` (пишет `{"id": "j<ms>", "js": ..., "added": ...}` в `queue/pending.json`, держит не более 100 элементов).
- неясность: `queue/pending.json` в репозитории содержит элементы вида `{"u": "..."}` без `id`/`js` — такие элементы `parse_items` отбросит (оба поля пустые). Похоже, файл в репо используется как список целей, а не как relay-очередь; workflow `.github/workflows/afeye.yml:22` задаёт `AFEYE_QUEUE_URL` на raw-URL этого же файла.

### fn wrap_js(js: &str) -> String  (строки 100-105)
- назначение: безопасная обёртка снипета для `Runtime.evaluate`.
- что внутри: `b = base64 STANDARD.encode(js.as_bytes())`; шаблон (одна строка):
  `(function(){var t0=performance.now();try{var r=eval(atob('<b>'));var ms=performance.now()-t0;try{var s=String(r);return JSON.stringify({ok:1,ms:Math.round(ms*10)/10,r:s.slice(0,384)})}catch(x){return JSON.stringify({ok:1,ms:...,r:''})}}catch(x){return JSON.stringify({ok:0,ms:Math.round((performance.now()-t0)*10)/10,e:String(x&&x.message||x).slice(0,384)})}})()`
  Свойства: код передаётся через base64 (никакого экранирования кавычек не нужно); результат — всегда строка JSON; `ms` округлён до 0.1 мс; значение результата урезается до 384 символов; сообщение об ошибке — до 384; внутренняя ошибка сериализации результата не портит `ok:1`. Тайминг — по `performance.now()` страницы (т.е. при `AFEYE_VIRTUAL_CLOCK` — виртуальное время).
- связи: `run` (176), тест `wrapper_is_valid_js`.

### async fn eval_tab(page: &chromiumoxide::Page, expr: &str) -> Option<String>  (строки 107-118)
- `EvaluateParams::builder().expression(expr).return_by_value(true).build().ok()?`; `tokio::time::timeout(Duration::from_secs(20), page.execute(p)).await.ok()?.ok()?`; возвращает `Some(s)` только если `result.result.value` — `Value::String`.
- таймаут: **20 секунд на вкладку** — единственное место с таким длинным ожиданием evaluate.

### fn load_processed(path: &PathBuf) -> HashSet<String>  (строки 120-132)
- читает JSONL, из каждой строки берёт `id` (строка) в множество. Ошибки чтения игнорируются (пустое множество).

### pub async fn run(ctx: Arc<Ctx>, tabs: Vec<Tab>) -> RelayOut  (строки 134-241)
- назначение: цикл опроса очереди и исполнения снипетов.
- что внутри (по шагам):
  1. `AFEYE_QUEUE_URL` — должен начинаться с `http`, иначе немедленный возврат нулевого `RelayOut` (136-139).
  2. `api_json = url.contains("api.github.com")` (140).
  3. `AFEYE_QUEUE_TOKEN` → заголовок `Authorization: Bearer <token>` (141-143).
  4. `every = AFEYE_RELAY_POLL` сек, default 30, `.max(5)` — минимум 5 секунд (144).
  5. `state_path = ctx.stage.join("relay-state.jsonl")`; `processed = load_processed(&state_path)` (145-146).
  6. `dump_path = $AF_ROOT (или ".") + /dumps/relay-state.jsonl`; `dump_processed = load_processed(...)` (147-152). Два независимых журнала «уже исполнено».
  7. `meta_ev(relay_line("poll-on","",",\"tabs\":N"))` (153-157).
  8. Цикл (158-239):
     - выход при `ctx.cn.stop` или `ctx.cn.dead` (Acquire), а также при `Instant::now() > ctx.deadline`.
     - `bust = "{url}?t={now_ms}"` — cache-buster; `arch::curl_get(&bust, hdr, 12)` — внешний `curl -sSL --max-time 12` (arch.rs:162-176), stderr в null, при ненулевом rc → `Err("curl rc=N")`.
     - При `Ok(body)`: `err_n = 0`; по каждому `parse_items`:
       - пропуск если id уже в `processed` ИЛИ в `dump_processed`;
       - проверка `stop` перед каждым снипетом (break из for);
       - `expr = wrap_js(&it.js)`; для каждой вкладки ПОСЛЕДОВАТЕЛЬНО `eval_tab`; парсит ответ: `ok==1` → `ok_n += 1`; `ms` → максимум в `max_ms`; `last` = последний сырой ответ;
       - `arch::write_append` одной и той же строки `{"id":"<id>","t":<ms>,"tabs":<N>,"ok":<ok_n>}` в ОБА файла (dump_path и state_path) (195-202);
       - вставка id в оба множества;
       - `prev = ",\"r\":<last>"` если last непуст;
       - `meta_ev(relay_line("exec", id, ",\"ms\":<max_ms>,\"tabs\":<N>,\"ok\":<ok_n><prev>"))`;
       - `out.executed += 1`; если `ok_n == 0 && !tabs.is_empty()` → `out.errors += 1`.
     - При `Err(e)`: `err_n += 1`; мета-событие `poll-err` с `{"e":"<e>","n":<err_n>}` только на первой ошибке и далее каждые 10 (`err_n == 1 || err_n.is_multiple_of(10)`).
     - Ожидание: цикл по 1 секунде до `every.as_secs()`, с проверкой `stop`/`dead` → немедленный `return out` (не `break`).
- связи: `arch::curl_get`, `arch::write_append`, `ctx.tx` (K_META), `ctx.cn.stop/dead`, `ctx.deadline`, `ctx.stage`. Запускается из main.rs:456-458 только если `AFEYE_QUEUE_URL` начинается с `http`.
- backpressure/ошибки: снижение частоты при ошибках отсутствует (нет backoff) — при недоступной очереди опрос идёт каждые `every` секунд; каждая вкладка ждёт до 20 с, поэтому при M вкладках один снипет может занять до 20*M секунд и заблокировать цикл (включая проверку `stop`).

### mod tests  (строки 243-276)
- `#[test] fn parse_raw_and_api` (247-259): raw-вход `{"items":[{"id":"a1","js":"console.log(1)"},{"id":"","js":"x"},{"js":"y"}]}` → ровно 1 элемент с `id=="a1"`, `js=="console.log(1)"` (элементы с пустым id или без id отбрасываются); затем тот же raw, завёрнутый в `{"content": base64(raw)}` и разобранный с `api_json=true` → 1 элемент; `"not json"` → пусто; `"{}"` → пусто.
- `#[test] fn wrapper_is_valid_js` (261-275): проверяет форму обёртки — начинается с `(function(){`, содержит `atob('`, заканчивается `})()`, и **не содержит ни одной двойной кавычки** (`assert!(!w.contains("\""))`) — это гарантия, что JSON-строка в шаблоне не конфликтует с внешним JSON. Затем пишет обёртку в `$TMPDIR/afeye_relay_check.js` и запускает `node --check <file>` через `std::process::Command::new("node")` с `.unwrap()`. **Тест требует установленного `node` в PATH**; без него падает на `unwrap()` (spawn error), а не на assert'е.

---

## src/human.rs — эмуляция человеческого ввода через CDP Input

Импорты (1-8): `crate::capture::Tab`, `crate::ctx::{char_floor, Cn, Ctx, host_of}`, `chromiumoxide::cdp::browser_protocol::input::*`, `chromiumoxide::cdp::browser_protocol::page::ReloadParams`, `rand::rngs::SmallRng`, `rand::{Rng, SeedableRng}`, `Arc`, `Duration`.

### const CDP / CDP_IN / DEGRADE  (строки 10-12)
- `CDP = 2s` — таймаут «тяжёлых» CDP-команд (`Page.reload`, `Runtime.evaluate` в poke).
- `CDP_IN = 600ms` — таймаут на ОДНО input-событие (мышь/клавиша).
- `DEGRADE = 15s` —冷却 вкладки после провала input-команды.

### struct Mv  (строки 14-17)
- поля: `x: f64`, `y: f64` — текущая позиция курсора вкладки.

### fn bez(p: &[f64; 4], t: f64) -> f64  (строки 19-22)
- кубическая кривая Безье по 4 контрольным точкам: `u^3*p0 + 3u^2 t*p1 + 3u t^2*p2 + t^3*p3`, `u = 1-t`. Единственная «кривая» в модуле — распределения задаются равномерными `gen_range`, не гауссовыми.

### struct Me  (строки 24-31)
- назначение: параметры одного мышиного события.
- поля: `x: f64`, `y: f64`, `ty: DispatchMouseEventType`, `btn: Option<MouseButton>`, `clicks: i64`, `dy: Option<f64>`.

### async fn mouse(page: &Page, m: &Me) -> bool  (строки 33-48)
- назначение: **CDP `Input.dispatchMouseEvent`** с таймаутом.
- что внутри: builder `x(m.x).y(m.y).type(m.ty.clone())`; при `btn.is_some()` — `.button(btn.clone())`; при `clicks > 0` — `.click_count(m.clicks)`; при `dy.is_some()` — `.delta_y(d).delta_x(0.0)`. Если `build()` вернул `Err` → `false`. Иначе `matches!(timeout(CDP_IN=600ms, page.execute(p)).await, Ok(Ok(_)))` — т.е. таймаут и CDP-ошибка одинаково дают `false`.
- связи: единственный способ послать мышь; `false` трактуется в `drive` как «вкладка мертва» → `bad_until`.

### async fn key(page: &Page, c: char) -> bool  (строки 50-70)
- назначение: **CDP `Input.dispatchKeyEvent`** для одного символа.
- что внутри: `s = c.to_string()`; KeyDown с `key(&s)` И `text(&s)`; KeyUp с `key(&s)` (без `text`). Если оба builder'а успешны: KeyDown под таймаутом `CDP_IN`; при провале — `false`; иначе `sleep(60ms)` и KeyUp под таймаутом, результат = успех KeyUp.
- дырка: не передаются `windowsVirtualKeyCode`/`nativeVirtualKeyCode`/`code`, поэтому для букв blink получит `vk=0` — патч 0009 (`input/key`) залогирует `vk=0 code=0 key=<dom_key>`.

### async fn enter(page: &Page) -> bool  (строки 72-97)
- то же, но с полными полями: KeyDown `key("Enter").code("Enter").text("\r").windows_virtual_key_code(13).native_virtual_key_code(13)`; `sleep(70ms)`; KeyUp с теми же key/code/vk (без `text`).

### fn rand_text(rng: &mut SmallRng, n: usize) -> String  (строки 99-109)
- `n` символов: с вероятностью 0.7 — цифра `b'0'..=b'9'`, иначе — строчная латинская `b'a'..=b'z'`. Распределение равномерное, без учёта раскладки/частотности.

### fn input_ev(ctx: &Ctx, t: &Tab, a: &str, n: u64)  (строки 111-130)
- назначение: записать действие драйвера в общий поток событий как `K_INPUT`.
- что внутри: собирает байтами `{"a":"<a>","n":<n>}` (itoa для числа), шлёт `FxEvent { t: now_ms(), site: t.site, tun: t.tun, tab: t.tab, vendor:0, name:0, kind: K_INPUT, _pad:0, d }`.
- дырка: `a` вставляется без экранирования, но все вызовы передают литералы (`reload`, `down`, `type`, `enter`, `poke`) — безопасно по факту.
- значения `a` по местам вызова: `"reload"` (198), `"down"` (249), `"type"` (294), `"enter"` (297), `"poke"` (347). События wheel/keypress/move НЕ эмитируются как K_INPUT.

### fn now_ms() -> u64  (строки 132-137)
- третья копия той же функции (capture.rs:84, relay.rs:15).

### async fn poke(ctx: &Ctx, tb: &Tab, ep: &str)  (строки 139-152)
- назначение: повторно дёрнуть замеченный endpoint того же сайта, чтобы спровоцировать антифрод-логику.
- что внутри: экранирование `\\` → `\\\\` и `'` → `\\'`; выражение `try{fetch('<ep>',{credentials:'include'}).catch(function(){})}catch(x){}`; `EvaluateParams::builder().expression(expr).build()` (**CDP `Runtime.evaluate`**, БЕЗ `return_by_value`); `timeout(CDP=2s, tb.page.execute(p))`, результат игнорируется; `Cn::inc(&ctx.cn.poke)`.
- связи: endpoint'ы берутся из `ctx.endpoints`, который наполняет writer при разборе `net:send` из JS-батчей (writer.rs:315-327). Т.е. poke замыкает цикл: инжект видит отправку → writer интернирует endpoint → human бьёт по нему повторно.

### pub async fn drive(ctx: Arc<Ctx>, tabs: Vec<Tab>)  (строки 154-355)
- назначение: главный бесконечный цикл эмуляции пользователя.
- инициализация (155-168):
  - `seed = ctx.t0ms ^ 0x9E37_79B9_7F4A_7C15` (константа золотого сечения) → `SmallRng::seed_from_u64`. Детерминированность от времени запуска, не от конфигурации.
  - `reload_every = AF_RELOAD_SECS` сек, default 70.
  - `pos` — по `Mv{640.0, 400.0}` на вкладку (старт в центре окна 1280x832).
  - `cands` — кандидаты-элементы на вкладку.
  - `last_ref`, `last_poke`, `last_reload` — `Instant::now()` на вкладку.
  - `bad_until` — `Option<Instant>` на вкладку.
- цикл (169-354):
  1. Выход: `cn.dead` (Acquire), `Instant::now() > ctx.deadline`, `tabs.is_empty()`. Заметьте: `cn.stop` здесь НЕ проверяется (в отличие от relay) — драйвер останавливается только по `dead`/дедлайну.
  2. `i = rng.gen_range(0..tabs.len())` — равновероятный выбор вкладки.
  3. Если `bad_until[i]` в будущем → `continue` (горячая прокрутка без задержки — потенциальный busy-loop на время деграда, т.к. sleep в конце цикла не достигается).
  4. Если `last_ref[i].elapsed() > 12s` → `cands[i] = capture::eval_list(&tabs[i].page).await` (обновление списка кликабельных элементов, до 40).
  5. Reload: если `reload_every > 0` и `last_reload[i].elapsed() > reload_every + rng(0..20)s` → сброс `cands[i]`, **CDP `Page.reload`** (`ReloadParams::default()`, таймаут `CDP=2s`), `input_ev("reload",1)`, `sleep(rng 400..900ms)`, `continue`.
  6. Цель: `pick` = с вероятностью 0.75 случайный кандидат из `cands[i]` (если непусто), иначе `None`. `(tx,ty)` = координаты кандидата либо `rng(30.0..1250.0) x rng(30.0..780.0)`.
  7. Перемещение: `steps = rng(10..28)`; `jx = rng(-180.0..180.0)`, `jy = rng(-160.0..160.0)`; для `s = 1..=steps`: `t = s/steps`, `x = bez([x0, (x0+tx)/2 + jx, (x0+tx)/2, tx], t)`, `y = bez([y0, (y0+ty)/2 + jy, (y0+ty)/2, ty], t)`. Контрольные точки: p1 сдвинута джиттером, p2 — ровно середина (асимметричная дуга). Каждому шагу — `MouseMoved` и `sleep(rng 8..17ms)`. При провале — `alive=false`, break.
     Скорость: 10-28 точек на движение с интервалом 8-17 мс → длительность перелёта 80-476 мс.
  8. `cur.x = tx; cur.y = ty`. При `!alive` → `bad_until[i] = now + DEGRADE(15s)`, `continue`.
  9. `act = rng(0..100)`:
     - `act < 30` (клик, 30%): `input_ev("down",1)`; `MousePressed` (Left, clicks=1); при успехе `sleep(rng 40..110ms)` (длительность нажатия) и `MouseReleased`; `alive` = успех release. Затем, если цель была кандидатом с тегом `INPUT|TEXTAREA|SELECT` и `rng.gen_bool(0.7)`: `sleep(rng 150..400ms)`, `n = rng(3..12)`, `txt = rand_text(n)`, посимвольно `key(c)` + `sleep(rng 55..170ms)`; при полном успехе — `input_ev("type", n)` и с вероятностью 0.3 `enter(&page)` + `input_ev("enter",1)`.
     - `30 <= act < 60` (скролл, 30%): `d = rng(-700.0..-120.0)` (всегда отрицательный — скролл вниз); `rng(2..5)` событий `MouseWheel` с `dy = d/3.0` и `sleep(rng 30..90ms)` между ними. Итоговый суммарный delta_y = d.
     - `60 <= act < 68` (одиночное нажатие клавиши, 8%): случайная `a-z` через `key()`.
     - `68 <= act < 76` (poke, 8%, не чаще раза в 25 с на вкладку): `host = interner.resolve(tb.site)`; reservoir sampling по `ctx.endpoints` — перебор, для каждого endpoint'а того же хоста `n += 1; if rng.gen_bool(1.0/n) { pick = Some((id, count)) }` (равновероятный выбор одного из N); затем `ep = resolve(eid)`, обрезка `char_floor(ep,290)`, `poke(...)`, `input_ev("poke",1)`.
     - `act >= 76` (24%): ничего, кроме финального sleep.
  10. При `!alive` → `bad_until[i] = now + DEGRADE`.
  11. `sleep(rng(300..1600ms))` — пауза между действиями.
- распределения: ВСЕ равномерные (`gen_range`/`gen_bool`), единственная нелинейность — траектория Безье. Никаких логнормальных/гауссовых задержек нет.
- связи: `capture::eval_list`, `ctx.interner`, `ctx.endpoints`, `ctx.cn.{dead,poke}`, `ctx.deadline`, `ctx.tx` (K_INPUT), CDP `Input.dispatchMouseEvent`, `Input.dispatchKeyEvent`, `Page.reload`, `Runtime.evaluate`. Запускается из main.rs:454 (`tokio::spawn(human::drive(ctx.clone(), tabs.clone()))`).

### Связь human.rs с патчами Blink (что именно ловят инжектированные патчи на эти события)
- `Input.dispatchMouseEvent`/`dispatchKeyEvent` приходят в renderer как `WebInputEvent` с модификатором `kFromDebugger`. Патч `patches/0015-blink-input-master.patch` (строки патча 32-115) в `WidgetEventHandler::HandleInputEvent` пишет в sink строку `input/raw type=<name> mods=<int> dbg=<0|1> x= y= sx= sy= btn= clicks=` (мышь), `dx= dy= phase=` (wheel), `vk= code= key=` (клавиша), `id= ptype= x= y= force=` (pointer), kind `kInput`, лимит 4 000 000 записей, гейт `AFEYE_TRACE_INPUT=0`. Флаг `dbg=1` — прямой маркер того, что событие прислано драйвером, а не человеком.
- Патч `patches/0009-blink-input.patch` добавляет дублирующую запись на более высоком уровне: `KeyboardEventManager::KeyEvent` → `input/key type=%d vk=%d code=%d key=%u mods=%d` (строки патча 16-33) и `MouseEventManager::DispatchMouseEvent` → `input/mouse <type> x= y= sx= sy= btn= clicks= mods=` (строки патча 52-72), обе kind `kInput`, БЕЗ лимита счётчика и БЕЗ env-гейта (только общий `blink::afeye::Enabled()`).
- JS-сторона: харнесс (inject.rs:68) навешивает capture-слушатели на `window` для 24 типов из `WA` и считает `disp:<type>` в `AG` — эти счётчики уезжают батчами `_c` раз в 700 мс. Т.е. одно действие `human` даёт три независимых свидетельства: sink `input/raw` (dbg=1), sink `input/mouse|key`, и JS-счётчик `disp:*` + Rust-событие `K_INPUT`.
- Тайминги: все задержки `human` (8-17 мс между точками траектории, 40-110 мс нажатие, 55-170 мс между символами, 300-1600 мс между действиями) видны патчу 0012/0034 через `performance.now()`; при `AFEYE_VIRTUAL_CLOCK` страница видит виртуальное время, а sink пишет реальное монотонное (`NowNs()` = `MonoNs()`), поэтому сопоставление «ввод → реакция» требует учёта расхождения часов.

### mod tests  (строки 357-380)
- `#[test] fn bez_bounds` (361-369): для `t ∈ {0, .25, .5, .75, 1}` и точек `[0,50,100,200]` значение лежит в `0..=200` (выпуклая оболочка); плюс точные границы `bez([1,2,3,4],0)==1`, `bez([1,2,3,4],1)==4`.
- `#[test] fn rand_text_shape` (371-379): `SmallRng::seed_from_u64(42)`; `rand_text(10).len()==10`, все символы ASCII-alnum; второй вызов `rand_text(5)` отличается от первого (проверка продвижения RNG).

---

## Взаимодействия

### Кто вызывает эти модули
- `main.rs:381-389` — конструирует `capture::Tb` (site = interned host target'а, tab = индекс target'а, tun = interned имя туннеля/`"local"`), вызывает `capture::instrument(tb.clone(), &tg.url)` под таймаутом 90 с.
- `main.rs:445-453` — из `Vec<Tb>` делает `Vec<capture::Tab>` (page/site/tun/tab).
- `main.rs:454` — `tokio::spawn(human::drive(ctx.clone(), tabs.clone()))`.
- `main.rs:455-460` — `relay::run(ctx.clone(), tabs)` спавнится ТОЛЬКО если `AFEYE_QUEUE_URL` начинается с `http`; иначе `RelayOut{0,0}`.
- `main.rs:484` — `ctx.cn.stop.store(true)` (после окончания сессии браузинга): это останавливает `relay::run`, но НЕ `human::drive`.
- `main.rs:501-503` — `capture::finalize(&tb)` в spawn'ах для каждой вкладки.
- `main.rs:596` — `ctx.cn.dead.store(true)`: останавливает и `drive`, и `relay`, и writer.

### Что эти модули используют
- `ctx::Ctx`: `tx` (unbounded `Sender<FxEvent>`), `art` (unbounded `Sender<Art>`), `interner` (arena::Interner), `cn` (счётчики `Cn`: ev/req/resp/body/art/scripts/batch/drop/bin/bout/poke/stop/dead), `binding`, `gl_spoof`, `budget`+`budget_limit()`, `stage`, `deadline`, `t0ms`, `endpoints`.
- `ctx`-хелперы: `char_floor` (безопасная обрезка по границе UTF-8), `vendor_of_url`/`vendor_of_stack` (таблица `VENDORS`: cloudflare, datadome, kasada, human, akamai, fpjs, seon, arkose, hcaptcha, recaptcha, imperva, threatmetrix, iovation, shape), `host_of`, `endpoint_of`.
- `events`: константы kind'ов `K_REQ=1 … K_META=17`, коды тел `E_JS=0, E_WASM=1, E_JSON=2, E_HTML=3, E_CSS=4, E_TXT=5, E_BIN=6, E_POST=8` и `EXT = ["js","wasm","json","html","css","txt","bin","png","post"]` (индекс 7 = "png" не используется capture'ом — `E_POST=8` → "post"), билдер `J`, `FxEvent`, `Art`, `ExtCode::ext()`.
- `arena::fx64` — FNV-подобный хэш (rotate_left(5) ^ c, *0x517cc1b727220a95) для ключей `meta`.
- `arch::curl_get` (внешний curl, `-sSL --max-time N`), `arch::write_append` (create_dir_all + append).
- `writer` (потребитель): `handle()` — `K_FILE` → файл в stage; `K_META` → `stage/meta.jsonl`; `K_BATCH` → разбор плоского массива и построчная запись `{"t","b","j","kk","v"}` в timeline (+ antifraud-копия при vendor); остальные kind'ы → `{"t","u","s","b"[,"v"],"k","d"}` в `sites/<site>/tunnels/<tun>/<slot>/timeline.jsonl` и, при vendor≠0, в `sites/<site>/antifraud/<vendor>/timeline.jsonl`. Артефакты — `stage/artifacts/<hex32>.<ext>` с дедупом по хэшу.

### Пути файлов, которые создают/читают эти модули
- пишутся (через writer): `<stage>/sites/<site>/tunnels/<tun>/<slot>/timeline.jsonl`, `<stage>/sites/<site>/antifraud/<vendor>/timeline.jsonl`, `<stage>/artifacts/<blake3hex>.<ext>`, `<stage>/meta.jsonl`, `<stage>/relay-state.jsonl`, `<stage>/sites/<site>/tunnels/<tun>/tabs/<tab>.final.html`, `.../<tab>.shot.png`, `.../<tab>.storage.json`, `<stage>/sites/<site>/tunnels/<tun>/cookies.json`.
- `<AF_ROOT|\.>/dumps/relay-state.jsonl` — второй журнал relay (переживает перезапуск, т.к. stage — в `/tmp`).
- читаются: `<stage>/relay-state.jsonl`, `<AF_ROOT>/dumps/relay-state.jsonl`.
- временные (тесты): `$TMPDIR/afeye_relay_check.js` (relay), `$TMPDIR/afeye_inject_check.js` (bin/jscheck).

### Env-переменные, используемые/затрагиваемые этими четырьмя файлами
| Переменная | где | default | эффект |
|---|---|---|---|
| `AFEYE_QUEUE_URL` | relay.rs:136 (и main.rs:455) | — | URL очереди; без `http`-префикса relay выключен |
| `AFEYE_QUEUE_TOKEN` | relay.rs:141 | — | `Authorization: Bearer <token>` для curl |
| `AFEYE_RELAY_POLL` | relay.rs:144 | 30 | период опроса, сек; `.max(5)` |
| `AF_ROOT` | relay.rs:148 | `.` | корень для `dumps/relay-state.jsonl` |
| `AF_RELOAD_SECS` | human.rs:158 | 70 | период перезагрузки вкладки; 0 отключает reload |
| `AF_BUDGET_MB` | main.rs:93-95 (через `post_art`) | 350 | лимит суммарного объёма артефактов |
| `AF_GL_SPOOF` | main.rs:271 → inject.rs:6 | не задан | `__G__`→`1`: подмена UNMASKED_VENDOR/RENDERER_WEBGL |
| `ctx.binding` | main.rs:222 | `_k<t0ms%997>z` | имя binding'а и `window[B]` |

Env, которые читает патченый Chrome и которые влияют на данные этих модулей (задаются в browser.rs:126-131,163-166): `AFEYE_SINK`, `AFEYE_RAW_DIR`/`AF_RAW_DIR`, `AFEYE_VIRTUAL_CLOCK` (0034), `AFEYE_TRACE_BYTECODE` (0033), `AFEYE_TRACE_INPUT` (0015), `AFEYE_TRACE_DOM_VALUES` (0024).

### Пересечения capture/inject/human/relay
- `inject.rs` поставляет source для `capture::instrument`; результат его работы возвращается в `capture::on_bind` как `Runtime.bindingCalled` → `K_BATCH`.
- `capture::eval_list` используется `human::drive` для выбора целей кликов.
- `ctx.endpoints`, заполняемый writer'ом из батчей инжекта (`net:send`), используется `human::poke`.
- `relay::run` и `capture::eval_str`/`human::poke` независимо вызывают `Runtime.evaluate` на одной и той же `Page`; relay отличается таймаутом 20 с и `return_by_value(true)`.
- `Tab` (capture.rs:19-25) — общий тип для human и relay; `Tb` — только для capture.

### Дырки и неясности (по четырём файлам)
1. capture.rs:645 — `s.truncate(512)` для console-аргументов: `String::truncate` паникует, если граница попадает внутрь многобайтового символа. Потенциальный panic в обработчике события (задача tokio, процесс не упадёт, но поток событий этой подписки оборвётся).
2. capture.rs:422 — второй элемент кортежа в `meta` всегда `true` и нигде не читается (мёртвое поле).
3. capture.rs:129-148 — `budget` только растёт; дубликаты (writer отбрасывает по `seen`) всё равно списывают бюджет.
4. capture.rs:247-250 — ошибка `event_listener` приводит к тихому отказу от всего потока событий; логов нет.
5. capture.rs:535-539 — `n` (полная длина WS-payload) не согласована с обрезанным `p`; флага усечения нет.
6. relay.rs:45-59 — `relay_line` режет первый байт `extra`; `id`/`kind`/текст ошибки не экранируются (JSON-инъекция из внешней очереди).
7. relay.rs:180-194 — вкладки опрашиваются последовательно с таймаутом 20 с каждая; при зависшей странице один снипет блокирует цикл до 20*N секунд, проверка `stop` внутри цикла по вкладкам отсутствует.
8. relay.rs:224-229 — нет backoff'а при ошибках curl; `poll-err` логируется только на 1-й и каждой 10-й ошибке.
9. relay.rs:195-202 — строка состояния пишется в два файла синхронно (`arch::write_append` = `fs::create_dir_all` + open + write на каждую запись) внутри async-контекста, блокируя executor.
10. inject.rs:80 — `GC(HTMLElement.prototype, "offsetWidth")` и т.п.: `GC` требует `typeof d.value === "function"`, а эти свойства в Blink — accessor'ы, поэтому обёртка, вероятно, не устанавливается. Проверить в рантайме не могу (сборка запрещена заданием) — помечаю как неясность.
11. inject.rs:20 — `CAP=6000` считается по ЭЛЕМЕНТАМ массива (по 3 на запись) → реальный лимит ~2000 записей между флашами; при переполнении считается только `DR`, содержимое теряется без деталей.
12. human.rs:180-185 — при активном `bad_until` выполняется `continue` до финального `sleep`, что даёт горячий цикл опроса всех вкладок в течение до 15 с.
13. human.rs:170 — `cn.stop` не проверяется: драйвер продолжает слать ввод после завершения сессии браузинга (до `dead`/дедлайна).
14. human.rs:50-70 — `key()` не передаёт `windowsVirtualKeyCode`/`code`, поэтому в sink-записях 0009/0015 для таких нажатий `vk=0 code=0` — отличается от `enter()`, где поля заполнены.
15. Три копии `now_ms()` (capture.rs:84, relay.rs:15, human.rs:132) и две `env_u64` (main.rs:88, relay.rs:22) — дублирование без общего модуля.
16. `queue/pending.json` в репозитории содержит элементы `{"u": ...}` без `id`/`js`; `parse_items` их отфильтрует. Неясно, является ли этот файл реальной relay-очередью или списком целей (`.github/workflows/afeye.yml:22` указывает `AFEYE_QUEUE_URL` именно на него).

---

## АУДИТ СООТВЕТСТВИЯ ЭТАЛОНУ

### 1. Флаги `--jitless --no-opt --no-sparkplug` (детерминированный интерпретаторный режим)

Что реально есть в `src/browser.rs`, функция `chrome_flags` (строки 58-102):
- `--jitless` — **ЕСТЬ**, browser.rs:98, внутри условия browser.rs:93: `if std::env::var("AF_JITLESS").map(|v| v == "1").unwrap_or(false)`. Гейт — env `AF_JITLESS`, строго строка `"1"`; по умолчанию НЕ задан → флаг не добавляется. Комментарий browser.rs:94-97 явно связывает это с патчем 0033 («interpreter-only mode… nothing escapes to Sparkplug/Maglev/TurboFan») и с 0034 (`AFEYE_VIRTUAL_CLOCK`).
- `--no-opt` — **НЕТ**. Поиск по всему репо (`--no-opt|--no-sparkplug|--js-flags|no_maglev|no-turbofan`) дал единственное вхождение `--jitless` (browser.rs:98); других JIT-флагов нет ни в `chrome_flags`, ни в workflow, ни в scripts.
- `--no-sparkplug` — **НЕТ**, там же.
- `--js-flags=...` — **НЕТ** (никаких V8-флагов через js-flags не передаётся).

Полный список флагов (browser.rs:64-101): `--no-first-run`, `--no-default-browser-check`, `--disable-session-crashed-bubble`, `--hide-crash-restore-bubble`, `--disable-search-engine-choice-screen`, `--disable-features=IsolateOrigins,site-per-process,PrivacySandboxSettings4`, `--disable-site-isolation-trials`, `--enable-unsafe-swiftshader`, `--password-store=basic`, `--use-mock-keychain`, `--no-sandbox`, `--remote-debugging-address=<bind>`, `--remote-debugging-port=<port>`, `--user-data-dir=<profile>`, `--window-size=1280,832`, `--window-position=<x>,<y>`; условно `--user-agent=<ua>` (82-84), `--headless --disable-gpu` (85-88 при `AF_TEST_HEADLESS`, 89-92 при `f.headless_shell`), `--jitless` (93-99); последний аргумент `about:blank` (100).

Чего НЕ ХВАТАЕТ по эталону:
- `--no-opt` (запрет TurboFan-оптимизации) — отсутствует.
- `--no-sparkplug` (запрет baseline-компилятора) — отсутствует.
- Формально `--jitless` в V8 сам по себе отключает и Sparkplug, и Maglev, и TurboFan, поэтому отсутствие двух других флагов при `AF_JITLESS=1` покрыто; но эталон требует их явно — **НЕ соответствует по букве** (требуется: добавить `--no-opt` и `--no-sparkplug` в тот же блок browser.rs:93-99).
- Отдельная проблема: **по умолчанию режим НЕ детерминированный** — `AF_JITLESS` нигде не выставляется в самом репо (grep по `.github/`, `scripts/`, `src/` нашёл только чтение в browser.rs:93; ни один workflow его не устанавливает). Значит в типовом запуске JIT включён, и трейс 0033 видит только инструкции до компиляции. Требуется: выставлять `AF_JITLESS=1` (и `AFEYE_VIRTUAL_CLOCK`) в месте запуска (`main.rs`/workflow), либо сделать `--jitless` безусловным.

### 2. Патч диспетчера Ignition (эталон: хук в `GENERATE_BYTECODE_HANDLER` в `src/interpreter/interpreter-generator.cc`)

Реально в `patches/0033-v8-ignition-bytecode-trace.patch` (929 строк, трогает 5 файлов):
- `v8/src/afeye/bcrec.h` (новый, строки патча 1-366) — wire-формат.
- `v8/src/afeye/sink.cc` (367-387) — `g_vclock_ns`, `afeye_vclock_ns()`, `VclockTick(ns)`.
- `v8/src/afeye/sink.h` (388-414) — `kBytecodeTrace = 40`, объявления vclock.
- `v8/src/interpreter/interpreter-assembler.cc` (415-454) — **место хука**.
- `v8/src/runtime/runtime-trace.cc` (455-900) — `RUNTIME_FUNCTION(Runtime_AfeyeTraceBytecodeEntry)`.
- `v8/src/runtime/runtime.h` (901-929) — регистрация intrinsic `AfeyeTraceBytecodeEntry, 4, 1, kCannotTriggerGC`.

Где РЕАЛЬНО стоит хук:
- НЕ в `interpreter-generator.cc` и НЕ в макросе `GENERATE_BYTECODE_HANDLER`. Хук стоит в `v8/src/interpreter/interpreter-assembler.cc` в **конструкторе** `InterpreterAssembler::InterpreterAssembler(...)` — строки патча 419-434 (вставка после инициализации `bytecode_array_valid_(true)`), и второй — в `InterpreterAssembler::InlineShortStar(...)` — строки патча 438-451. Комментарий патча (424-429) объясняет выбор: конструктор вызывается кодогенератором для КАЖДОГО обработчика байткода, поэтому `CallRuntime(Runtime::kAfeyeTraceBytecodeEntry, GetContext(), BytecodeArrayTaggedPointer(), SmiTag(BytecodeOffset()), GetAccumulatorUnchecked(), SmiTag(IntPtrConstant(operand_scale_)))` компилируется внутрь каждого обработчика; `operand_scale_` — константа времени кодогенерации, поэтому Wide/ExtraWide несут настоящий масштаб. Второй хук нужен потому, что Star0-Star7 инлайнятся в предыдущий обработчик через `StarDispatchLookahead` и через конструктор не проходят (строки патча 443-445).
- Итого: цель (каждый обработчик байткода логирует исполнение) достигнута, но **точка входа другая** — `interpreter-assembler.cc` вместо `interpreter-generator.cc`/`GENERATE_BYTECODE_HANDLER`. Соответствие по сути — ДА, по букве эталона — НЕТ (требуется либо признать эквивалентность, либо перенести хук в генератор).

Что фиксируется реально vs эталон, по пунктам:
| Эталон требует | Реально | Где |
|---|---|---|
| `BytecodeOffset` | ДА: `SmiTag(BytecodeOffset())` передаётся в runtime; в runtime пересчитывается `offset = bytecode_offset - BytecodeArray::kHeaderSize + kHeapObjectTag` и кладётся в `Hdr.offset` | патч 431, 762, 773, 808 |
| опкод | ДА: читается из байткода `op_byte = *pc`, пишется в `Hdr.opcode` | патч 786-787, 807 |
| аргументы: имя свойства из пула констант | ДА, но косвенно: операнды декодируются движком (`BytecodeDecoder::DecodeUnsignedOperand`/`DecodeSignedOperand`/`DecodeRegisterOperand`) и эмитятся блоками `kTagOperand` (индекс + u64 значение); сам пул констант целиком уходит в func-def blob (`kCpTagStr/Str16/F64/Raw`), а сопоставление «операнд 0 → cp[i]» делает уже Rust | патч 811-869; bcrec.h 75-80, 240-253; bctrace.rs:633-664 |
| аргументы: регистры источника и приёмника | ДА: для register-input операндов пишется `ib.Reg(idx, raw_word)` плюс, если в регистре String/HeapNumber/Smi — полное значение (`RegStr`/`RegStr16`/`RegF64`/`RegSmi`); первые 6 регистров дублируются в `Hdr.regs[6]`; аккумулятор — `Hdr.acc` + блоки `AccStr/AccF64/AccSmi` | патч 822-859, 871-885; bcrec.h 55, 171-223 |
| `SharedFunctionInfo` | ДА: `frame->function()` → `fn->shared()` → `sfi`; из него `script_id`, `function_literal_id()`, `StartPosition()`, из которых `MakeFuncId(script_id, literal_id, start_pos, iso_tag)` (FNV-1a по 16 байтам, `>>16`) даёт GC-стабильный `func_id` | патч 789-798; bcrec.h 117-133 |
| имя исходного скрипта | ЧАСТИЧНО: имя скрипта пишется ОДИН РАЗ на функцию в func-def blob (`AfeyeEmitFuncDef` → `sc->name()` → `name_buf` → `FuncDefBuilder.Build`), а не в каждой инструкции; инструкция несёт только `func_id` | патч 658-678, 727-732; bctrace.rs:60-68, 244-293 |

Дополнительно сверх эталона (в 0033 есть, эталон не требует): meta-запись один раз на процесс с полной таблицей опкодов — имена, `n_ops`, флаги (jump/returns/calls/subtype/cond), `acc_use`, размеры и (тип, смещение) каждого операнда для трёх масштабов, плюс имена всех runtime-функций (патч 589-656); дедупликация func-def по `(func_id, bc_len)` через `thread_local unordered_set` (патч 535-549, 800-803); сплит записей больше одного sink-слота флагом `kFlagCont` с `EmitSplit` (bcrec.h 332-360); счётчик виртуальных часов на каждой инструкции (см. п.3).

Расхождения по пунктам:
1. Файл/функция хука — `interpreter-assembler.cc:InterpreterAssembler::InterpreterAssembler` + `InlineShortStar` вместо `interpreter-generator.cc:GENERATE_BYTECODE_HANDLER`. **НЕ соответствует по месту, соответствует по покрытию.**
2. `interpreter.cc`/`DispatchTable` не тронуты вообще (в патче таких файлов нет). Эталонное описание «таблица перехода опкодов» фактически не используется.
3. Имя скрипта — не в каждой записи, а через справочник func-def. **НЕ соответствует по букве** (требуется: либо дублировать имя/его id в каждую инструкцию, либо считать соответствие через `func_id`).
4. Хук выполняется через `CallRuntime` — это полноценный runtime-вызов на КАЖДУЮ инструкцию (патч 430-433), а не «лёгкий» логгер; intrinsic помечен `kCannotTriggerGC` (патч 911-912), внутри `DisallowGarbageCollection no_gc` (патч 758). Соответствует требованию детерминизма, но это и есть источник замедления, который эталон предлагает компенсировать виртуальными часами (п.3) — компенсация есть.
5. Лимиты: в bcrec.h заявлено «No limits anywhere» (строки патча 17-22), реальная квота — sink-уровня (`kMaxRecord = 1MiB`, `kRingBytes = 8MiB`, ring-переполнение → `g_dropped` в 0001-v8-sink.patch:73-90, 257-259), т.е. ограничение всё же есть, но не в трейсе, а в транспорте; `SERIES.md:85` упоминает квоту 50M инструкций и `AFEYE_BC_CAP`, однако **в самом патче 0033 ни `AFEYE_BC_CAP`, ни счётчика 50M нет** (grep по патчу: только `AFEYE_TRACE_BYTECODE`, `AFEYE_VIRTUAL_CLOCK`, `AFEYE_VCLOCK_NS_PER_INSTR`). Расхождение документации с кодом.

### 3. Виртуализация таймингов (эталон: `src/base/platform/time.cc` ИЛИ blink `Performance::now`, формула `virtual_time += kBaseInstructionCost * instruction_count`)

Реально в `patches/0034-v8-blink-virtual-clock.patch` (85 строк, 2 файла):
- `third_party/blink/renderer/core/timing/performance.cc` — патч строки 1-44. Добавлен `extern "C" uint64_t afeye_vclock_ns(void);` (строка патча 15) и блок в `DOMHighResTimeStamp Performance::now() const` (патч 19-44): при `blink::afeye::Enabled()` и `AFEYE_VIRTUAL_CLOCK` (гейт-лямбда, `v[0] != '0'`, строки патча 30-33) возвращается `g_afeye_origin_ms + afeye_vclock_ns()/1e6`, где `g_afeye_origin_ms` — однократно снятый `base::TimeTicks::Now().since_origin().InMillisecondsF()` (патч 35-37). Иначе — штатный `MonotonicTimeToDOMHighResTimeStamp(base::TimeTicks::Now())` (патч 43).
- `v8/src/objects/js-objects.cc` — патч строки 45-85. В `int64_t JSDate::CurrentTimeValue(Isolate*)` (т.е. `Date.now()`) при `v8::afeye::Enabled()` и том же env-гейте возвращается `g_afeye_epoch_ms + afeye_vclock_ns()/1e6`, где `g_afeye_epoch_ms` — однократно `V8::GetCurrentPlatform()->CurrentClockTimeMilliseconds()` (патч 69-80).
- Инкремент счётчика — НЕ в 0034, а в 0033: `runtime-trace.cc`, строки патча 768-770: `if (AfeyeVclockOn()) { v8::afeye::VclockTick(AfeyeVclockNsPerInstr()); }` — один тик на каждую исполненную инструкцию, ДО разбора операндов. Шаг: `AfeyeVclockNsPerInstr()` читает `AFEYE_VCLOCK_NS_PER_INSTR`, default `10` нс (патч 517-524). Хранение: `std::atomic<uint64_t> g_vclock_ns{0}`, `VclockTick` = `fetch_add(ns, relaxed)` (0033 патч 375-383).

Сопоставление с эталоном:
- Место: эталон допускает «`time.cc` ИЛИ blink `Performance::now`». Реально выбран blink `Performance::now` (performance.cc) плюс V8 `JSDate::CurrentTimeValue`. **Соответствует** (второй вариант эталона), performance.cc:патч-строки 19-44.
- `src/base/platform/time.cc` **НЕ тронут** — grep по всем патчам (`base/platform/time\.cc|kBaseInstructionCost|instruction_count`) не дал ни одного совпадения. Значит `base::TimeTicks::Now()`, `Clock::Now()`, монотонные часы sink'а (`NowNs()`/`MonoNs()`, 0001 патч:92, 235) и все небраузерные таймеры остаются ФИЗИЧЕСКИМИ. **НЕ соответствует первой части эталона**; следствие: `ts` в sink-записях (включая записи 0033) — реальное монотонное время, а не виртуальное.
- Формула: эталон `virtual_time += kBaseInstructionCost * instruction_count`. Реально — эквивалент с шагом 1 инструкцию: `g_vclock_ns += ns_per_instr` на каждую инструкцию (0033 патч 768-770, 381-383), т.е. `virtual_time = ns_per_instr * instruction_count`, `kBaseInstructionCost` = `AFEYE_VCLOCK_NS_PER_INSTR` (default 10 нс). **Соответствует по сути**; константа называется иначе и настраивается через env.
- Гранулярность/масштаб: `performance.now()` получает наносекунды/1e6 → мкс-точность; `Date.now()` целочисленно делит на 1e6 → 1 мс на 100 000 инструкций при default-шаге (это же честно noted в SERIES.md:88-89).
- Область действия счётчика: `g_vclock_ns` — одна атомик-переменная на процесс (0033 патч 375), НЕ на isolate; несколько вкладок/воркеров делят счётчик. Эталон предполагает единый `virtual_time` — формально совпадает, практически даёт перекрёстное влияние вкладок (отмечено в SERIES.md:89).
- Взаимодействие с 0012: патч `0012-blink-clock-canvas.patch` (строки 78-85) в том же `performance.cc` логирует каждый вызов `performance.now()` строкой `"clock performance-now"` kind `kClock` под гейтом `AFEYE_TRACE_CLOCK`. Порядок вставок: 0012 вставляет логирование, 0034 вставляет возврат виртуального значения ПОСЛЕ `#endif` блока 0012 (патч 0034:23-42) — т.е. при включённом vclock лог `kClock` пишется, но возвращаемое значение уже виртуальное. Оба патча правят один файл, порядок наложения существенен (0034 идёт после 0012 в нумерации серии).
- Чего не хватает по эталону: (а) `src/base/platform/time.cc` не виртуализован — `setTimeout`/`setInterval`/`requestAnimationFrame`/сетевые таймауты в Blink продолжают идти от физического `TimeTicks`; (б) `performance.timeOrigin`, `Date` конструктор (не `now`) и `new Date()` без аргументов — конструктор `JSDate::New` патчем НЕ затронут (в 0034 правится только `CurrentTimeValue`), хотя патч 0022 (`AFEYE_TRACE_CLOCK` в конструкторе Date) логирует его; (в) счётчик на процесс, а не на isolate.

### 4. Перехват WebIDL/DOM-биндингов (эталон: патч `src/bindings/core/v8/`, логировать геттер/сеттер интерфейса с аргументами и ТИПОМ возвращаемого значения)

Реально:
- `patches/0008-blink-dom-api.patch` (202 строки, 1 файл) хукает **`third_party/blink/renderer/platform/bindings/idl_member_installer.cc`** — НЕ `src/bindings/core/v8/`. Это уровень ниже: `idl_member_installer` ставит шаблоны/функции для атрибутов и операций всех IDL-интерфейсов, поэтому перехват получается всеобщим, а не по конкретным биндингам.
  - Механизм (патч 23-78): `struct AfeyeApiCell { v8::FunctionCallback orig; const char* prop; char what[104]; }`, пул `g_afeye_api_cells[1<<16]` с линейным пробированием от слота `(uintptr(orig) >> 4) & mask`, мьютекс, глобальный счётчик `g_afeye_api_calls`. `AfeyeWrapDomApi(isolate, orig, interface_name, accessor, property_name)` заполняет ячейку и формирует строку `what = "dom <interface>.<get|set|call> <property>"` (патч 68-69), возвращая `v8::External` с указателем на ячейку.
  - Подстановка (патч 94-112): в `CreateFunctionTemplate<kind>` определяется `afeye_access` = `"get"` для `kAttributeGet`, `"set"` для `kAttributeSet`, иначе `"call"`; если `AfeyeWrapDomApi` вернул непустой data — `callback` заменяется на `&AfeyeDomApiThunk`. Data-слот прокидывается в оба варианта создания шаблона (патч 121-122, 130-131) — там, где штатно стоял пустой `v8::Local<v8::Value>()`. Параметр `afeye_interface_name` добавлен в сигнатуры `CreateFunctionTemplate`/`CreateFunction` (патч 87, 139) и передан из `InstallAttribute` (get/set, патч 151-178) и `InstallOperation` (патч 181-199) как `interface_name_ptr`.
  - Что эмитит (патч 34-50): `AfeyeDomApiThunk` при `data->IsExternal()` достаёт ячейку, при `g_afeye_api_calls.fetch_add(1) < 8_000_000` пишет `blink::afeye::EmitStr(kDomApi, NowNs(), cell->what)`, затем вызывает оригинал. **Возвращаемое значение и аргументы в 0008 НЕ логируются.**
- `patches/0024-blink-dom-api-values.patch` (93+ строки, тот же файл `idl_member_installer.cc`) добавляет значение возврата:
  - `AfeyeCaptureValue(isolate, rv, buf, buf_sz)` (патч 25-58): `undefined` → `"undefined"`; `null` → `"null"`; boolean → `"0"/"1"`; number → `"%.17g"`; string → UTF-8 с обрезкой до `buf_sz-1` и заменой всех байтов `<0x20` и `>=0x7f` на `'?'`; array → `"[array len=N]"`; всё прочее → `"[object]"`.
  - Порядок в thunk'е изменён (патч 71-90): сначала фиксируется `afeye_record` (счётчик < 8M), ПОТОМ вызывается оригинал, ПОТОМ — если `AFEYE_TRACE_DOM_VALUES` не выставлен в `"0"` (патч 20-23) — пишется `"<what> val=<значение, до 150 символов>"` в буфере 320 байт; при выключенном гейте — прежняя строка без значения.
  - **Тип возвращаемого значения**: отдельного поля типа НЕТ; тип кодируется формой строки (`undefined`/`null`/`0|1`/число/строка/`[array len=N]`/`[object]`). Это различимо при парсинге, но не является явным типом. **Частично соответствует.**
  - **Аргументы вызова**: НЕ логируются ни в 0008, ни в 0024 — только имя интерфейса, вид доступа (get/set/call), имя свойства и значение возврата. **НЕ соответствует** (требуется: захватывать `info[i]` аналогично `AfeyeCaptureValue`).
- `patches/0019-blink-fp-values.patch` (341 строка, 7 файлов) — точечные хуки «значений фингерпринта», kind `kFingerprint`, все под `blink::afeye::Enabled()` и с собственными счётчиками-квотами:
  - `core/css/css_computed_style_declaration.cc` (патч 32-49): `GetPropertyCSSValue` → `"css/get-computed prop=%.64s val=%.96s"`, квота `g_afeye_css < 2_000_000`. Есть И аргумент (property), И значение (`value->CssText()`).
  - `core/css/font_face_set.cc` (патч 82-99): `FontFaceSet::check` → `"fonts/check font=%.96s text=%.40s"`, квота 200_000. Аргументы есть, возвращаемое значение (bool) — НЕТ.
  - `core/css/media_query_list.cc` (патч 131-146): `MediaQueryList::matches` → `"media/matches q=%.128s m=%d"`, квота 200_000. Аргумент (media) и результат (0/1).
  - `core/frame/local_dom_window.cc` (патч ~184-196 в файле, hunk `@@ -1106,6 +1119,16 @@`): `matchMedia(media)` → `"media/query q=%.128s"`, квота `g_afeye_mm < 200_000`. Только аргумент.
  - `modules/canvas/canvas2d/base_rendering_context_2d.cc` (hunk `@@ -1025,6 +1032,21 @@`): `DrawTextInternal` → `"canvas/draw-text op=stroke|fill text=%.64s font=%.64s xy=%.1f,%.1f"`, квота `g_afeye_drawtext < 2_000_000`. Аргументы есть, возврата нет (void).
  - `modules/notifications/notification.cc` (hunk `@@ -421,6 +428,12 @@`, `@@ -429,6 +442,12 @@`, `@@ -448,6 +467,20 @@`): `Notification::permission` → `"perm/notification value=denied ctx=insecure"` / `"... value=default ctx=prerender"` / `"perm/notification value=%s"` (granted|denied|prompt). Возвращаемое значение ЕСТЬ, аргументов нет.
  - `modules/permissions/permissions.cc` (hunk `@@ -113,6 +120,15 @@`): `Permissions::query` → `"perm/query name=%.40s"`. Аргумент есть, результата (promise) нет.
  - Итого 0019 — это НЕ общий перехват WebIDL, а ручной набор fingerprint-точек; общий перехват делает 0008+0024.
- Соответствие эталону по п.4: каталог НЕ тот (`platform/bindings/idl_member_installer.cc` вместо `bindings/core/v8/`), но покрытие шире (все IDL-атрибуты и операции, а не отдельные биндинги). Геттер/сеттер различаются (`get`/`set`/`call` в строке `what`). Возвращаемое значение — есть (0024), тип возврата — только неявно, формой строки. Аргументы — НЕТ. **Частично соответствует**; требуется: добавить захват аргументов в `AfeyeDomApiThunk` (0024) и явный тег типа返回值.
- Неясность: `interface_name_ptr` в 0008 используется как аргумент 6 раз (патч:156, 161, 171, 176, 187, 198), но патч его НЕ объявляет — переменная должна уже существовать в upstream `idl_member_installer.cc` (`InstallAttribute`/`InstallOperation`). Проверить по исходникам Chromium 153.0.8010.52 (CHROMIUM_REF из `.github/workflows/afeye-build.yml:48`) не могу: дерева chromium в репо нет, сборка заданием запрещена. Если такой переменной в upstream нет, патч 0008 не соберётся.
- Квота DOM-перехвата: `g_afeye_api_calls < 8_000_000` на процесс (0008 патч:41-42, 0024 патч:71-72) — после 8M записей thunk продолжает вызывать оригинал, но ничего не эмитит, и счётчик переполнения в отчёт не уходит (в отличие от sink-drop 0023). Это единственное «молчаливое» усечение в DOM-слое.

### 5. Финальный формат лога

Что реально пишет 0033 (`v8/src/afeye/bcrec.h` + `runtime-trace.cc`): бинарная запись, НЕ JSONL/protobuf. Заголовок `Hdr` — ровно 72 байта, little-endian, без паддинга (bcrec.h патч-строки 35-57, `static_assert(sizeof(Hdr)==72)`):
`u8 opcode` (0xff = func-def, 0xfe = meta, иначе opcode инструкции) | `u8 scale` (1/2/4) | `u8 n_payload` (saturate 255) | `u8 flags` (1=FuncDef, 2=Cont, 4=AccPayload) | `u32 offset` | `u32 func_id` | `u32 line` (для инструкции — isolate-тег, для func-def — стартовая строка функции, для meta — 0) | `u64 acc` (raw tagged word; для blob'ов — полная длина) | `u64 regs[6]`.
Далее payload-блоки `[u8 tag][u32 len][bytes]`, теги 0..13 (bcrec.h патч-строки 65-83). Запись уезжает через `v8::afeye::Emit(kBytecodeTrace=40, NowNs(), buf, size)` (патч 577-587), т.е. транспортный таймстамп — `NowNs()` = `MonoNs()` (0001 патч:92, 235), ФИЗИЧЕСКОЕ монотонное время. Rust-сторона: `collect.rs` (KINDS[40] = `"bytecode-trace"`, collect.rs:15-57; вид входит в `BATCHED_KINDS`, collect.rs:59-68, поэтому пишется в part-файлы с `PART_ROLL_BYTES = 8MiB`, collect.rs:69) → `index.jsonl` c полями `k`, `ts`, `pid`, `p`, `o`, `len` → `src/bctrace.rs:390-419` читает индекс, режет blob'ы по `o`/`len`, склеивает `kFlagCont`-части по `(opcode, func_id)` в порядке `offset` (bctrace.rs:433-521) и парсит `parse_instr` (bctrace.rs:295-311) в `InstrRec { ts, pid, func_id, offset, opcode, scale, flags, iso, acc, payloads }` (bctrace.rs:85-96). Семантический проход (bctrace.rs:592-750) пишет `filtered/bctrace/sem/<func_id:08x>.jsonl` по строке на инструкцию.

Таблица соответствия полей эталона:
| Поле эталона | Есть ли реально | Где именно (файл:строка) | Что делать, если нет |
|---|---|---|---|
| `timestamp_virtual` | **НЕТ** — есть `ts`, но это физическое монотонное время sink'а, не `afeye_vclock_ns()` | эмит: 0033 патч:584 (`v8::afeye::NowNs()`), `NowNs()=MonoNs()` в 0001 патч:235; запись в sem: `src/bctrace.rs:716` (`"ts": r.ts`) | либо класть в `Hdr` (например в неиспользуемое для инструкций поле `line`/отдельный блок) значение `afeye_vclock_ns()` на момент эмитa, либо писать его вторым u64-блоком payload; парсеру добавить поле `vts` в sem-строку (bctrace.rs:715-719) |
| `script_id` | **НЕТ** в sem-строке и **НЕТ** в `FuncDef` — script_id используется только как вход `MakeFuncId` и наружу не отдаётся | `MakeFuncId(script_id, literal_id, start_pos, iso_tag)`: 0033 патч:120-133, 797-798; `script_id` добывается в патч:795-796 и 668-673; `FuncDef` (Rust): bctrace.rs:60-68 — поля `func_id, line, frame_size, param_count, name, bytecode, cp`, script_id отсутствует; func-def blob layout: bcrec.h патч:240-243 — script_id не входит | добавить `script_id` (i32) в func-def blob (bcrec.h `FuncDefBuilder::Build` + `parse_func_def_blob` bctrace.rs:244-293) и/или в per-function report bctrace.rs:568-582 |
| `function_name` | **ЧАСТИЧНО**: в sem-строке имени нет; имя функции есть в per-function отчёте и в func-def blob | sem-строка: bctrace.rs:715-749 — поля `ts, off, op[, args][, acc][, res][, regs]`, имени нет; имя: `def.name` из blob (bctrace.rs:263, 289) и report `"name": def.name` (bctrace.rs:570), файл `filtered/bctrace/<func_id:08x>.json` (bctrace.rs:583-588) | либо добавлять `"fn": def.name` в sem-строку (bctrace.rs:715-719, `def` уже доступен как `funcs.get(&r.func_id)` — bctrace.rs:629), либо считать имя доступным через join по `func_id` (дешевле, но требует чтения отчёта) |
| `bytecode_op` | **ДА** — `"op": m.name`, имя опкода берётся из meta-записи движка | sem: bctrace.rs:718; meta: `parse_meta` bctrace.rs:172-239 (`OpMeta.name`, bctrace.rs:45); источник meta: 0033 патч:594-645 (`Bytecodes::ToString(bc)`) | — |
| `target_property` | **ЧАСТИЧНО** — отдельного поля нет; есть массив `args` с cp-разрешёнными значениями и агрегированные ключи `prop <name>` / `global <name>` / `call <name>` / `runtime <name>` | `args`: bctrace.rs:631-665 (cp-разрешение для `GetNamedProperty/SetNamedProperty/DefineNamedOwnProperty/AddNamedProperty/LdaConstant/LdaGlobal/...` при `idx == 0` — bctrace.rs:637-653), запись `"args"` bctrace.rs:720-722; ключи: bctrace.rs:676-700; сводка `api_calls` (what/times/values) bctrace.rs:701-709, 752-772 → `filtered/bctrace.json` | для точного соответствия вынести разрешённое имя в отдельное поле `"target"` в sem-строке (данные уже вычислены в `key`, bctrace.rs:676-700) |
| `arguments_hash` | **НЕТ** — хэша аргументов нет; вместо него полные значения операндов и регистров (строки/f64/Smi целиком) | значения операндов: 0033 патч:811-869 (`ib.Operand(i, value)`, `ib.Reg/RegStr/RegStr16/RegF64/RegSmi`), блоки `kTagOperand=7` bcrec.h патч:75-77; Rust: `Pv::Operand(u8,i64)` bctrace.rs:82, парсинг bctrace.rs:159-161, sem-вывод через `args` bctrace.rs:633-664; регистры: bctrace.rs:730-748 (`regs`) | хэш не нужен, если требовалась компактность: фактически передаётся больше данных, чем хэш. Если эталон требует именно хэш (для сопоставления вызовов без раскрытия значений) — добавить `blake3/FNV` от сериализованных `args` в sem-строку (bctrace.rs:715-722) |

Дополнительно, чего эталон не требует, но что реально есть в sem-строке: `"acc"` — значение аккумулятора ДО инструкции (bctrace.rs:611-622, 667, 723-725); `"res"` — значение результата для опкодов, пишущих аккумулятор, вычисляется как `acc` СЛЕДУЮЩЕЙ записи того же `(pid, iso)` (bctrace.rs:592-605, 668-674, 726-728); `"regs"` — массив `{reg, word|v}` (bctrace.rs:729-748). Формат итоговой сводки — `filtered/bctrace.json` с полями `records, instructions, funcs, dead_blocks, live_blocks, dead_bytes, live_bytes, funcs_reported, api_calls, rule, functions` (bctrace.rs:763-781), плюс per-function отчёты с `dead_ranges` (bctrace.rs:568-588).

Расхождение формата в целом: эталон требует «структурированный лог (JSONL/protobuf) по операции». Реально — двухступенчато: бинарный wire-формат (72-байтный Hdr + тегированные блоки) на стороне движка, JSONL только после офлайн-обработки `src/bctrace.rs` (`sem/*.jsonl`, `bctrace.json`). Т.е. JSONL **есть**, но не на выходе патча, а на выходе Rust-декодера. Соответствует по конечному результату, **не соответствует** по месту формирования.
