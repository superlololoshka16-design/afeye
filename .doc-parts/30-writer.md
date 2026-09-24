# Подсистема записи: события, арена строк, писатель, zip-упаковка

## src/events.rs — общий тип события FxEvent, константы kinds/расширений и zero-alloc JSON-билдер

### const K_REQ..K_META (строки 3-19)
- назначение: числовые коды типов событий (u16), которые кладутся в `FxEvent.kind` и пишутся в JSON как `"k"`.
- что внутри: `K_REQ=1` (net.request), `K_RESP=2` (net.response), `K_BODY=3` (net.body), `K_FAIL=4` (net.fail), `K_HDR=5` (net.headers), `K_WS=6` (net.ws), `K_SCRIPT=7` (js.script), `K_SRC=8` (js.source), `K_BATCH=9` (js.batch), `K_INPUT=10`, `K_CONSOLE=11`, `K_EXC=12` (exception), `K_CTX=13` (execcontext), `K_NAV=14` (navigation), `K_LIFE=15` (lifecycle), `K_FILE=16`, `K_META=17`.
- связи: используются продюсерами событий (`capture.rs`, `human.rs`, `main.rs`, `relay.rs`, `tg.rs`) и потребителем `writer.rs::handle` (специальные ветки для K_FILE/K_META/K_BATCH, строки 365/377/393).

### const KIND_NAMES (строки 21-39)
- назначение: таблица соответствия «человеческое имя → код» для 17 видов.
- что внутри: `[(&str, u16); 17]`: `net.request`, `net.response`, `net.body`, `net.fail`, `net.headers`, `net.ws`, `js.script`, `js.source`, `js.batch`, `input`, `console`, `exception`, `execcontext`, `navigation`, `lifecycle`, `file`, `meta`.
- связи: `writer.rs::write_lexicon` (строки 524-532) выписывает её в `lexicon.json` секцию `"kinds"` как `{код:"имя"}`.

### const E_JS..E_POST и EXT (строки 41-52)
- назначение: коды типов контента артефактов (`Art.code`) и имена файловых расширений.
- что внутри: `E_JS=0, E_WASM=1, E_JSON=2, E_HTML=3, E_CSS=4, E_TXT=5, E_BIN=6, E_POST=8` (обратите внимание: код 7 пропущен в константах, но `EXT[7]="png"`). `EXT: [&str;9] = ["js","wasm","json","html","css","txt","bin","png","post"]`.
- связи: `ExtCode for u8` (строки 142-146) маппит код в расширение с clamp `min(EXT.len()-1)` (любой код ≥9 даст "post"); `writer.rs::run` строка 470 формирует имя артефакта `format!("{}.{}", hexs(&a.hash), a.code.ext())`.

### struct FxEvent (строки 54-65)
- назначение: единичное событие телеметрии, летящее по crossbeam-каналу от capture/human к writer.
- что внутри: `#[repr(C, align(64))]` — выравнивание под кэш-линию. Поля:
  - `t: u64` — таймстамп в миллисекундах (ставит продюсер через `now_ms()`);
  - `site: u32` — interned id домена цели (0 в meta-событиях);
  - `tun: u32` — interned id туннеля/таргета;
  - `tab: u32` — id вкладки браузера;
  - `vendor: u32` — interned id вендора антифрода (0 = нет вендора);
  - `name: u32` — interned id имени (используется только для K_FILE как относительный путь внутри stage);
  - `kind: u16` — код вида (K_*);
  - `_pad: u16` — выравнивание;
  - `d: Bytes` — payload, уже сериализованный в JSON (для K_FILE — сырое содержимое файла).
- связи: создаётся в `capture.rs::emit/emit_v/emit_file` (строки 38-75), `human.rs` (строка 119), `main.rs::meta_ev` (108), `relay.rs::meta_ev` (32), `tg.rs::meta_ev` (30); потребляется `writer.rs::run` → `Wc::handle`.

### struct Art (строки 67-71)
- назначение: артефакт контента (скрипт/wasm/JSON-ответ/POST-тело), летит по отдельному каналу.
- что внутри: `code: u8` (тип, см. E_*), `hash: [u8;32]` (SHA-256 содержимого), `data: Bytes` (байты).
- связи: шлется из `capture.rs` (строки 139-143, хэш считается там: `sha256(data)` → `ctx.art.send`); `writer.rs::run` дедуплицирует по хэшу через `HashSet<[u8;32]> seen` и пишет файл `artifacts/<hex64>.<ext>`.

### struct J и impl J (строки 73-136)
- назначение: минималистичный потоковый JSON-билдер поверх `BytesMut` без serde — продюсеры собирают payload `d` им.
- что внутри: поле `b: BytesMut`. Методы:
  - `new(cap)` — аллокация с ёмкостью;
  - `open()` — пишет `{`;
  - `fkey(k)` — пишет `"k":` (первый ключ, без запятой);
  - `key(k)` — пишет `,"k":` (последующие ключи);
  - `u64v/i64v` — числа через `itoa::Buffer`;
  - `f64v` — через `ryu::Buffer`, неконечные (NaN/Inf) → литерал `null` (строки 110-115);
  - `bool` — `true`/`false`;
  - `s(v)` — строка с JSON-экранированием через `esc`;
  - `hex(h)` — `"<64 hex символа>"` через `hex32`;
  - `fin()` — пишет `}` и `freeze()` → `Bytes` (zero-copy отдача payload).
- связи: используется продюсерами событий для сборки `FxEvent.d`; сам writer его не вызывает (payload приходит уже готовым JSON).

### trait ExtCode + impl for u8 (строки 138-146)
- назначение: код контента → расширение файла.
- что внутри: `ext(&self) -> &'static str` = `EXT[(*self as usize).min(8)]`.
- связи: `writer.rs::run` строка 470.

### fn esc_json (строки 148-152)
- назначение: экранированная JSON-строка прямо в `impl Write`.
- что внутри: аллоцирует временный `BytesMut(len+2)`, зовёт `esc`, `write_all`.
- связи: `writer.rs::write_lexicon` и `write_digest` (имена видов, строки, ключи дайджеста, endpoint'ы).

### fn esc (строки 154-179)
- назначение: быстрое JSON-экранирование строки в `BytesMut` (с кавычками).
- что внутри: быстрый путь — если в строке нет байтов `<0x20`, `"` и `\`, копирует слайс целиком (строки 157-161). Медленный путь: `"` → `\"`, `\` → `\\`, `\n`/`\r`/`\t` → короткие эскейпы, остальные управляющие `0x00..=0x1f` → `\u00XX` через таблицу `H=b"0123456789abcdef"`. UTF-8 выше 0x7f не трогается (проходит как есть).
- связи: `J::s`, `esc_json`, тест `esc_roundtrip`.

### fn hex32 (строки 181-187)
- назначение: 32 байта → 64 hex-символа в `BytesMut` без аллокаций.
- связи: `J::hex`; в writer есть отдельный аналог `hexs` (возвращает `String`).

### mod tests (строки 189-228)
- `esc_roundtrip` — 6 кейсов (кавычки, бэкслэш, `\n`, управляющие `\u{1}\u{1f}`, кириллица+✓): `esc` → `serde_json::from_str` возвращает исходную строку.
- `j_line_valid` — собирает объект `{"a":42,"b":-1.5e10,"c":"x\"y"}` через J, парсит serde_json, проверяет значения.
- `ext_map` — `E_JS→"js"`, `E_WASM→"wasm"`, `9u8→"post"` (clamp).

### Каналы (crossbeam)
- В самих файлах writer/events каналов не создают. Создание — в `main.rs` строки 187-188: `crossbeam_channel::unbounded::<FxEvent>()` и `unbounded::<events::Art>()` — ОБА unbounded. `tx`/`art` кладутся в `Ctx` (ctx.rs строки 194-195), приемники передаются в `writer::spawn(rx, arx, ctx)` (main.rs строка 276).
- Поток событий: продюсеры (`capture.rs` — сетевые/JS-события и артефакты, `human.rs` — ввод, `main.rs`/`relay.rs`/`tg.rs` — meta) → `ctx.tx.send(FxEvent)` / `ctx.art.send(Art)` → писатель-поток `afeye-writer` → файлы в stage-директории.
- Завершение: main.rs строки 596-598 — `ctx.cn.dead.store(true, Release)`, `drop(tx)`, `drop(atx)`, затем `writer.join()` (599).

## Взаимодействия (events.rs)
- Определяет общий контракт «продюсер → писатель»: `FxEvent`/`Art` — типы обоих crossbeam-каналов.
- Продюсеры: `capture.rs` (emit/emit_v/emit_file/артефакты), `human.rs`, `main.rs::meta_ev`, `relay.rs::meta_ev`, `tg.rs::meta_ev`.
- Потребитель: `writer.rs` — читает `kind`, `t`, `site`, `tun`, `tab`, `vendor`, `name`, `d`; использует `KIND_NAMES` для лексикона, `ExtCode` для имён артефактов, `esc_json` для лексикона/дайджеста.

## src/arena.rs — интернер строк на mmap-арене (id u32 ↔ &'static str), FxHash

### const SLAB, ENTS (строки 5-6)
- `SLAB = 48 << 20` = 48 МиБ — байтовый сляб под строки; `ENTS = 1 << 21` = 2 097 152 — максимум записей-энтри.

### struct Ent (строки 8-12)
- назначение: дескриптор интернированной строки.
- что внутри: `#[repr(C)]`, поля `off: u32` (смещение в слябе), `len: u32` (длина в байтах). Отсюда ограничение: строка ≤ 0xffff байт (проверка в `intern`, строка 112), хотя len — u32.

### struct FxHasher + impl Hasher (строки 14-28), type FxBuild (строка 30), fn fx64 (строки 32-36)
- назначение: простой быстрый FxHash (rustc-стиль).
- что внутри: `write` — побайтово `h = (h.rotate_left(5) ^ c) * 0x517c_c1b7_2722_0a95` (строка 22); `finish` возвращает `h`. `FxBuild = BuildHasherDefault<FxHasher>` для DashMap. `fx64(b)` — хэш байтового слайса одной функцией.
- связи: `Interner.intern` (ключ индекса), тест `fx_stable`.

### struct Interner (строки 38-47)
- назначение: конкурентный интернер строк: строка → `u32` id, обратно → `&'static str`. Это НЕ bumpalo — своя mmap-арена; bumpalo используется в writer.rs для токенов сканера.
- что внутри:
  - `slab: *mut u8` — 48 МиБ анонимной памяти под байты строк;
  - `ents: *mut Ent` — массив энтри (ENTS × 8 байт = 16 МиБ);
  - `slab_cur: AtomicU64` — курсор сляба, стартует с 1 (offset 0 не используется);
  - `ent_cur: AtomicU32` — счётчик энтри, стартует с 1 → **id 0 = пустая строка** (resolve(0) = "", intern("") = 0);
  - `idx: DashMap<u64, Vec<u32>, FxBuild>` — хэш → список id (коллизии хэша и гонка дублей);
  - `unsafe impl Send/Sync` (строки 46-47) — обосновано тем, что память арены никогда не освобождается (нет Drop), указатели стабильны, мутации через атомики + DashMap.
- связи: живёт в `Ctx.interner` (ctx.rs строка 196); зовут `capture.rs` (интернирование доменов/туннелей/вендоров/имён файлов), `writer.rs` (resolve для путей, intern ключей батчей/endpoint'ов/вендоров, `all()` для лексикона).

### fn mmap_anon (unix: строки 49-74; windows: 76-82)
- назначение: аллокация анонимной памяти.
- что внутри (unix): `libc::mmap(NULL, len, RW, MAP_PRIVATE|MAP_ANONYMOUS [| MAP_HUGETLB], -1, 0)`; при провале с `huge=true` — рекурсивный повтор без hugepages; иначе `MAP_FAILED` → `null_mut()`.
- что внутри (windows): hugepages игнорируются; аллоцирует `Vec<u8>` ёмкостью len, `resize(len,0)`, `Box::into_raw(into_boxed_slice)` — память навсегда утекает намеренно (нет Drop).
- связи: `Interner::new`.

### impl Interner (строки 85-158)
#### fn new (86-97)
- mmap сляба (с попыткой hugepages) и массива энтри; `assert!` что оба не null ("arena mmap"); курсоры = 1.
#### fn intern(&self, s: &str) -> u32 (99-141)
- назначение: вернуть стабильный id строки, дедуплицируя.
- шаги:
  1. пустая строка → 0 (строки 100-102);
  2. `h = fx64(bytes)`; быстрый путь: `idx.get(&h)` → пробежать Vec, сравнить `resolve(id) == s` → вернуть id (103-110);
  3. проверка вместимости `cap` (112-114): `len ≤ 0xffff` И `ent_cur < ENTS` И `slab_cur + len < SLAB`;
  4. если не влезает → деградация: вернуть первый существующий id с тем же хэшем, иначе 0 (115-121). **Тихо теряет строку — id 0 = ""**, это потенциальный источник «пропажи» строк при переполнении;
  5. `off = slab_cur.fetch_add(len+1, AcqRel)` — bump-выделение (+1 байт запаса), `copy_nonoverlapping` байтов в сляб (122-125);
  6. `id = ent_cur.fetch_add(1, AcqRel)`, запись `Ent{off,len}` по `ents.add(id)` (126-132);
  7. под локом DashMap-энтри по хэшу: ещё раз пробежать существующие id, если нашелся дубль строки — вернуть его (свой id при этом «сгорает»: энтри записана, но в индекс не попала; resolve по ней всё равно работал бы) (133-138);
  8. иначе `push(id)` в вектор и вернуть id (139-140).
- Гонка: два потока могут одновременно записать одну строку разными id — шаг 7 уменьшает, но не исключает дубли полностью для разных хэш-бакетов? Нет — бакет один на хэш, и проверка под `entry()` локом делает дубли маловероятными; однако строка, добавленная в сляб/энтри до push, уже видна через `all()`/`resolve`.
#### fn resolve(&self, id: u32) -> &'static str (143-152)
- id 0 → ""; иначе читает `Ent`, `slice::from_raw_parts(slab+off, len)`, валидация `simdutf8::basic::from_utf8`, при провале — `""`. Возврат `&'static str` — намеренная ложь компилятору: арена не освобождается, поэтому время жизни фактически бессрочное.
#### fn all(&self) -> Vec<(u32, &'static str)> (154-157)
- снимок всех id `1..ent_cur` с resolve. Используется writer'ом при финализации для `lexicon.json`.

### mod tests (строки 160-208)
- `intern_dedup` — одна строка дважды → один id; другая строка → другой id; resolve верен; "" → 0.
- `intern_bytes` — интернирование строки в стиле HTTP request-line, `all()` содержит id.
- `intern_threads` — 4 потока × 200 итераций интернируют общий "parallel-key" и уникальные; все потоки получили одинаковый id общего ключа.
- `fx_stable` — детерминированность и чувствительность fx64.

### Zero-copy парсинг (уточнение)
- Сам arena.rs не парсит JSON. Zero-copy цепочка такая: продюсер собирает payload в `BytesMut` (J) → `Bytes` (refcounted, без копирования) в `FxEvent.d` → writer парсит payload сканером токенов (tok-слайсы — это индексы `a..b` в исходный буфер, значение копируется в выходную строку как срез, без декодирования) → интернер хранит строки один раз в слябе, по событиям летают только u32 id. Копии байт происходят только при записи строк в сляб и в файлы.

## Взаимодействия (arena.rs)
- `Ctx.intnerer` (ctx.rs:196) — единственная точка владения; `Arc<Ctx>` шарится между всеми потоками.
- Пишут (intern): `capture.rs` (site/tun/vendor/name/пути), `writer.rs::batch` (ключи `_c/_m/_mm`-пар, endpoint'ы, вендоры URL).
- Читают (resolve): `writer.rs::ensure_tun/ensure_vd` (имена сайтов/туннелей/вендоров для путей), `write_digest` (ключи дайджеста, endpoint'ы), `write_lexicon` через `all()`.
- `FxBuild`/`fx64` используются только внутри интернера.

## src/writer.rs — поток-писатель: таймлайны JSONL, артефакты, лексикон и дайджест

### struct Sink (строки 14-39)
- назначение: append-файл с буферизацией и счётчиком строк.
- что внутри: `w: BufWriter<File>` ёмкостью `1<<17` (128 КиБ), `n: u64` — число записанных строк.
  - `open(p)` (20-29): `create_dir_all(parent)`, `OpenOptions::create(true).append(true)` — файл дописывается, не перетирается (важно при рестарте в тот же slot);
  - `line(b)` (31-38): пишет байты + `\n`, `n += 1`, **flush каждые 256 строк** (`n.is_multiple_of(256)`). Ошибки записи глушатся (`let _ =`).
- связи: два пула в `Wc` — таймлайны туннелей и таймлайны вендоров.

### struct Agg (строки 41-45) и enum Pm (47-52)
- `Agg { n: f64, ms: f64, mx: f64 }` — агрегат по интернированному ключу: счётчик, сумма миллисекунд, максимум.
- `Pm { Cnt, Sum, Max }` — режим агрегации (Copy).

### struct Tok (строки 54-58)
- назначение: токен JSON — срез исходного буфера без копирования.
- что внутри: `tag: u8` (0=строка с кавычками, 1=число, 2=массив, 3=объект, 4=литерал/прочее), `a: usize`, `b: usize` — полуинтервальные индексы в payload.

### fn skip_ws (строки 60-65)
- пропускает пробел/таб/\n/\r; возвращает false на конце ввода.

### fn scan_val (строки 67-135)
- назначение: отсканировать одно JSON-значение из позиции, вернуть `Tok` (срез).
- ветки:
  - `"` — строка: скан до незакрытой кавычки, `\\` пропускает 2 байта (эскейпы); tag 0; незакрытая → None (70-84);
  - `-`/цифра — число: жрёт `[-+.eE0-9]*`; tag 1 (85-90);
  - `[`/`{` — контейнер: счётчик глубины `d`, строки внутри пропускаются (с эскейпами), чтобы `[]{}` внутри строк не считались; закрытие при `d==0` → tag 2/3; незакрытый → None (91-124);
  - иначе — литерал (true/false/null/мусор): скан до `,`/`]`/`}`; пустой → None; tag 4 (125-133).
- Значения НЕ валидируются как JSON (число может быть мусором типа `1e`), контент строк не деэкранируется.

### fn scan_arr (строки 137-170)
- назначение: распарсить верхнеуровневый JSON-массив в `BVec<'a, Tok>` (вектор в bumpalo-арене — zero-copy, только индексы).
- что внутри: требует `[` первым непробельным; цикл: `]` → конец, иначе `scan_val`, затем `,` (с проверкой висячей запятой — `[a,]` → None, строки 160-162) или `]`. Любая ошибка → None целиком.

### fn unq (строки 172-177)
- снять обрамляющие кавычки со строкового токена: `s[1..len-1]` как `&str` через `simdutf8::basic::from_utf8`, провал → "". **Эскейпы не декодируются** (ключ `"a\"b"` останется с бэкслэшем).

### struct Wc<'a> (строки 179-186)
- назначение: состояние писателя (writer context).
- что внутри:
  - `ctx: &'a Arc<Ctx>` — общий контекст (stage, slot, interner, cn, endpoints);
  - `tl: Vec<Sink>` + `tix: HashMap<(u32,u32), usize>` — пул таймлайнов туннелей, ключ `(tun, site)` → индекс;
  - `vd: Vec<Sink>` + `vix: HashMap<(u32,u32), usize>` — пул таймлайнов вендоров, ключ `(site, vendor)`;
  - `dig: HashMap<u32, Agg>` — агрегаты батч-метрик по interned id ключа.

### impl Wc (строки 188-432)
#### fn ensure_tun (189-214)
- лениво открывает таймлайн туннеля. Путь: `<stage>/sites/<site>/tunnels/<tunnel>/<slot>/timeline.jsonl` (site/tunnel — resolve interned id; slot — `ctx.slot`, формат из main.rs:223 `timefmt::slot(t0ms, 30)`). Кэш в `tix`. Ошибка открытия → None (событие молча не пишется в туннельный таймлайн).
#### fn ensure_vd (216-240)
- то же для вендора: `<stage>/sites/<site>/antifraud/<vendor>/timeline.jsonl` — **без slot-поддиректории** (один файл на сайт+вендор на весь stage).
#### fn dig_add (242-253)
- `dig.entry(id).or_insert(Agg{0,0,0})`; по `Pm`: Cnt → `n += cv`, Sum → `ms += cv`, Max → `mx = max(mx, cv)`.
#### fn flat_pairs (255-270)
- назначение: разбор «плоского» массива `[key1, num1, key2, num2, ...]` из значения батч-ключа.
- что внутри: `scan_arr(vb)` → `chunks(2)`; пара должна быть (строка tag 0, число tag 1); ключ `unq` → `intern` → `dig_add(cid, pm, cv)`; число парсится `parse::<f64>()`, мусор → 0.0.
- связи: вызывается из `batch` для ключей `_c` (Cnt), `_m` (Sum), `_mm` (Max).
#### fn batch (272-362)
- назначение: разбор payload K_BATCH (плоский JSON-массив триплетов `[key, value, ts, key, value, ts, ...]` из JS-инжекта) и запись компактных строк в таймлайны + агрегация.
- шаги:
  1. `std::str::from_utf8(&ev.d)` — невалидный UTF-8 → `Cn::inc(&ctx.cn.drop)` и выход (274-280);
  2. `scan_arr` payload — провал → `cn.drop++`, выход (281-287);
  3. `tix = ensure_tun(ev)` — один раз на батч (288);
  4. цикл `toks.chunks(3)`: триплет должен быть (строка, любое значение, число); `k = unq(tri[0])`, пустой ключ → skip; `vb` — сырой срез значения; невалидный UTF-8 → `cn.drop++`; `t = parse::<f64>(tri[2])`, ошибка → skip (289-305);
  5. `kid = intern(k)`; `dig_add(kid, Cnt, 1.0)` — счётчик по каждому ключу (306-307);
  6. спец-ключи (308-331):
     - `"_c"` → `flat_pairs(vb, Cnt)` — счётчики по вложенным парам;
     - `"_m"` → `flat_pairs(vb, Sum)` — суммы мс;
     - `"_mm"` → `flat_pairs(vb, Max)` — максимумы;
     - `"net:send"` → `scan_arr(vb)`, первый элемент-строка = URL: `endpoint_of(url)` (ctx.rs) → intern → `*ctx.endpoints.entry(eid).or_insert(0) += 1`; `vendor_of_url(url)` (ctx.rs) → intern → локальный `vendor`;
  7. сборка строки (332-345), формат JSONL (компактный, ключи как сырые JSON-токены):
     `{"t":<ev.t ms>,"b":<ev.tab>,"j":<t f64 ryu>,"kk":<сырой токен ключа с кавычками>,"v":<сырой срез значения>}`
     где `"kk"` копирует байты `tri[0].a..b` (включая кавычки), `"v"` — сырой JSON-срез значения (массив/объект/строка/число как есть);
  8. запись строки в туннельный sink (346-350) и, если `vendor != 0`, в вендорный sink (351-358);
  9. `drop(toks); bump.reset()` — арена токенов сбрасывается после каждого батча (360-361).
#### fn handle (364-431)
- назначение: диспетчер одного FxEvent.
- ветки:
  - **K_FILE** (365-376): `name = interner.resolve(ev.name)` (пустой → return); путь `<stage>/<name>`; `create_dir_all(parent)`; `fs::write(p, &ev.d)` — payload пишется как есть (это содержимое файла, не JSON). Возврат.
  - **K_META** (377-392): собирает `{"t":<ev.t>,"d":<ev.d сырой JSON>}` в BytesMut, append в `<stage>/meta.jsonl` (открывает/пишет/закрывает файл на каждое событие — без Sink-буферизации). Возврат.
  - **K_BATCH** (393-396): → `batch`. Возврат.
  - **остальные kinds** (397-431): полная строка JSONL:
    `{"t":<ms>,"u":<tun id>,"s":<site id>,"b":<tab>[,"v":<vendor id> если !=0],"k":<kind>,"d":<payload сырой JSON>}`
    Пишется в туннельный таймлайн (ensure_tun) и, при `vendor != 0`, в вендорный. `bump.reset()` в конце.
- Важно: `u`/`s`/`v` — это **числовые interned id**, расшифровка только в `lexicon.json`.

### fn spawn (строки 434-439)
- назначение: поднять поток-писатель.
- что внутри: `std::thread::Builder::name("afeye-writer").spawn(move || run(rx, art, ctx))`, `.expect("writer thread")`. Возвращает `JoinHandle<()>`.
- связи: вызывается один раз из main.rs:276; join — main.rs:599.

### fn run (строки 441-507)
- назначение: главный цикл писателя.
- шаги:
  1. **пинning на последнее ядро**: `core_affinity::get_core_ids()` → `set_for_current(cores.last())` (442-446) — писатель изолируется от остальных потоков на последнем CPU;
  2. `Bump::with_capacity(1<<21)` — 2 МиБ арена bumpalo под токены/строки (447);
  3. инициализация `Wc` (448-455);
  4. `seen: HashSet<[u8;32]>` — дедуп артефактов по SHA-256 (456);
  5. `art_root = <stage>/artifacts`, `create_dir_all` (457-458); счётчики `art_n` (файлы), `art_b` (байты);
  6. цикл `crossbeam_channel::select!` (461-495):
     - `recv(rx)` — событие → `wc.handle(ev, &mut bump)`; ошибка канала (все Sender дропнуты) → break;
     - `recv(art)` — артефакт: если `seen.insert(hash)` (новый) → имя `<hexs(hash)>.<ext>`, `fs::write(art_root/name, data)`; успех → `art_n += 1; art_b += len`; провал записи → `seen.remove` (даёт повторную попытку); ошибка канала → break только если `ctx.cn.dead.load(Acquire)` (468-485);
     - `default(250ms)` — таймаут: если `dead` → пробуем дренаж `rx.try_recv()/art.try_recv()` (есть данные → continue), иначе break (486-493). То есть выход по флагу смерти с обязательным опустошением очередей;
  7. финализация (496-506): flush всех таймлайновых sink'ов; `ctx.cn.art.store(art_n, Release)`, `ctx.cn.bout.store(art_b, Release)` — атомики счётчиков для итогового отчёта main.rs; `write_lexicon(<stage>/lexicon.json, interner)`; `write_digest(ctx, dig)`; `eprintln!("[afeye] writer flushed")`.

### fn hexs (строки 509-516)
- SHA-256 `[u8;32]` → 64-символьная hex-`String` через `char::from_digit`. (Дублирует `events::hex32`, но с аллокацией.)

### fn write_lexicon (строки 518-545)
- назначение: словарь расшифровки числовых id для всех JSONL.
- формат `<stage>/lexicon.json` (одна строка, в конце `\n`):
```json
{"kinds":{<kind u16>:"<имя из KIND_NAMES>",...17 штук...},
 "strings":{<id u32>:"<интернированная строка>",...все id 1..ent_cur...}}
```
- строки экранируются `events::esc_json`. `create_dir_all(parent)`, `BufWriter(File::create)` — файл перетирается.

### fn write_digest (строки 547-618)
- назначение: итоговые агрегаты батч-метрик и топ endpoint'ов.
- формат `<stage>/digest.json` (одна строка + `\n`):
```json
{"counts":{"<ключ>":<n f64>,...},
 "ms":{"<ключ>":<сумма f64>,...},
 "max":{"<ключ>":<максимум f64>,...},
 "endpoints":[{"u":"<endpoint>","n":<count u64>},... до 64 ...]}
```
- детали: в каждый раздел попадают только ненулевые агрегаты (`n>0` / `ms>0` / `mx>0`, строки 553/569/585); ключи — resolve interned id, сортировка лексикографическая (556/572/588); числа через `ryu`. `endpoints` — из `ctx.endpoints` (DashMap<u32,u64>, наполняется в `batch` для `net:send`), сортировка по убыванию count, при равенстве по возрастанию id (604), берётся топ-64 (605).

### Атомики ctx.cn (ctx.rs:122-137), используемые writer'ом
- `cn.drop: AtomicU64` — инкрементируется в `batch` при невалидном UTF-8 payload, провале scan_arr, невалидном UTF-8 значения (строки 277/284/299).
- `cn.dead: AtomicBool` — флаг завершения, ставит main.rs:596 (`store(true, Release)`); writer читает `load(Acquire)` в ветках art-ошибки и default-таймаута (481/487).
- `cn.art: AtomicU64` — writer пишет число сохранённых артефактов при выходе (502).
- `cn.bout: AtomicU64` — writer пишет суммарный байтаж артефактов (503).
- (`cn.ev/req/resp/...` инкрементируются продюсерами, не writer'ом.)

### mod tests (строки 620-670)
- `scan_flat_batch` — плоский батч `["_boot",[...],3.25,"net:send",[...],100.1]`: 6 токенов, теги (0,2,1,...), `unq` ключей, сырой срез числа "3.25".
- `scan_nested_and_esc` — вложенный объект `{"x":[1,2,{"y":"\"z\""}]}` сканится как один tok tag 3; `scan_arr` на объекте (не массиве) → None; `[1,2,3]` → 3 токена.
- `scan_garbage_rejected` — "not json", "[1,2" (незакрытый), `["a",]` (висячая запятая) → None.
- `scan_empty_and_literals` — `[]` → 0 токенов; `[null,true,false,0.5]` → 4 токена, null имеет tag 4.

### Формат выходных файлов (сводка)
Дерево stage:
```
<stage>/
  sites/<site>/tunnels/<tunnel>/<slot>/timeline.jsonl   — события+батчи туннеля
  sites/<site>/antifraud/<vendor>/timeline.jsonl        — события+батчи вендора (без slot)
  meta.jsonl                                            — {"t":ms,"d":<json>}
  artifacts/<sha256hex64>.<ext>                         — дедуплицированные артефакты
  lexicon.json                                          — {"kinds":{...},"strings":{...}}
  <name из K_FILE>                                      — произвольные файлы по ev.name
  digest.json                                           — {"counts","ms","max","endpoints"}
```
Строки таймлайнов, два формата:
- полный (обычные события): `{"t":u64,"u":u32,"s":u32,"b":u32,"v":u32?,"k":u16,"d":<json>}`;
- компактный (K_BATCH-триплеты): `{"t":u64,"b":u32,"j":f64,"kk":<json-строка>,"v":<json-значение>}`.

## Взаимодействия (writer.rs)
- Вход: два unbounded crossbeam-канала из main.rs:187-188, старт main.rs:276, останов main.rs:596-599 (dead → drop senders → join).
- Зависит от: `arena::Interner` (intern/resolve/all), `ctx::{Ctx, Cn, endpoint_of, vendor_of_url}` (пути, slot, атомики, endpoints-мапа, классификация URL), `events::{FxEvent, Art, ExtCode, K_*, KIND_NAMES, esc_json}`, `bumpalo` (арена токенов), `crossbeam_channel::select!`, `core_affinity` (пиннинг), `itoa`/`ryu` (числа), `simdutf8` (валидация).
- Выход: файлы stage-дерева (см. выше) + финальные значения `cn.art`/`cn.bout`, которые main.rs читает для итогового отчёта/meta; сам stage затем пакуется `zipper::pack` (main.rs:659, 729; tg.rs:100).
- `ctx.endpoints` (DashMap) наполняется только здесь (batch → net:send) и читается только здесь же (write_digest).

## src/zipper.rs — упаковка stage-дерева в zip

### fn pack(stage, out) -> Result<u64, String> (строки 7-42)
- назначение: рекурсивно упаковать директорию stage в один zip.
- шаги:
  1. `stage.exists()` иначе Err("stage dir missing"); `create_dir_all(out.parent())` (8-13);
  2. `collect(stage, &mut files)` — обход дерева, затем `files.sort()` (полная лексикографическая сортировка путей → детерминированный порядок записей в zip) (14-16);
  3. `File::create(out)` — zip перетирается; `zip::ZipWriter::new` (17-18);
  4. опции записи (19-23): `CompressionMethod::Deflated`, `compression_level(Some(9))` — максимальный deflate, `unix_permissions(0o644)`, `large_file(true)` (zip64 для файлов >4GiB);
  5. для каждого пути: имя записи = относительный путь от stage, `\` → `/` (25-26); пустое имя → skip; директория → `add_directory(name, perms 0o755)` (31-34); файл → `start_file(name, opt)` + `io::copy` из файла в zip-поток (35-37) — потоково, без загрузки файла в память;
  6. `w.finish()` (центральная директория); возврат — **число файлов** (без директорий, `filter(is_file)`, строка 40).
- связи: вызывается из main.rs:659 (фильтрованный дамп `<stem>-filtered.zip`), main.rs:729 (финальный `<stage>.zip`; дальше main.rs:731-732 предупреждает если zip > 95 МиБ — «lower AF_BUDGET_MB») и tg.rs:100 (чекпойнт-апロード в Telegram-канале).
- Ошибки: все IO-ошибки мапятся в `Result<_, String>`.

### fn collect(dir, out) (строки 44-57)
- назначение: рекурсивный обход.
- что внутри: `read_dir` → пути, локальная сортировка; директория — push + рекурсия, файл — push. В out попадают и директории тоже (pack записывает их отдельными entry). Скрытые файлы не фильтруются (попадёт и `.git` и пр., если лежит в stage). Симлинки не обрабатываются specially (`is_dir/is_file` следуют за ними).

### mod tests (строки 59-88)
- `zip_roundtrip` — строит фейковый stage (`sites/example.com/tunnels/1.2.3.4_51820/09.15.2026_10.30-11.00/timeline.jsonl` + `artifacts/aabb.js`), пакует, проверяет: n == 2; запись `artifacts/aabb.js` существует, метод Deflated, содержимое `var x=1;` читается обратно. В tmp-директории `afeye-ziptest`.

### Wire-формат zip
- Записи: пути POSIX (`/`), deflate level 9, zip64 включён, unix perms 0644/0755, порядок — сортировка полных путей. Имя архива задаёт вызывающий (не zipper).

## Взаимодействия (zipper.rs)
- Использует только std + крейт `zip`. Не знает про Ctx/события — чистая утилита «директория → zip».
- Вызывающие: main.rs (дважды: filtered-дамп и финальная упаковка stage после `writer.join()`), tg.rs (чекпойнт).
- Содержимое zip — ровно то, что положили writer.rs и K_FILE-обработчик (таймлайны, артефакты, lexicon.json, digest.json, meta.jsonl).

## Общие дырки и наблюдения (не догадки — факты из кода)
- Переполнение интернера (48 МиБ сляб / 2M энтри / строки >64KiB) тихо возвращает id 0 или чужой id по коллизии хэша (arena.rs:115-121) — в lexicon/digest такие строки потеряются или склеятся.
- `unq` не деэкранирует строки: ключи батчей с эскейпами попадут в `dig`/`lexicon` в сыром виде (writer.rs:172-177).
- `scan_val` не валидирует числа/литералы — мусор типа `1e` станет токеном tag 1, а `parse::<f64>` в batch вернёт Err → триплет молча пропущен (без cn.drop).
- Вендорный таймлайн не имеет slot-поддиректории (writer.rs:223-230), в отличие от туннельного (196-204) — при нескольких запусках в один stage файлы будут дописываться вперемешку (Sink — append).
- K_META открывает/закрывает meta.jsonl на каждое событие (writer.rs:387) — медленно при частых мета-событиях, в отличие от Sink-пулов.
- `hexs` (writer) и `hex32` (events) — дублирующая логика.
- Все ошибки записи sink'ов глушатся `let _ =` — потери строк невидимы (кроме cn.drop для parse-ошибок батчей).

## АУДИТ СООТВЕТСТВИЯ ЭТАЛОНУ

Сравнение реального кода репо с эталонной архитектурой (4 пункта + формат лога). Только факты с номерами строк. Номера строк патчей — номера строк в файле `.patch`.

### 1. jitless / no-opt / no-sparkplug (src/browser.rs)

Полный список chrome-флагов: `chrome_flags()` browser.rs:58-102. Базовые (64-81): `--no-first-run`, `--no-default-browser-check`, `--disable-session-crashed-bubble`, `--hide-crash-restore-bubble`, `--disable-search-engine-choice-screen`, `--disable-features=IsolateOrigins,site-per-process,PrivacySandboxSettings4`, `--disable-site-isolation-trials`, `--enable-unsafe-swiftshader`, `--password-store=basic`, `--use-mock-keychain`, `--no-sandbox`, `--remote-debugging-address=<bind>`, `--remote-debugging-port=<port>`, `--user-data-dir=/tmp/afeye/p<i>|local`, `--window-size=1280,832`, `--window-position=<idx%4*320>,<idx/4*250>`. Условные: `--user-agent=<ua>` если ua непустой (82-84); `--headless --disable-gpu` если `AF_TEST_HEADLESS` выставлен (85-88) или бинарь headless_shell (89-92, детект `is_headless_shell` 104-109); `--jitless` если `AF_JITLESS=1` (93-99). Последний арг — `about:blank` (100).

- `--jitless`: ЕСТЬ, browser.rs:98. Env-гейт: `AF_JITLESS=1` (browser.rs:93), **по умолчанию ВЫКЛЮЧЕН** (opt-in). Комментарий 94-97 прямо связывает с 0033/0034.
- `--no-opt`: НЕТ nigде в browser.rs и вообще в src/ (grep по репо: единственное вхождение «jitless» — browser.rs:93-98 и SERIES.md:85).
- `--no-sparkplug`: НЕТ.
- НЕ ХВАТАЕТ (списком): `--no-opt`, `--no-sparkplug` не передаются никогда; `--jitless` не включён по умолчанию. Примечание: в реальном V8 `--jitless` сам запрещает Sparkplug/Maglev/TurboFan, поэтому функционально одного `--jitless` может быть достаточно — но по букве эталона двух флагов нет, и режим вообще opt-in.
- Env-гейты запуска браузера: `AFEYE_SINK` (default "1", browser.rs:129-130/165), `AFEYE_RAW_DIR`/`AF_RAW_DIR` (default `/tmp/afeye-raw`, browser.rs:126-128/163-164), `AF_JITLESS` (93), `AF_TEST_HEADLESS` (85), `AF_DEBUG_ARGS` (171). В netns-запуске env передаётся через `ip netns exec ... runuser ... env HOME=... USER=... DISPLAY=... AFEYE_SINK=... AFEYE_RAW_DIR=...` (browser.rs:119-133); `AF_JITLESS` читается родительским процессом и превращается в флаг, а не в env для chrome.

### 2. Патч диспетчера Ignition (patches/0033-v8-ignition-bytecode-trace.patch)

Где РЕАЛЬНО стоит хук:
- Файл `v8/src/interpreter/interpreter-assembler.cc`, НЕ `interpreter-generator.cc`. Две точки:
  1. конструктор `InterpreterAssembler::InterpreterAssembler` (патч 419-437, hunk `@@ -48,6 +48,18 @@`): `CallRuntime(Runtime::kAfeyeTraceBytecodeEntry, GetContext(), BytecodeArrayTaggedPointer(), SmiTag(BytecodeOffset()), GetAccumulatorUnchecked(), SmiTag(operand_scale_))`. Комментарий 424-429: вызов КОМПИЛИРУЕТСЯ в каждый байткод-хэндлер генератором (generator строит хэндлеры через InterpreterAssembler), operand_scale — codegen-константа на хэндлер, поэтому Wide/ExtraWide несут истинный масштаб.
  2. `InterpreterAssembler::InlineShortStar` (патч 438-454, hunk `@@ -1381,6 +1393,16 @@`): тот же CallRuntime с scale=kSingle — потому что Star0..Star4 инлайнятся в предыдущий хэндлер через StarDispatchLookahead и через конструктор не проходят.
- Регистрация рантайм-функции: `v8/src/runtime/runtime.h` (патч 901-929): `FOR_EACH_INTRINSIC_AFEYE` → `F(AfeyeTraceBytecodeEntry, 4, 1, kCannotTriggerGC)`, подключён в `FOR_EACH_INTRINSIC_TRACE`.
- Реализация: `v8/src/runtime/runtime-trace.cc`, `RUNTIME_FUNCTION(Runtime_AfeyeTraceBytecodeEntry)` (патч 750-894).

Совпадение с эталоном: НЕ соответствует по месту (этот патч — в interpreter-assembler.cc, эталон — GENERATE_BYTECODE_HANDLER в interpreter-generator.cc), но ЭКВИВАЛЕНТНО по покрытию: конструктор InterpreterAssembler — это ровно то место, из которого генератор собирает каждый хэндлер, плюс дополнительно покрыты инлайновые ShortStar (эталон этого не требует). Файл `interpreter.cc`/DispatchTable не тронут.

Что фиксируется реально (по пунктам эталона):
- BytecodeOffset: ЕСТЬ. SmiTag(BytecodeOffset()) аргументом (патч 431), в рантайме пересчёт `offset = bytecode_offset - kHeaderSize + kHeapObjectTag` (773), пишется в `Hdr.offset` (InstrBuilder::Begin, bcrec.h патч 149-161; вызов 807-809).
- Опкод: ЕСТЬ. Читается из байткода `op_byte = *pc` (786), `Bytecodes::FromByte` (787), в `Hdr.opcode` (bcrec.h патч 37-39). Префиксы Wide уже потреблены диспетчером, scale — codegen-константа (комментарий 782-785).
- Аргументы (операнды): ЕСТЬ, декодируются САМИМ ДВИЖКОМ (`BytecodeDecoder::DecodeRegisterOperand`/`DecodeSignedOperand`, патч 811-869). Для регистровых операндов дополнительно дампится содержимое регистра: сырое слово (kTagReg), полная строка 8-bit/UTF-16LE (kTagRegStr/kTagRegStr16), f64 (kTagRegF64), Smi (kTagRegSmi) — патч 837-856. Для остальных операндов — декодированное знаковое значение (kTagOperand, патч 860-868).
- Имя свойства из пула констант: ЕСТЬ, но НЕ в per-instruction записи. Пул констант целиком (строки 8/16-bit, f64, сырые слова) уходит в func-def блобе (AfeyeEmitFuncDef, патч 680-746; CpSpan/FuncDefBuilder, bcrec.h патч 239-287); резолвинг операнда-индекса в строку происходит OFFLINE в Rust: bctrace.rs:637-653 (список опкодов LdaConstant/GetNamedProperty/SetNamedProperty/CallProperty*/... → `cp_json(&d.cp, v)`), для CallRuntime — таблица runtime-имён из meta-блоба (bctrace.rs:654-660).
- Регистры источника/приёмника: ЕСТЬ (см. выше, патч 822-859) + первые 6 регистровых слов дублируются в шапке `Hdr.regs[6]` (bcrec.h патч 55, InstrBuilder::Reg 171-178). Аккумулятор: сырое слово в `Hdr.acc` (bcrec.h 53, патч 807-809) + полное значение String/f64/Smi пейлоад-блоками с флагом kFlagAccPayload (871-885, bcrec.h 205-223).
- SharedFunctionInfo: ЧАСТИЧНО. Живая ссылка НЕ сериализуется; вместо неё детерминированный `func_id = FNV-1a(script_id, function_literal_id, StartPosition, isolate_tag)` (bcrec.h MakeFuncId патч 117-133; вычисление в рантайме 789-798 через `JavaScriptStackFrameIterator → UnoptimizedJSFrame → fn->shared()`). GC-стабилен (комментарий 117-119). Func-def эмитится один раз на (func_id, bc_len) через thread_local `unordered_set` (патч 531-549, 800-803).
- Имя исходного скрипта: ЕСТЬ в func-def блобе — `Script::name()` полными байтами (патч 664-678), плюс стартовая строка функции `sc->GetLineNumber(sfi->StartPosition())` в `Hdr.line` func-def записи (667-672, 739). ВНИМАНИЕ: поле `line` в ИНСТРУКЦИОННЫХ записях переиспользовано под isolate-тег (bcrec.h патч 50-52; AfeyeIsoTag = `(isolate_ptr>>3) & 0xffffffff`, патч 526-529). Имя самой JS-функции (sfi->Name()) НЕ эмитится — только script name + literal id внутри хэша func_id.
- Дополнительно (эталон не требует): meta-блоб один раз на процесс — полная таблица опкодов (имена, число операндов, флаги jump/returns/calls/cond, размеры для 3 масштабов, типы и офсеты операндов) + имена всех Runtime-функций (AfeyeEmitMeta, патч 589-656; MetaBuilder, bcrec.h 289-330). Записи > 1МиБ-16 режутся на части kFlagCont с досборкой (EmitSplit, bcrec.h 332-360; склейка в bctrace.rs:433-512).
- Гейты: master `v8::afeye::Enabled()` (AFEYE_SINK) + `AFEYE_TRACE_BYTECODE=0` отключает только трейс (патч 750-756, 501-507).

Wire-формат 0033 (bcrec.h патч 33-89): kind=40 (kBytecodeTrace, sink.h патч 396); `Hdr` ровно 72 байта LE без паддинга: `opcode u8` (0xff=func-def, 0xfe=meta), `scale u8` (1/2/4), `n_payload u8` (saturates 255), `flags u8` (bit0 FuncDef, bit1 Cont, bit2 AccPayload), `offset u32`, `func_id u32`, `line u32` (инструкция: iso-тег; func-def: стартовая строка), `acc u64` (инструкция: тегированное слово; блоб: длина), `regs[6] u64`. Пейлоад: блоки `[u8 tag][u32 len][bytes]`, теги 0..13 (bcrec.h 67-83). Rust-декодер: bctrace.rs:21-36 (константы совпадают), InstrRec 85-96, parse_blocks 133-167.

### 3. Виртуализация таймингов (patches/0034-v8-blink-virtual-clock.patch)

Что сделано реально:
- Файлы патча 0034: `third_party/blink/renderer/core/timing/performance.cc` (строки патча 1-44) и `v8/src/objects/js-objects.cc` (45-85). **`src/base/platform/time.cc` НЕ тронут** (в патче только эти два файла).
- `Performance::now()` (патч 19-44, hunk `@@ -1373,6 +1380,25 @@`): при `blink::afeye::Enabled()` и `AFEYE_VIRTUAL_CLOCK` (static-лямбда getenv, непустой и != '0', патч 29-33) возвращает `g_afeye_origin_ms + afeye_vclock_ns()/1e6`, где origin — `base::TimeTicks::Now().since_origin()` один раз (35-37). Иначе — штатный `MonotonicTimeToDOMHighResTimeStamp` (43).
- `JSDate::CurrentTimeValue` (Date.now(), патч 60-82, hunk `@@ -5914,6 +5918,25 @@`): при `v8::afeye::Enabled()` и том же env — `g_afeye_epoch_ms + vclock_ns/1e6`, epoch — `CurrentClockTimeMilliseconds()` один раз (75-77).
- Счётчик: в 0033 патч sink.cc 375-383 — `std::atomic<uint64_t> g_vclock_ns`, `extern "C" afeye_vclock_ns()` (relaxed load), `VclockTick(ns)` (relaxed fetch_add). Объявления sink.h патч 404-410. Инкремент: в `Runtime_AfeyeTraceBytecodeEntry` на КАЖДУЮ трассируемую инструкцию — `if (AfeyeVclockOn()) VclockTick(AfeyeVclockNsPerInstr())` (0033 патч 768-770); шаг из `AFEYE_VCLOCK_NS_PER_INSTR`, дефолт 10 нс (патч 517-524).

Совпадение с эталоном:
- Формула `virtual_time += kBaseInstructionCost * instruction_count`: СООТВЕТСТВУЕТ по сути — тождественно сумме шагов: каждый тик добавляет константу (10 нс по умолчанию) на инструкцию, т.е. `vclock_ns = NS_PER_INSTR * instr_count`. Место инкремента — рантайм-функция трейса (0033 патч 768-770), не отдельный счётчик в движке.
- `Performance::now` в blink: СООТВЕТСТВУЕТ (патч 0034, performance.cc). `src/base/platform/time.cc`: НЕ тронут — эталон допускает «time.cc ИЛИ Performance::now», выполнена вторая ветка, но всё, что читает `base::TimeTicks::Now()` напрямую (setTimeout/setInterval, rAF, сетевые тайминги, performance.timeOrigin), остаётся на реальном времени.
- Расхождение с эталоном по охвату: виртуализированы только performance.now() и Date.now(). Хронология: SERIES.md:88-89 сам признаёт — vclock глобален на процесс, не на isolate (вкладки делят счётчик); Date.now() имеет миллисекундную гранулярность (~100k инструкций на тик при 10 нс).
- Гейты: `AFEYE_VIRTUAL_CLOCK` (вкл), шаг `AFEYE_VCLOCK_NS_PER_INSTR`; оба читаются ленивыми static-лямбдами (кэшируются на процесс). browser.rs эти env в chrome НЕ передаёт (в launch передаются только AFEYE_SINK и AFEYE_RAW_DIR, browser.rs:121-132/165-166) — включать нужно снаружи через окружение процесса chrome.

### 4. WebIDL/DOM-биндинги (patches/0008, 0024, 0019)

Что реально хукается:
- 0008: файл `third_party/blink/renderer/platform/bindings/idl_member_installer.cc` — НЕ `bindings/core/v8/` (этот каталог из патчей трогает только 0007 — `serialization/serialized_script_value.cc`, к геттерам/сеттерам отношения не имеет). Механизм: в `CreateFunctionTemplate`/`CreateFunction` (патч 83-150) колбэк IDL-члена подменяется на `AfeyeDomApiThunk`, а оригинал + идентичность кладутся в data-слот шаблона как `v8::External` на статическую таблицу `AfeyeApiCell g_afeye_api_cells[1<<16]` с линейным пробингом (патч 24-32, 52-77). Ячейка хранит `what[104]` = `"dom <Interface>.<get|set|call> <property_name>"` (патч 68-69; kind доступа из `ExceptionContext` — kAttributeGet/kAttributeSet/kOperation, патч 100-107). Тunk проброшен во ВСЕ точки установки: InstallAttribute (шаблонный и нетемплейтный варианты, патч 151-179) и InstallOperation (181-203) — т.е. покрыт каждый WebIDL-атрибут и каждая операция, устанавливаемые через idl_member_installer.
- Что эмитит 0008: `blink::afeye::EmitStr(kDomApi, NowNs(), cell->what)` — ТОЛЬКО идентичность (интерфейс.доступ свойство), БЕЗ аргументов и БЕЗ возвращаемого значения (патч 34-50). Лимит 8 000 000 записей на процесс (патч 41-42). Порядок: в 0008 emit ДО вызова оригинала (43-48).
- 0024 (тот же файл): добавляет `AfeyeCaptureValue` (патч 25-58) — рендер возвращаемого значения в буфер 160 байт ПО ТИПАМ: `undefined`/`null`/`0|1` (bool)/`%.17g` (number)/строка (обрезка по буферу, байты <0x20 и >=0x7f → '?')/`[array len=N]`/`[object]`. Thunk переписан: сначала вызывается оригинал, потом эмитится `"<what> val=<значение>"` (патч 60-92). Гейт: `AFEYE_TRACE_DOM_VALUES=0` отключает значения, оставляя формат 0008 (патч 20-23, 77-79).
- 0019: НЕ generic-биндинги, а ручные хуки в конкретных реализациях API, все эмитят `kFingerprint` через EmitStr:
  - `core/css/css_computed_style_declaration.cc` `GetPropertyCSSValue` → `"css/get-computed prop=<имя> val=<CssText>"`, лимит 2M (патч 32-49);
  - `core/css/font_face_set.cc` `check` → `"fonts/check font=<...> text=<...>"`, лимит 200k (82-99);
  - `core/css/media_query_list.cc` `matches` → `"media/matches q=<query> m=<0|1>"`, лимит 200k (131-146);
  - `core/frame/local_dom_window.cc` `matchMedia` → `"media/query q=<query>"`, лимит 200k (179-194);
  - `modules/canvas/canvas2d/base_rendering_context_2d.cc` `DrawTextInternal` → `"canvas/draw-text op=fill|stroke text=<64> font=<64> xy=<x>,<y>"`, лимит 2M (221-242);
  - `modules/notifications/notification.cc` `permission` → `"perm/notification value=denied|default|granted|prompt ctx=..."` в трёх ветках (261-306);
  - `modules/permissions/permissions.cc` `query` → `"perm/query name=<имя>"` (326-341).

Совпадение с эталоном:
- Место патча: НЕ соответствует (`platform/bindings/idl_member_installer.cc` вместо `bindings/core/v8/`). Функционально покрытие ШИРЕ эталонного: idl_member_installer — единая точка установки всех IDL-членов, включая window/navigator/document.
- Геттер/сеттер идентичность: СООТВЕТСТВУЕТ (0008 патч 68-69, 100-107 — «dom Interface.get/set/call prop»).
- Аргументы вызова: в generic-хуке (0008/0024) НЕТ — thunk логирует только `what` и return value; входные аргументы не читаются (патч 0024:60-92 — используется только `info.GetReturnValue()`). Аргументы есть только в ручных хуках 0019 (text/font/query/property name — конкретные параметры конкретных API). НЕ соответствует эталону для произвольного интерфейса.
- Тип возвращаемого значения: ЧАСТИЧНО — отдельного поля типа НЕТ; тип неявно кодируется форматом рендера значения в 0024 (undefined/null/0|1/число/строка/[array len=N]/[object], патч 25-58). Значение строкой — есть (лимит 160 байт, не-ASCII → '?').

### 5. Финальный формат лога (эталон vs sem/*.jsonl)

Что реально пишет 0033: бинарные записи kind 40 в sink (формат — раздел 2 выше), не JSONL. JSONL produces офлайн-декодер `src/bctrace.rs::run` (390-783): вход — `<collect>/index.jsonl` с записями `{"k":"bytecode-trace","p":<файл>,"ts":<u64>,"pid":<u64>,"o":<offset>,"len":<u64>}` (bctrace.rs:400-419); выход — `<collect>/filtered/bctrace/sem/<func_id:08x>.jsonl` (526-529, 711-713), пер-функция отчёты `<collect>/filtered/bctrace/<func_id:08x>.json` (568-588) и сводка `<collect>/filtered/bctrace.json` (763-781).

Строка sem/*.jsonl (bctrace.rs:715-749): `{"ts":u64,"off":u32,"op":"<имя опкода из meta>"[,"args":[...engine-decoded операнды, cp-резолвинг...][,"acc":<значение аккумулятора>][,"res":<acc СЛЕДУЮЩЕЙ записи того же (pid,iso) для write-acc опкодов>][,"regs":[{"reg":i,"v"|"word":...}]]}`. Сводка bctrace.json: `records/instructions/funcs/dead_blocks/live_blocks/dead_bytes/live_bytes/funcs_reported/api_calls[{what,times,values≤8}]/rule/functions[]` (763-775); api_calls-ключи — `"global X"/"prop X"/"call X"/"runtime X"` (676-700). Per-function отчёт: `func_id/name/line/frame_size/param_count/bc_len/instructions/blocks/executions/live_blocks/dead_blocks/dead_ranges/first_ts` (568-582).

Таблица соответствия:

| Поле эталона | Есть ли реально | Где именно (файл:строка) | Что делать если нет |
|---|---|---|---|
| `timestamp_virtual` | НЕТ (есть физический ts) | `"ts"` в sem-строке — bctrace.rs:716; источник ts — index.jsonl `"ts"` (bctrace.rs:413), который ставится на стороне sink от `NowNs()` = реальные монотонные нс (0033 патч 373, 584). Виртуальные часы (0034) видны только JS-странице, в трейс НЕ пишутся | Эмитировать `afeye_vclock_ns()` в Hdr/запись sink (0033 AfeyeEmit, патч 577-587) и пробросить в InstrRec/sem-строку |
| `script_id` | ЧАСТИЧНО (свёрнут в хэш) | script_id извлекается (0033 патч 795-796), но эмитится только внутри `MakeFuncId(script_id, literal_id, start_pos, iso_tag)` (bcrec.h патч 120-133); отдельного поля нет ни в Hdr, ни в sem-строке (bctrace.rs:715-718), ни в func-отчёте (568-582) | Добавить script_id в func-def блоб (AfeyeEmitFuncDef, патч 658-746) и в FuncDef/отчёт bctrace.rs |
| `function_name` | НЕТ | В func-def эмитится только имя СКРИПТА `Script::name()` (0033 патч 664-678); `FuncDef.name` (bctrace.rs:65, 570) = имя скрипта. `sfi->Name()`/FunctionLiteral name не эмитится нигде в 0033 | Эмитировать `sfi->Name()` вторым именем в func-def блоб (AfeyeEmitFuncDef) и вывести в отчёт/sem |
| `bytecode_op` | ЕСТЬ | Hdr.opcode (bcrec.h патч 37-39) → InstrRec.opcode (bctrace.rs:90) → `"op": m.name` по meta-таблице (bctrace.rs:718, 625-628) | — |
| `target_property` | ЕСТЬ (offline-резолвинг) | cp-строка операнда 0 для GetNamedProperty/CallProperty*/LdaGlobal и др. (bctrace.rs:637-663), в sem-строке как `"args"` (720-722); агрегированно — ключи `"prop X"/"call X"/"global X"` в api_calls (676-702, 752-761) | — |
| `arguments_hash` | НЕТ как хэш (есть полные значения — строго больше эталона) | engine-decoded операнды kTagOperand (0033 патч 860-868) → `"args"` (bctrace.rs:720-721); регистровые значения kTagReg* (0033 патч 822-856) → `"regs"` (bctrace.rs:730-748); аккумулятор → `"acc"`/`"res"` (611-622, 667-674, 723-728) | Ничего: хэш — деградация; если нужен для компактности — добавить поле hash от args в bctrace.rs при записи строки (715-749) |

Итог по пункту 5: из 6 эталонных полей в sem/*.jsonl полностью присутствуют 2 (`bytecode_op`, `target_property`), 1 присутствует в более сильной форме (`arguments_hash` → полные значения), 1 частично (`script_id` свёрнут в func_id), 2 отсутствуют (`timestamp_virtual` — ts физический; `function_name` — есть только имя скрипта).

### Сводка расхождений (что делать)
1. `--no-opt`/`--no-sparkplug` не передаются; `--jitless` opt-in (browser.rs:93-99) — добавить флаги в chrome_flags или задокументировать, что --jitless покрывает их.
2. Хук 0033 стоит в interpreter-assembler.cc (конструктор + InlineShortStar), а не в interpreter-generator.cc — расхождение по месту, не по покрытию; трогать не требуется, эталонное место не даёт большего охвата.
3. `src/base/platform/time.cc` не виртуализован (0034 трогает только Performance::now и Date.now) — таймеры/raff/timeOrigin на реальном времени; при необходимости патчить TimeTicks.
4. Generic DOM-хук (0008/0024) не логирует входные аргументы и тип возврата отдельным полем; место — platform/bindings, не bindings/core/v8.
5. В sem-лог не попадают: виртуальный таймстамп, отдельный script_id, имя JS-функции. Всё остальное эталонного формата есть или превосходит эталон.
