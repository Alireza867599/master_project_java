# نسخه Java 21 پروژه SFDAC — شامل هر شش نقش

این بسته شامل سورس Java برای هر شش نقش `Bidder`، `BidderBoss`، `P0`، `P1`، `P2` و `ProverParty` است. `P0.java` و `P1.java` از کلاس‌های مشترک `AuctioneerParty.java`، `AuctioneerIngress.java` و `AuctioneerMpc.java` استفاده می‌کنند؛ این تصمیم عمدی است تا پیاده‌سازی MPC دو طرف ناسازگار نشود.

> **حدود ادعای صحت:** همه سورس‌های حاضر با JDK 21 کامپایل می‌شوند و تست‌های مشخص‌شده پایین گذرانده شده‌اند، اما این بسته هنوز یک تبدیل *صددرصد معادل* همه شاخه‌های `p0.cpp` و `p1.cpp` نیست. به‌ویژه شاخه‌های تست تخریب عمدی (`--test-invalid-*`, `--force-false-*`)، برخی گزارش‌های اختلاف commitment/Merkle و جزئیات وابسته به زنجیره همچنان پیاده‌سازی/تست کامل ندارند. این بخش‌ها باید پیش از استفاده تولیدی تکمیل و با کد اصلی C++ و قراردادهای واقعی مقایسه شوند. ابزارهای JS، کلیدهای واقعی و قراردادها نیز همراه فایل‌های C++ ارسالی نبودند.

## فایل‌ها

| فایل C++ مبنا | فایل Java | کارکرد پیاده‌سازی‌شده |
| --- | --- | --- |
| `bidder.cpp` | `src/Bidder.java` | ساخت share، رمزنگاری، امضای Ed25519، ارسال مستقیم و دریافت رسید |
| `bidderboss.cpp` | `src/BidderBoss.java` | دریافت بسته‌ها، چهار درخت Merkle، relay، randomness reveal |
| `p0.cpp` | `src/P0.java` + کلاس‌های مشترک | دریافت مستقیم و Merkle، رمزگشایی، بررسی امضا و CCE، alignment، MPC shuffle/sort/clearing، hash و ارسال payload |
| `p1.cpp` | `src/P1.java` + کلاس‌های مشترک | همان پروتکل با نقش طرف ۱ و ترتیب معکوس ارسال/دریافت |
| `p2.cpp` | `src/P2.java` | توزیع ماتریس/ماسک، Beaver triples و مقایسه‌های MPC؛ با retry اتصال |
| `prover_party.cpp` | `src/ProverParty.java` | دریافت و رمزگشایی transport، ذخیره داده و ACK |

کلاس‌های کمکی: `Wire` (پروتکل TCP با unsigned u64 به صورت big-endian)، `SimpleJson`، `Secp256k1Ecies`، `AuctioneerMpc`، `AuctioneerIngress` و `AuctioneerParty`.

## نیازمندی‌ها

- Java Development Kit نسخه 21 یا بالاتر
- Node.js و فایل‌های JavaScript پروژه اصلی (از جمله `verify_sigma_cce_local.js`، اسکریپت‌های Poseidon، BabyJub، ثبت قرارداد، `prover_payload_tool_babyjub_split_v2.cjs` و ...)
- کلیدها، `pubkeys.json`، آدرس قراردادها و RPC بلاک‌چین
- Python 3 و بسته `cryptography` تنها برای تعدادی از تست‌های آزمایشی

**توجه امنیتی:** عملیات secp256k1 با `BigInteger` نوشته شده‌اند و ممیزی کانال جانبی/زمان ثابت نشده‌اند. برای تولید، از کتابخانه ممیزی‌شده استفاده کنید. ابزارهای Node آزمایشی، هیچ تضمینی درباره درستی امضاهای Ethereum، BabyJub یا اثبات Sigma-CCE ایجاد نمی‌کنند.

## ساخت و تست

```bash
./build.sh
./test.sh
```

دستور ساخت همچنین `sfdac-java.jar` را می‌سازد. آزمون‌ها:

- `SelfTest` و `IntegrationTest` (ریاضیات u64، رمزنگاری و ارتباطات پایه)
- `prover_reveal_smoke.py` و `full_protocol_smoke.py` (Java Bidder/BidderBoss/Prover با ابزار Node آزمایشی)
- `auctioneer_mpc_smoke.py` (تطابق P0/P1/P2 برای ۱، ۲، ۳ و ۴ پیشنهاددهنده در هر سمت، صحت ترتیب مرتب‌سازی و توافق تسویه)
- `six_party_smoke.py` (تبادل کامل پیام بین Bidder خریدار/فروشنده، BidderBoss، P0، P1 و P2، با تأیید واقعی Ed25519 و AES-GCM و Merkle و **تأیید شبیه‌سازی‌شده CCE و ریشه روی زنجیره**)

## اجرای شش نقش

از دایرکتوری **پروژه اصلی** که اسکریپت‌ها و کلیدها در آن قرار دارند اجرا کنید. می‌توانید JAR را با مسیر مطلق صدا بزنید:

```bash
# ترمینال ۱
java -cp /path/to/sfdac-java.jar P0 \
  --buyers --sellers --nbuyers 2 --nsellers 2 \
  --perm-session-id 0 --perm-registry 0xYOUR_REGISTRY --dispute-manager 0xYOUR_DISPUTE_MANAGER

# ترمینال ۲
java -cp /path/to/sfdac-java.jar P1 \
  --buyers --sellers --nbuyers 2 --nsellers 2 \
  --perm-session-id 0 --perm-registry 0xYOUR_REGISTRY --dispute-manager 0xYOUR_DISPUTE_MANAGER

# ترمینال ۳
java -cp /path/to/sfdac-java.jar BidderBoss --mode run \
  --nbuyers 2 --nsellers 2 --listen 7500 --session-id 0 \
  --chain-rpc http://127.0.0.1:8545 --auction-registry 0xYOUR_REGISTRY \
  --eth-priv keys/bidderboss.eth.priv

# خریدار و فروشنده: نمونه هر یک؛ به تعداد موردنیاز اجرا شود
java -cp /path/to/sfdac-java.jar Bidder --mode submit --role buyer \
  --name Alice --bid 90 --id 101 --session-id 0 \
  --chain-rpc http://127.0.0.1:8545 --auction-registry 0xYOUR_REGISTRY \
  --eth-priv keys/Alice.eth.priv

# بعد از مرحله جمع‌آوری و هم‌ترازسازی در P0/P1
java -cp /path/to/sfdac-java.jar P2
```

برای ارسال مدارک به `ProverParty`، آن را نیز **قبل از پایان تسویه** راه‌اندازی کنید:

```bash
java -cp /path/to/sfdac-java.jar ProverParty \
  --listen 7800 --priv keys/ProverParty.elg.priv \
  --out-dir zk-snark/perm_payloads --max-n 128
```

اگر می‌خواهید MPC را **بدون اجرای قراردادها و ProverParty** در محیط توسعه آزمایش کنید، هر سه سوییچ را برای P0/P1 استفاده کنید:

```bash
--disable-chain-submit --disable-result-submit --disable-prover-send
```

توجه: حتی در این حالت دریافت واقعی پیشنهادها همچنان ریشه Merkle روی زنجیره و CCE را چک می‌کند. در `auctioneer_mpc_smoke.py` از گزینه اختصاصی `--test-shares-json` برای تزریق سهم‌های ساختگی استفاده شده است؛ **این گزینه صرفاً تست است و بررسی امنیتی بسته‌های اصلی را دور می‌زند.**

## پورت‌ها

- `P0`: دریافت خریداران 7000، فروشندگان 7002، ارتباط با P1 روی 6000، ارتباط P2 روی 6001
- `P1`: دریافت خریداران 7001، فروشندگان 7003، ارتباط P2 روی 6002
- `BidderBoss`: دریافت بسته‌ها 7500، reveal روی 7700
- `ProverParty`: دریافت transport روی 7800

## تفاوت‌ها و محدودیت‌های فعلی

1. تمام شش نقش فایل Java و نقطه ورود اجرایی دارند، اما پورت `P0/P1` هنوز پوشش یکسانی برای همه سوییچ‌ها و سناریوهای تخریب عمدی منبع ندارد. سوییچ ناشناخته به جای نادیده گرفته‌شدن، خطای روشن ایجاد می‌کند.
2. هنگام رد شدن CCE با امضای معتبر، ارسال اختلاف CCE با `--cce-dispute-tool` اضافه شده؛ اما گزارش‌های پیشرفته equivocation/commitment consistency و Merkle و آزمون‌های گزارش خلاف واقع هنوز معادل کامل C++ نیستند. داده نادرست وارد حراج نمی‌شود.
3. انتشار واقعی hashها روی زنجیره، تولید امضاهای BabyJub و پردازش ProverParty با JS اصلی نیازمند فایل‌های کمکی و شبکه معتبر است و با منابع ارسالی این پروژه، قابل آزمون زنده نبود.
4. کانال TCP بدون TLS است؛ همان پروتکل C++ را حفظ می‌کند، ولی برای اجرا در شبکه غیرقابل‌اعتماد باید لایه امن مناسب اضافه شود.
5. به‌دلیل همین موارد، موفقیت در کامپایل و smoke test **تضمین بدون خطای اجرایی یا امنیتی در همه حالت‌ها نیست**.
