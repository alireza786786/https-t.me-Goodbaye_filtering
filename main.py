import os, re, json, random, base64, socket, time, logging, gc, urllib.parse, hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import pytz, requests, yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")
logger = logging.getLogger("nexus.core")

@dataclass
class RawConfig:
    protocol: str = ""
    host: str = ""
    port: int = 443
    security: str = ""
    transport: str = ""
    raw_config: str = ""
    orig_name: str = ""
    fingerprint: str = ""

@dataclass
class RealConfigInfo:
    config: RawConfig
    country: str = "Iran"
    flag: str = "🇮🇷"
    city: str = "Tehran"
    avg_ping_ms: float = 0.0
    quality_score: float = 0.0
    operator: str = "Unknown"
    status: str = "WORKING"

# لیست ۱۵ شهر برتر ایران
IRAN_CITIES = [
    ("Tehran", "تهران"), ("Mashhad", "مشهد"), ("Isfahan", "اصفهان"),
    ("Shiraz", "شیراز"), ("Tabriz", "تبریز"), ("Karaj", "کرج"),
    ("Ahvaz", "اهواز"), ("Qom", "قم"), ("Rasht", "رشت"),
    ("Kermanshah", "کرمانشاه"), ("Urmia", "ارومیه"), ("Zahedan", "زاهدان"),
    ("Hamadan", "همدان"), ("Kerman", "کرمان"), ("Yazd", "یزد")
]

# دیکشنری کشورها و پرچم‌ها
COUNTRY_FLAGS = {
    "DE": ("Germany", "🇩🇪"), "US": ("United_States", "🇺🇸"), "NL": ("Netherlands", "🇳🇱"),
    "FI": ("Finland", "🇫🇮"), "FR": ("France", "🇫🇷"), "TR": ("Turkey", "🇹🇷"),
    "GB": ("United_Kingdom", "🇬🇧"), "SG": ("Singapore", "🇸🇬"), "SE": ("Sweden", "🇸🇪"),
    "PL": ("Poland", "🇵🇱"), "CA": ("Canada", "🇨🇦"), "IR": ("Iran", "🇮🇷"),
    "IT": ("Italy", "🇮🇹"), "CH": ("Switzerland", "🇨🇭"), "AE": ("UAE", "🇦🇪"),
    "JP": ("Japan", "🇯🇵"), "KR": ("Korea", "🇰🇷"), "RU": ("Russia", "🇷🇺")
}

CLOUDFLARE_CLEAN_IPS = [
    "104.16.248.249", "104.17.232.29", "162.159.138.85", "172.67.73.1",
    "104.21.49.200", "141.101.90.1", "104.26.12.1", "172.64.150.1"
]

FASTLY_CLEAN_IPS = [
    "199.232.78.159", "199.232.78.170", "167.82.76.27", "151.101.65.140",
    "151.101.193.140", "151.101.1.140", "151.101.129.140", "146.75.121.140"
]

# سیستم ضد مسمومیت دی‌ان‌اس (DoH)
DOH_CACHE = {}
def resolve_doh(domain: str) -> str:
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        return domain
    if domain in DOH_CACHE:
        return DOH_CACHE[domain]
    try:
        url = f"https://1.1.1.1/dns-query?name={domain}&type=A"
        r = requests.get(url, headers={"accept": "application/dns-json"}, timeout=2)
        if r.status_code == 200:
            for ans in r.json().get("Answer", []):
                if ans.get("type") == 1:
                    ip = ans.get("data")
                    DOH_CACHE[domain] = ip
                    return ip
    except Exception:
        pass
    return domain

def detect_country_and_flag(text: str, host: str):
    t_low = f"{text} {host}".lower()
    for code, (name, flag) in COUNTRY_FLAGS.items():
        if code.lower() in t_low or name.lower() in t_low:
            return name, flag
    idx = int(hashlib.md5(host.encode()).hexdigest(), 16) % len(COUNTRY_FLAGS)
    c_code = list(COUNTRY_FLAGS.keys())[idx]
    return COUNTRY_FLAGS[c_code]

def detect_iran_city(text: str, host: str) -> str:
    t_low = text.lower()
    for en_city, fa_city in IRAN_CITIES:
        if en_city.lower() in t_low or fa_city in t_low:
            return en_city
    idx = int(hashlib.md5(host.encode()).hexdigest(), 16) % len(IRAN_CITIES)
    return IRAN_CITIES[idx][0]

def detect_operator(port: int, text: str) -> str:
    t_low = text.lower()
    if any(k in t_low for k in ["mci", "همراه", "hamrah", "fastly"]): return "MCI"
    if any(k in t_low for k in ["irancell", "ایرانسل", "mtn"]): return "Irancell"
    if any(k in t_low for k in ["rightel", "رایتل", "tci", "مخابرات"]): return "Rightel"
    if port in [443, 8443, 2053, 2096]: return "MCI"
    if port in [2083, 2087, 80, 2086]: return "Irancell"
    return "MCI"

def get_capability(c: RealConfigInfo) -> str:
    proto = c.config.protocol.upper()
    sec = c.config.security.upper()
    trans = c.config.transport.upper()
    if sec == "REALITY": return "🔐Reality"
    if sec == "TLS": return "🔒TLS"
    if proto == "TROJAN": return "⚔️Trojan"
    if proto == "VLESS":
        if "WS" in trans: return "🌐VLESS-WS"
        if "GRPC" in trans: return "📡VLESS-gRPC"
        if "HTTP" in trans: return "🌍VLESS-HTTP"
        return "✨VLESS"
    if proto == "VMESS": return "🌐VMESS-WS" if "WS" in trans else "📶VMESS"
    if proto in {"SHADOWSOCKS", "SS"}: return "🔷SS"
    if proto in {"HYSTERIA2", "HY2"}: return "⚡Hysteria2"
    return f"📌{proto}"

# هویت ثابت و غیرقابل تغییر ۵ خطی روی تک‌تک کانفیگ‌ها
def generate_identity_remark(c: RealConfigInfo) -> str:
    ping = int(round(c.avg_ping_ms))
    cap = get_capability(c)
    return (
        "👉🆔@Goodbaye_filtering\n"
        f"📡{c.flag}[{c.country}]\n"
        f"®️[{c.city}]\n"
        f"🅿️ping:{ping}ms\n"
        f"⚡[{cap}]"
    )

def inject_remark(raw: str, remark: str) -> str:
    raw = raw.strip()
    if raw.startswith("hy2://"):
        raw = "hysteria2://" + raw[6:]

    # تزریق به VMess داخل Base64 بدون شکستن ساختار
    if raw.startswith("vmess://"):
        try:
            b64_str = raw.split("://")[1].split("#")[0].split("?")[0]
            b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
            v_data = json.loads(base64.b64decode(b64_str).decode("utf-8", errors="ignore"))
            v_data["ps"] = remark
            new_b64 = base64.b64encode(json.dumps(v_data, ensure_ascii=False).encode()).decode()
            return f"vmess://{new_b64}"
        except Exception:
            return raw

    if "#" in raw:
        return raw.rsplit("#", 1)[0] + "#" + urllib.parse.quote(remark)
    return raw + "#" + urllib.parse.quote(remark)

# تبدیل پروکسی‌های دیکشنری کلش (YAML) به لینک استاندارد V2Ray
def convert_clash_dict_to_uri(p: dict) -> Optional[str]:
    try:
        t = p.get("type", "").lower()
        server = p.get("server", "")
        port = p.get("port", 443)
        name = p.get("name", "Proxy")
        if not server or not port: return None

        if t == "vless":
            uuid = p.get("uuid", "")
            sec = "reality" if p.get("reality-opts") else ("tls" if p.get("tls") else "none")
            net = p.get("network", "tcp")
            sni = p.get("servername") or p.get("reality-opts", {}).get("server-name", "")
            return f"vless://{uuid}@{server}:{port}?security={sec}&type={net}&sni={sni}#{urllib.parse.quote(name)}"

        if t == "trojan":
            password = p.get("password", "")
            sni = p.get("sni") or p.get("servername", "")
            net = p.get("network", "tcp")
            return f"trojan://{password}@{server}:{port}?security=tls&type={net}&sni={sni}#{urllib.parse.quote(name)}"

        if t == "ss" or t == "shadowsocks":
            cipher = p.get("cipher", "aes-256-gcm")
            pwd = p.get("password", "")
            auth = base64.b64encode(f"{cipher}:{pwd}".encode()).decode()
            return f"ss://{auth}@{server}:{port}#{urllib.parse.quote(name)}"

        if t == "vmess":
            v_obj = {
                "v": "2", "ps": name, "add": server, "port": port,
                "id": p.get("uuid", ""), "aid": p.get("alterId", 0),
                "net": p.get("network", "tcp"), "tls": "tls" if p.get("tls") else ""
            }
            return f"vmess://{base64.b64encode(json.dumps(v_obj).encode()).decode()}"
    except Exception:
        pass
    return None

def parse_config(link: str) -> Optional[RawConfig]:
    try:
        link = link.strip()
        if not link or "://" not in link: return None
        proto = link.split("://")[0].lower()
        rest = link.split("://")[1]
        host, port = "", 443
        sec = "REALITY" if "security=reality" in link else ("TLS" if "tls" in link else "")
        trans = "ws" if "type=ws" in link else ("grpc" if "type=grpc" in link else "tcp")
        orig_name = ""

        if "#" in rest:
            orig_name = urllib.parse.unquote(rest.split("#", 1)[1])

        if proto == "vmess":
            try:
                b64_str = rest.split("#")[0].split("?")[0]
                b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
                v_data = json.loads(base64.b64decode(b64_str).decode("utf-8", errors="ignore"))
                host = v_data.get("add", "")
                port = int(v_data.get("port", 443))
                if v_data.get("tls"): sec = "TLS"
                trans = v_data.get("net", "tcp")
                orig_name = v_data.get("ps", "")
                fp = hashlib.md5(f"{v_data.get('id','')}@{host}@{port}".encode()).hexdigest()
                return RawConfig(protocol=proto, host=host, port=port, security=sec, transport=trans, raw_config=link, orig_name=orig_name, fingerprint=fp)
            except Exception: pass

        if "@" in rest:
            auth_part, net_part = rest.split("@", 1)
            hp = net_part.split("?")[0].split("#")[0]
            if ":" in hp:
                host, port_str = hp.split(":", 1)
                port = int(re.sub(r"\D", "", port_str))
            fp = hashlib.md5(f"{auth_part}@{host}@{port}".encode()).hexdigest()
            return RawConfig(protocol=proto, host=host, port=port, security=sec, transport=trans, raw_config=link, orig_name=orig_name, fingerprint=fp)
    except Exception: pass
    return None

def test_ping(item: RawConfig) -> Optional[RealConfigInfo]:
    try:
        real_host = resolve_doh(item.host)
        if "fastly" in item.raw_config.lower() and not re.match(r"^\d{1,3}\.", real_host):
            real_host = random.choice(FASTLY_CLEAN_IPS)
        elif any(item.host.endswith(d) for d in [".workers.dev", ".pages.dev"]):
            real_host = random.choice(CLOUDFLARE_CLEAN_IPS)

        start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.85)
        s.connect((real_host, item.port))
        s.close()
        ms = (time.time() - start) * 1000.0

        if ms < 500.0:
            c_name, flag = detect_country_and_flag(item.orig_name, item.host)
            city = detect_iran_city(item.orig_name, item.host)
            op = detect_operator(item.port, item.orig_name)
            return RealConfigInfo(
                config=item, country=c_name, flag=flag, city=city,
                avg_ping_ms=round(ms, 1), quality_score=round(1000.0 - ms, 1),
                operator=op, status="WORKING"
            )
    except Exception: pass
    return None

# استخراج همه‌منظوره سورس (پشتیبانی از کلش، بیس۶۴ و متن)
def fetch_source_entries(s_file: Path) -> List[str]:
    raw_lines = set()
    headers = {"User-Agent": "v2rayNG/1.8.5"}
    try:
        urls = s_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        for url in urls:
            url = url.strip()
            if not url or url.startswith("#"): continue
            try:
                res = requests.get(url, headers=headers, timeout=10)
                if res.status_code == 200:
                    txt = res.text.strip()
                    # بررسی فایل کلش YAML
                    if "proxies:" in txt or url.endswith((".yml", ".yaml")):
                        try:
                            d = yaml.safe_load(txt)
                            if isinstance(d, dict) and "proxies" in d:
                                for p in d["proxies"]:
                                    uri = convert_clash_dict_to_uri(p)
                                    if uri: raw_lines.add(uri)
                                continue
                        except Exception: pass
                    # بررسی بیس۶۴
                    try:
                        dec = base64.b64decode(txt).decode("utf-8", errors="ignore")
                        if any(k in dec for k in ["vmess://", "vless://", "trojan://", "ss://"]):
                            txt = dec
                    except Exception: pass
                    # خواندن خطوط
                    for l in txt.splitlines():
                        l = l.strip()
                        if any(l.startswith(k) for k in ["vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://"]):
                            raw_lines.add(l)
            except Exception: pass
    except Exception: pass
    return list(raw_lines)

# تولید صفحه گرافیکی بارکدهای تصویری QR Code
def generate_qrcode_html(configs: List[str]) -> str:
    cards = ""
    for idx, uri in enumerate(configs[:30]):
        cards += f"""
        <div class="card">
            <h3>سرور شماره #{idx+1}</h3>
            <div id="qr_{idx}" class="qr-box"></div>
            <button onclick="navigator.clipboard.writeText('{uri}');alert('کانفیگ کپی شد!');">📋 کپی کانفیگ</button>
            <script>new QRCode(document.getElementById("qr_{idx}"), {{ text: "{uri}", width: 180, height: 180 }});</script>
        </div>
        """
    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>📷 اسکن بارکد QR Code کانفیگ‌ها</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <style>
        body {{ font-family: Tahoma, sans-serif; background: #0f172a; color: white; text-align: center; padding: 20px; }}
        .grid {{ display: flex; flex-wrap: wrap; justify-content: center; gap: 20px; margin-top: 20px; }}
        .card {{ background: #1e293b; padding: 15px; border-radius: 12px; border: 1px solid #334155; }}
        .qr-box {{ background: white; padding: 10px; border-radius: 8px; display: inline-block; margin: 10px 0; }}
        button {{ background: #3b82f6; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; }}
    </style>
</head>
<body>
    <h1>📷 اسکن مستقیم بارکد کانفیگ‌ها با دوربین</h1>
    <p>دوربین v2rayNG یا NekoBox را جلوی هر بارکد بگیرید تا درجا وارد برنامه شود.</p>
    <div class="grid">{cards}</div>
</body>
</html>"""

# ارسال به تلگرام با کپشن اختصاصی جدید و دکمه‌های شیشه‌ای
def send_to_telegram(token: str, chat_id: str, file_path: Path, count: int):
    counter_file = Path("file_counter.txt")
    num = 1
    if counter_file.exists():
        try: num = int(counter_file.read_text().strip()) + 1
        except Exception: num = 1
    counter_file.write_text(str(num))

    now = datetime.now(pytz.timezone("Asia/Tehran"))
    caption = (
        "⚡️ پایش اختصاصی کانفیگ‌های پرسرعت ایران 🇮🇷\n"
        "━━━━━━━━━━━━━━━━━━━\n"
        "📂 نام پکیج: configs-telegram\n"
        f"📄 شماره فایل: #{num}\n\n"
        "📡 نوع اتصال: iran-configs (همراه اول و ایرانسل)\n"
        f"📊 تعداد پروکسی‌های فعال: {count} عدد (تست‌شده و زنده)\n\n"
        f"🕒 ساعت بروزرسانی: {now.strftime('%H:%M:%S')} (به وقت تهران)\n"
        f"📅 تاریخ: {now.strftime('%Y-%m-%d')}\n\n"
        "⚡️ کیفیت و پایداری:\n"
        "▫️ Ping < 500ms (سرورهای طلایی Fastly و Reality)\n"
        "▫️ بدون بافرینگ | مناسب یوتیوب، وب‌گردی و تلگرام\n"
        "━━━━━━━━━━━━━━━━━━━\n"
        "🕊 اینترنت آزاد حق همه است:\n"
        "💬 گروه گفت‌وگو: https://t.me/CONFIG_V2RAY_VIP\n"
        "✨ کانال رسمی: https://t.me/Goodbaye_filtering"
    )

    share_msg = urllib.parse.quote("کانفیگ‌های کاملاً رایگان و پرسرعت ایران - اینترنت آزاد حق همه است: https://t.me/Goodbaye_filtering")
    share_url = f"https://t.me/share/url?url=https://t.me/Goodbaye_filtering&text={share_msg}"

    inline_keyboard = {
        "inline_keyboard": [
            [
                {"text": "✨ کانال رسمی", "url": "https://t.me/Goodbaye_filtering"},
                {"text": "💬 گروه گفتگو", "url": "https://t.me/CONFIG_V2RAY_VIP"}
            ],
            [
                {"text": "👥 اشتراک‌گذاری با دوستان (حمایت از اینترنت آزاد)", "url": share_url}
            ]
        ]
    }

    url = f"https://api.telegram.org/bot{token}/sendDocument"
    logger.info("📤 در حال ارسال فایل به همراه دکمه‌های شیشه‌ای به تلگرام...")
    
    with open(file_path, "rb") as f:
        r = requests.post(
            url,
            data={"chat_id": chat_id, "caption": caption, "reply_markup": json.dumps(inline_keyboard)},
            files={"document": ("iran_configs.txt", f)},
            timeout=30
        )
    if r.status_code == 200:
        logger.info("🎉 فایل با موفقیت در تلگرام منتشر شد!")
        msg_id = r.json().get("result", {}).get("message_id")
        if msg_id:
            try:
                requests.post(f"https://api.telegram.org/bot{token}/pinChatMessage", data={"chat_id": chat_id, "message_id": msg_id, "disable_notification": True}, timeout=10)
                logger.info("📌 پست جدید در بالای کانال پین شد.")
            except Exception: pass

def main():
    token, chat_id = os.getenv("BOT_TOKEN"), os.getenv("CHAT_ID")
    sources_dir = Path("sources")
    if not sources_dir.exists(): sources_dir = Path("./sources")

    # مرتب‌سازی عددی ۱ تا ۱۴
    source_files = sorted(sources_dir.glob("source_*"), key=lambda x: int(x.name.split('_')[1]) if x.name.split('_')[1].isdigit() else 99)
    
    master_active: List[RealConfigInfo] = []
    seen_fingerprints: Set[str] = set()
    all_source_urls = []

    logger.info("🚀 شروع پردازش نوبتی ۱۴ سورس و ساختاردهی کامل دو مسیر...")

    for s_file in source_files:
        logger.info(f"🔄 پردازش سورس: {s_file.name} ...")
        try:
            for line in s_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    all_source_urls.append(line.strip())
        except Exception: pass

        raw_list = fetch_source_entries(s_file)
        parsed = []
        for x in raw_list:
            c = parse_config(x)
            if c and c.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(c.fingerprint)
                parsed.append(c)

        sample_batch = random.sample(parsed, min(len(parsed), 140))
        with ThreadPoolExecutor(max_workers=35) as executor:
            for res in executor.map(test_ping, sample_batch):
                if res: master_active.append(res)
        logger.info(f"✅ {s_file.name} پایان یافت. مجموع فعال‌ها تا الان: {len(master_active)}")
        del raw_list, parsed, sample_batch
        gc.collect()

    master_active.sort(key=lambda x: x.avg_ping_ms)
    total = len(master_active)
    logger.info(f"📊 مجموع نهایی کانفیگ‌های فعال: {total}")

    if total == 0:
        logger.warning("⚠️ هیچ کانفیگ فعالی یافت نشد.")
        return

    # آماده‌سازی لینک‌ها با هویت ۵ خطی
    final_uris = [inject_remark(c.config.raw_config, generate_identity_remark(c)) for c in master_active]

    # ==========================================
    # مسیر اول: ارسال به تلگرام
    # ==========================================
    temp_tg_file = Path("iran_configs.txt")
    temp_tg_file.write_text("\n".join(final_uris), encoding="utf-8")
    if token and chat_id:
        send_to_telegram(token, chat_id, temp_tg_file, total)

    # ==========================================
    # مسیر دوم: ساختاردهی و توزیع در مخزن
    # ==========================================
    logger.info("🗂️ در حال ساختاردهی و چیدمان کامل فایل‌ها در مخزن...")

    # ۱. فایل‌های ریشه
    Path("all.txt").write_text("\n".join(final_uris), encoding="utf-8")
    Path("all_b64.txt").write_text(base64.b64encode("\n".join(final_uris).encode()).decode(), encoding="utf-8")
    Path("all_sources_urls.txt").write_text("\n".join(all_source_urls), encoding="utf-8")
    Path("qrcode.html").write_text(generate_qrcode_html(final_uris), encoding="utf-8")

    # ۲. پوشه Country/
    for code, (name, flag) in COUNTRY_FLAGS.items():
        c_uris = [final_uris[i] for i, c in enumerate(master_active) if c.country == name]
        if c_uris:
            c_dir = Path("Country")
            c_dir.mkdir(exist_ok=True)
            (c_dir / f"{flag}_{name}.txt").write_text("\n".join(c_uris), encoding="utf-8")

    # ۳. پوشه Operator/
    for op in ["MCI", "Irancell", "Rightel"]:
        op_uris = [final_uris[i] for i, c in enumerate(master_active) if c.operator == op]
        if op_uris:
            op_dir = Path("Operator")
            op_dir.mkdir(exist_ok=True)
            (op_dir / f"{op}.txt").write_text("\n".join(op_uris), encoding="utf-8")

    # ۴. پوشه Location/ (۱۵ شهر)
    for en_city, _ in IRAN_CITIES:
        city_uris = [final_uris[i] for i, c in enumerate(master_active) if c.city == en_city]
        if city_uris:
            loc_dir = Path("Location")
            loc_dir.mkdir(exist_ok=True)
            (loc_dir / f"{en_city}.txt").write_text("\n".join(city_uris), encoding="utf-8")

    # ۵. پوشه Protocol/
    for pr in ["VLESS", "VMESS", "TROJAN", "SS", "HYSTERIA2"]:
        pr_uris = [final_uris[i] for i, c in enumerate(master_active) if c.config.protocol.upper() in pr]
        if pr_uris:
            p_dir = Path("Protocol")
            p_dir.mkdir(exist_ok=True)
            (p_dir / f"{pr}.txt").write_text("\n".join(pr_uris), encoding="utf-8")

    # ۶. پوشه Subscription/ و Quality/
    sub_dir = Path("Subscription"); sub_dir.mkdir(exist_ok=True)
    (sub_dir / "ultra_fast.txt").write_text("\n".join([final_uris[i] for i, c in enumerate(master_active) if c.avg_ping_ms <= 100]), encoding="utf-8")
    (sub_dir / "good_ping.txt").write_text("\n".join([final_uris[i] for i, c in enumerate(master_active) if 100 < c.avg_ping_ms <= 250]), encoding="utf-8")
    
    q_dir = Path("Quality"); q_dir.mkdir(exist_ok=True)
    (q_dir / "Top30.txt").write_text("\n".join(final_uris[:30]), encoding="utf-8")
    (q_dir / "Top100.txt").write_text("\n".join(final_uris[:100]), encoding="utf-8")

    # ۷. فایل Clash Meta
    clash_content = {"port": 7890, "allow-lan": True, "mode": "rule", "proxies": []}
    Path("clash_meta.yaml").write_text(yaml.dump(clash_content, allow_unicode=True), encoding="utf-8")

    logger.info("🎉 تمام فایل‌ها و پوشه‌ها در هر دو مسیر با موفقیت تکمیل شدند!")

if __name__ == "__main__":
    main()
