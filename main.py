# main.py
import os
import sqlite3
import bcrypt
import logging
from datetime import datetime
from telegram import Update, ReplyKeyboardRemove
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    ConversationHandler,
    filters,
)

# --- Config ---
DB_PATH = os.getenv("DB_PATH", "users.db")
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("Missing BOT_TOKEN environment variable")

# Conversation states
ASK_PASSWORD = 1

# --- Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- DB helpers ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER UNIQUE,
        username TEXT,
        password_hash BLOB,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

def user_exists_by_telegram(telegram_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE telegram_id = ?", (telegram_id,))
    row = cur.fetchone()
    conn.close()
    return row is not None

def user_exists_by_username(username):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row is not None

def create_user(telegram_id, username, password_plain):
    pw_bytes = password_plain.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pw_bytes, salt)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (telegram_id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (telegram_id, username, hashed, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

def verify_password(username, password_plain):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False
    stored_hash = row[0]
    return bcrypt.checkpw(password_plain.encode('utf-8'), stored_hash)

# --- Bot handlers ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    await update.message.reply_text(
        "Ciao! Usa /register per creare un account (username = tuo username Telegram). "
        "Se non hai username, impostalo nelle impostazioni di Telegram o scrivilo quando richiesto."
    )

async def register_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    tg_username = user.username
    if user_exists_by_telegram(user.id):
        await update.message.reply_text("Sei già registrato.")
        return ConversationHandler.END

    if tg_username:
        if user_exists_by_username(tg_username):
            # username Telegram già usato da altro account: chiedi di inserire uno username alternativo
            await update.message.reply_text(
                f"Il tuo username Telegram @{tg_username} è già registrato. "
                "Scrivi qui lo username che vuoi usare (senza @):"
            )
            # store that we need to accept a username first
            context.user_data['need_custom_username'] = True
            return ASK_PASSWORD
        else:
            context.user_data['chosen_username'] = tg_username
            await update.message.reply_text(
                "Ok, user sarà @{0}. Invia ora la password che vuoi usare:".format(tg_username)
            )
            return ASK_PASSWORD
    else:
        await update.message.reply_text(
            "Non vedo uno username Telegram sul tuo profilo. Scrivi qui lo username che vuoi usare (senza @):"
        )
        context.user_data['need_custom_username'] = True
        return ASK_PASSWORD

async def register_password_received(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    # if we previously asked for a username, the first message is the username
    if context.user_data.get('need_custom_username') and 'chosen_username' not in context.user_data:
        chosen = text.lstrip('@').strip()
        if user_exists_by_username(chosen):
            await update.message.reply_text("Questo username è già preso. Scrivine un altro:")
            return ASK_PASSWORD
        context.user_data['chosen_username'] = chosen
        await update.message.reply_text("Ok. Ora invia la password che vuoi usare:")
        return ASK_PASSWORD

    # otherwise, text is the password
    password = text
    chosen_username = context.user_data.get('chosen_username')
    if not chosen_username:
        await update.message.reply_text("Errore interno: username non impostato. Ripeti /register")
        return ConversationHandler.END

    # basic password checks (puoi arricchire)
    if len(password) < 6:
        await update.message.reply_text("Password troppo corta (min 6 caratteri). Invia un'altra password:")
        return ASK_PASSWORD

    # create user
    try:
        create_user(update.effective_user.id, chosen_username, password)
    except Exception as e:
        logger.exception("Errore creazione utente")
        await update.message.reply_text("Errore durante la registrazione. Contatta l'admin.")
        return ConversationHandler.END

    await update.message.reply_text(f"Registrazione completata! Username: @{chosen_username}")
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Operazione annullata.", reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END

async def login_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # usage: /login <username> <password>
    args = context.args
    if len(args) < 2:
        await update.message.reply_text("Usa: /login <username> <password>")
        return
    username = args[0].lstrip('@')
    password = " ".join(args[1:])
    ok = verify_password(username, password)
    if ok:
        await update.message.reply_text("Login eseguito correttamente.")
    else:
        await update.message.reply_text("Username o password errati.")

def main():
    init_db()
    app = Application.builder().token(BOT_TOKEN).build()

    conv = ConversationHandler(
        entry_points=[CommandHandler('register', register_start)],
        states={
            ASK_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, register_password_received)],
        },
        fallbacks=[CommandHandler('cancel', cancel)]
    )

    app.add_handler(CommandHandler('start', start))
    app.add_handler(conv)
    app.add_handler(CommandHandler('login', login_cmd))
    logger.info("Bot avviato")
    app.run_polling()

if __name__ == "__main__":
    main()
