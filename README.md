#!/usr/bin/env python3
"""
DAWN Bot with Telegram and AES Encryption
A modular bot framework with database, Telegram integration, and encrypted data storage.
Developed by Grok 3 (xAI) - March 22, 2025
"""

import logging
import asyncio
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
import json
import os
import sqlite3
from datetime import datetime
import sys
import subprocess
from telegram import Bot
from telegram.ext import Application, CommandHandler, ContextTypes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='dawn_bot.log'
)
logger = logging.getLogger("DAWNBot")


# ----------------------
# Encryption Manager
# ----------------------
class EncryptionManager:
    """
    Handles AES encryption and decryption for confidential data.
    Uses AES-256 in CBC mode with a 256-bit key and random IV for each encryption.
    """
    
    def __init__(self, key: bytes = None):
        """
        Initializes the encryption manager with a key.
        If no key is provided, generates a new 256-bit key.
        """
        self.key = key if key else get_random_bytes(32)  # 256-bit key
        logger.info("EncryptionManager initialized")

    def encrypt(self, data: str) -> str:
        """
        Encrypts data using AES-256-CBC.
        Args:
            data: Plaintext string to encrypt.
        Returns:
            Base64-encoded string containing IV + ciphertext.
        """
        try:
            cipher = AES.new(self.key, AES.MODE_CBC)
            iv = cipher.IV  # 16-byte initialization vector
            padded_data = pad(data.encode('utf-8'), AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            # Combine IV and ciphertext, encode to base64 for storage
            encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
            return encrypted_data
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypts data encrypted with AES-256-CBC.
        Args:
            encrypted_data: Base64-encoded string with IV + ciphertext.
        Returns:
            Decrypted plaintext string.
        """
        try:
            raw_data = base64.b64decode(encrypted_data)
            iv = raw_data[:16]  # Extract IV from first 16 bytes
            ciphertext = raw_data[16:]  # Remaining bytes are ciphertext
            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
            padded_data = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_data, AES.block_size).decode('utf-8')
            return plaintext
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

    def get_key(self) -> bytes:
        """Returns the encryption key for storage or sharing."""
        return self.key


# ----------------------
# Configuration Manager
# ----------------------
class ConfigManager:
    """Handles loading and saving configuration settings, including encryption key."""
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        self.encryption = EncryptionManager(
            base64.b64decode(self.config.get("encryption_key")) if self.config.get("encryption_key") else None
        )
        if not self.config.get("encryption_key"):
            self.config["encryption_key"] = base64.b64encode(self.encryption.get_key()).decode('utf-8')
            self.save_config()

    def _load_config(self) -> Dict[str, Any]:
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            return {"telegram_token": "YOUR_TELEGRAM_BOT_TOKEN", "admin_chat_id": "YOUR_CHAT_ID"}
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}

    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)


# ----------------------
# Database Manager
# ----------------------
class DatabaseManager:
    """Manages database operations with encrypted metadata and balances."""
    
    def __init__(self, db_file: str = "dawn_accounts.db", encryption: EncryptionManager = None):
        self.db_file = db_file
        self.encryption = encryption
        self._init_db()
        logger.info("DatabaseManager initialized")

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS accounts (
                        account_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        status TEXT DEFAULT 'active',
                        last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        metadata TEXT DEFAULT '{}'
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS balances (
                        account_id INTEGER,
                        balance TEXT DEFAULT '0.0',  -- Encrypted balance
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (account_id) REFERENCES accounts(account_id)
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {e}")
            raise

    def _get_connection(self) -> sqlite3.Connection:
        try:
            return sqlite3.connect(self.db_file)
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    async def add_account(self, username: str, metadata: Dict[str, Any] = None) -> int:
        encrypted_metadata = self.encryption.encrypt(json.dumps(metadata or {}))
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO accounts (username, metadata) VALUES (?, ?)", (username, encrypted_metadata))
                account_id = cursor.lastrowid
                encrypted_balance = self.encryption.encrypt("0.0")
                cursor.execute("INSERT INTO balances (account_id, balance) VALUES (?, ?)", (account_id, encrypted_balance))
                conn.commit()
                return account_id
        except sqlite3.Error as e:
            logger.error(f"Database error during account addition: {e}")
            raise

    async def update_balance(self, account_id: int, balance: float):
        encrypted_balance = self.encryption.encrypt(str(balance))
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO balances (account_id, balance, last_updated) VALUES (?, ?, ?)",
                    (account_id, encrypted_balance, datetime.now().isoformat())
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error during balance update: {e}")
            raise

    async def get_balance(self, account_id: int) -> Dict[str, Any]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT balance, last_updated FROM balances WHERE account_id = ?", (account_id,))
                row = cursor.fetchone()
                if row:
                    decrypted_balance = float(self.encryption.decrypt(row[0]))
                    return {"balance": decrypted_balance, "last_updated": row[1]}
                return {"balance": 0.0, "last_updated": None}
        except sqlite3.Error as e:
            logger.error(f"Database error during balance retrieval: {e}")
            raise

    async def get_account(self, account_id: int = None, username: str = None) -> Optional[Dict[str, Any]]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if account_id is not None:
                    cursor.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,))
                elif username is not None:
                    cursor.execute("SELECT * FROM accounts WHERE username = ?", (username,))
                else:
                    raise ValueError("Must provide account_id or username")
                row = cursor.fetchone()
                if row:
                    account = {
                        "account_id": row[0],
                        "username": row[1],
                        "status": row[2],
                        "last_active": row[3],
                        "metadata": json.loads(self.encryption.decrypt(row[4]))
                    }
                    balance = await self.get_balance(account["account_id"])
                    account.update(balance)
                    return account
                return None
        except sqlite3.Error as e:
            logger.error(f"Database error during account retrieval: {e}")
            raise

    async def list_accounts(self, status: str = None) -> List[Dict[str, Any]]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if status:
                    cursor.execute("SELECT * FROM accounts WHERE status = ?", (status,))
                else:
                    cursor.execute("SELECT * FROM accounts")
                rows = cursor.fetchall()
                accounts = []
                for row in rows:
                    account = {
                        "account_id": row[0],
                        "username": row[1],
                        "status": row[2],
                        "last_active": row[3],
                        "metadata": json.loads(self.encryption.decrypt(row[4]))
                    }
                    balance = await self.get_balance(account["account_id"])
                    account.update(balance)
                    accounts.append(account)
                return accounts
        except sqlite3.Error as e:
            logger.error(f"Database error during account listing: {e}")
            raise


# ----------------------
# Core Bot Class (Abstract)
# ----------------------
class BotCore(ABC):
    def __init__(self, config: ConfigManager):
        self.config = config
        self.is_running = False
        logger.info("BotCore initialized")

    @abstractmethod
    async def start(self):
        pass

    @abstractmethod
    async def stop(self):
        pass


# ----------------------
# Telegram Communication Handler
# ----------------------
class TelegramCommHandler:
    """Handles Telegram bot integration with encrypted data notifications."""
    
    def __init__(self, config: ConfigManager, bot_instance):
        self.config = config
        self.bot = Bot(config.get("telegram_token"))
        self.admin_chat_id = config.get("admin_chat_id")
        self.application = Application.builder().token(config.get("telegram_token")).build()
        self.bot_instance = bot_instance
        self._setup_handlers()
        logger.info("TelegramCommHandler initialized")

    def _setup_handlers(self):
        self.application.add_handler(CommandHandler("start", self._start_command))
        self.application.add_handler(CommandHandler("status", self._status_command))
        self.application.add_handler(CommandHandler("restart", self._restart_command))
        self.application.add_handler(CommandHandler("balance", self._balance_command))

    async def start(self):
        await self.application.initialize()
        await self.application.start()
        await self.application.updater.start_polling()

    async def stop(self):
        await self.application.updater.stop()
        await self.application.stop()

    async def send_message(self, message: str):
        try:
            await self.bot.send_message(chat_id=self.admin_chat_id, text=message)
            logger.info(f"Telegram message sent: {message}")
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")

    async def _start_command(self, update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text("DAWN Bot is online! Use /status, /restart, or /balance.")

    async def _status_command(self, update, context: ContextTypes.DEFAULT_TYPE):
        status = "Running" if self.bot_instance.is_running else "Stopped"
        accounts = await self.bot_instance.db.list_accounts()
        msg = f"System Status: {status}\nAccounts: {len(accounts)}"
        await update.message.reply_text(msg)

    async def _restart_command(self, update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text("Restarting DAWN Bot...")
        await self.bot_instance.restart_script()

    async def _balance_command(self, update, context: ContextTypes.DEFAULT_TYPE):
        accounts = await self.bot_instance.db.list_accounts()
        msg = "Balance Status:\n" + "\n".join(
            [f"{a['username']}: {a['balance']} (Updated: {a['last_updated']})" for a in accounts]
        )
        await update.message.reply_text(msg)


# ----------------------
# Task Processor
# ----------------------
class TaskProcessor:
    """Manages tasks with encrypted data monitoring."""
    
    def __init__(self, db: DatabaseManager, comm_handler: TelegramCommHandler):
        self.tasks = asyncio.Queue()
        self.db = db
        self.comm_handler = comm_handler
        logger.info("TaskProcessor initialized")

    async def add_task(self, task: Dict[str, Any]):
        await self.tasks.put(task)
        logger.info(f"Task added: {task}")

    async def process_tasks(self):
        while True:
            task = await self.tasks.get()
            logger.info(f"Processing task: {task}")
            if task["type"] == "health_check":
                await self._perform_health_check()
            elif task["type"] == "balance_monitor":
                await self._monitor_balances()
            self.tasks.task_done()

    async def _perform_health_check(self):
        try:
            with self.db._get_connection() as conn:
                conn.execute("SELECT 1")
            logger.info("Health check passed")
        except Exception as e:
            await self.comm_handler.send_message(f"Health Check Failed: {str(e)}")
            logger.error(f"Health check failed: {e}")

    async def _monitor_balances(self):
        accounts = await self.db.list_accounts(status="active")
        for account in accounts:
            if account["balance"] < 10.0:
                await self.comm_handler.send_message(
                    f"Low Balance Alert: {account['username']} has {account['balance']}"
                )
            new_balance = account["balance"] + 1.0  # Simulated update
            await self.db.update_balance(account["account_id"], new_balance)


# ----------------------
# Main DAWN Bot Implementation
# ----------------------
class DawnBot(BotCore):
    """Main bot with AES encryption integration."""
    
    def __init__(self, config: ConfigManager):
        super().__init__(config)
        self.db = DatabaseManager(encryption=config.encryption)
        self.comm_handler = TelegramCommHandler(config, self)
        self.task_processor = TaskProcessor(self.db, self.comm_handler)

    async def start(self):
        if self.is_running:
            logger.warning("Bot is already running")
            return
        self.is_running = True
        logger.info("DAWN Bot starting...")
        await self.comm_handler.send_message("DAWN Bot started")
        asyncio.create_task(self.task_processor.process_tasks())
        asyncio.create_task(self._schedule_monitoring())
        await self.comm_handler.start()

    async def stop(self):
        self.is_running = False
        await self.comm_handler.send_message("DAWN Bot stopped")
        await self.comm_handler.stop()
        logger.info("DAWN Bot stopped")

    async def restart_script(self):
        await self.stop()
        await self.comm_handler.send_message("Restarting script...")
        logger.info("Restarting script")
        subprocess.Popen([sys.executable, *sys.argv])
        sys.exit(0)

    async def _schedule_monitoring(self):
        while self.is_running:
            await self.task_processor.add_task({"type": "health_check"})
            await self.task_processor.add_task({"type": "balance_monitor"})
            await asyncio.sleep(300)  # Every 5 minutes


# ----------------------
# Entry Point
# ----------------------
async def main():
    config = ConfigManager()
    if not config.get("telegram_token") or not config.get("admin_chat_id"):
        logger.error("Telegram token or admin chat ID missing in config")
        sys.exit(1)
    
    bot = DawnBot(config)
    try:
        await bot.start()
    except KeyboardInterrupt:
        await bot.stop()
    except Exception as e:
        logger.error(f"Bot crashed: {e}")
        await bot.comm_handler.send_message(f"Bot Crashed: {str(e)}")
        await bot.stop()

if __name__ == "__main__":
    asyncio.run(main())
