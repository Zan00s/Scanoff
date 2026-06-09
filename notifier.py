import requests

class TelegramNotifier:
    def __init__(self, token, chat_id, proxy=None):
        self.token = token
        self.chat_id = chat_id
        self.proxy = {"https": proxy} if proxy else None

    def send_message(self, text):
        if not self.token or not self.chat_id:
            return
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        data = {
            "chat_id": self.chat_id,
            "text": text,
        }
        try:
            resp = requests.post(url, data=data, timeout=10, proxies=self.proxy)
            resp.raise_for_status()
        except Exception as e:
            print(f"[!] Telegram notification failed: {e}")
