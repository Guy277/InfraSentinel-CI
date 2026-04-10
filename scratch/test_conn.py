import json
import logging
from chatbot.security_chatbot import SecurityChatbot

logging.basicConfig(level=logging.INFO)

class MockAgent:
    def get_stats(self): return {}
    def get_recent_decisions(self, n): return []
    def get_whitelist(self): return []

cb = SecurityChatbot(agent=MockAgent())
cb.enable()

print(f"Status: {cb.get_status()}")
print("Testing chat...")
resp = cb.chat("Bonjour, teste la connexion cloud.")
print(f"Response: {resp}")
