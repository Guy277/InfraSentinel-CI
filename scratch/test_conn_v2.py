import json
import logging
import sys
import os

sys.path.append('.')
from chatbot.security_chatbot import SecurityChatbot

logging.basicConfig(level=logging.INFO)

class MockAgent:
    def get_stats(self): return {}
    def get_recent_decisions(self, n): return []
    def get_whitelist(self): return []
    def get_incident_logger(self): return None

cb = SecurityChatbot(agent=MockAgent())
cb.enable()

print(f"Status: {cb.get_status()}")
print("Testing cloud chat...")
resp = cb.chat("Bonjour, quel est le score de risque moyen d'un scan de port ?")
print(f"Response: {resp}")
