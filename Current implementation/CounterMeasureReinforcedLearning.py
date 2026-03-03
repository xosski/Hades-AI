import numpy as np
import random

ACTIONS = ["block", "rate_limit", "honeypot", "log", "ignore"]
Q_TABLE = np.zeros((5, 5))  # Reinforcement learning memory

def choose_defense(state):
    if random.uniform(0, 1) < 0.2:  # 20% chance to explore new defenses
        return random.choice(ACTIONS)
    return ACTIONS[np.argmax(Q_TABLE[state])]

def update_q_table(state, action, reward):
    action_index = ACTIONS.index(action)
    Q_TABLE[state][action_index] = (1 - 0.1) * Q_TABLE[state][action_index] + 0.1 * reward

# AI Defense Decision Flow
attack_intensity = random.randint(0, 4)  # Simulated attack severity
defense_action = choose_defense(attack_intensity)
print(f"🛡️ AI Defender deploying: {defense_action}")
update_q_table(attack_intensity, defense_action, 10)  # Reward for successful mitigation

