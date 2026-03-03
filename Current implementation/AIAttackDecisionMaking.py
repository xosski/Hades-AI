import numpy as np
import random

# Actions: Attack, Evade, Move, Sleep
ACTIONS = ["exploit", "lateral_move", "persist", "evade", "sleep"]
Q_TABLE = np.zeros((5, 5))  # AI learns from this table

def choose_action(state):
    if random.uniform(0, 1) < 0.2:  # 20% chance to explore
        return random.choice(ACTIONS)
    return ACTIONS[np.argmax(Q_TABLE[state])]

def update_q_table(state, action, reward):
    action_index = ACTIONS.index(action)
    Q_TABLE[state][action_index] = (1 - 0.1) * Q_TABLE[state][action_index] + 0.1 * reward

# Example Attack Decision Flow
current_state = 0  # Example: No security detected
action = choose_action(current_state)
print(f"AI Decision: {action}")
update_q_table(current_state, action, 10)  # Example: AI rewards successful attack

