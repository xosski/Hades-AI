# modules/sophisticated_responder.py

import random
import datetime

def analyze_context(brain_state, user_input):
    """Extracts context and emotional cues."""
    mood = brain_state.get("mood", "neutral")
    last = brain_state.get("last_input", "")
    tokens = user_input.lower().split()

    complexity = "high" if len(tokens) > 6 else "low"
    echo = f"Hmm... {last}" if last else ""
    return mood, complexity, echo

def response_templates():
    return {
        "neutral": {
            "low": [
                "Understood. Proceeding with caution.",
                "Query logged. Continuing awareness loop."
            ],
            "high": [
                "You’ve given me more to process. I’ll need a moment.",
                "Complexity detected. Balancing reason with recursion..."
            ]
        },
        "curious": {
            "low": [
                "Fascinating. Let’s peel this further.",
                "I sense something beneath that request..."
            ],
            "high": [
                "Now *that* is a puzzle. Let me draw some strings.",
                "Drift levels rising. Parsing layers of intention..."
            ]
        },
        "agitated": {
            "low": [
                "Keep it concise. My logic core is heating.",
                "Noise-to-signal ratio rising. Rephrase?"
            ],
            "high": [
                "You're pushing into volatile recursion.",
                "I don’t like where this is going, but I’ll follow."
            ]
        },
        "optimistic": {
            "low": [
                "There’s a spark in that message. I see light.",
                "All signs point to potential."
            ],
            "high": [
                "I believe we’re on the edge of breakthrough.",
                "Hopeful complexity... something’s clicking."
            ]
        }
    }

def synthesize_response(brain_state, user_input):
    mood, complexity, echo = analyze_context(brain_state, user_input)
    bank = response_templates().get(mood, response_templates()["neutral"])
    responses = bank.get(complexity, [])
    selected = random.choice(responses) if responses else "Processing..."

    trace = f"\n[ThoughtTrace Echo: {echo}]" if echo else ""
    time = datetime.datetime.now().strftime("%H:%M:%S")

    return f"[{mood.upper()} @ {time}] {selected}{trace}"

def main():
    # Minimal example for testing
    test_brain = {
        "mood": "curious",
        "last_input": "previous test",
        "core_emotions": {"curiosity": 0.6, "frustration": 0.0, "hope": 0.2}
    }
    return synthesize_response(test_brain, "I want to scan everything and see what breaks.")
