import random

PROFILE_CONFIG = {
    "low": {
        "chain_repeats": 1,
        "step_delay": 0.8,
        "noise_events": 12,
        "false_positive_rate": 0.03,
        "evasion_rate": 0.05,
    },
    "medium": {
        "chain_repeats": 2,
        "step_delay": 0.45,
        "noise_events": 24,
        "false_positive_rate": 0.06,
        "evasion_rate": 0.12,
    },
    "high": {
        "chain_repeats": 3,
        "step_delay": 0.25,
        "noise_events": 40,
        "false_positive_rate": 0.1,
        "evasion_rate": 0.2,
    },
}

DEFAULT_PROFILE = "medium"


def choose_profile(name: str):
    return PROFILE_CONFIG.get(name, PROFILE_CONFIG[DEFAULT_PROFILE])


def maybe(probability: float):
    return random.random() < max(0.0, min(1.0, probability))
