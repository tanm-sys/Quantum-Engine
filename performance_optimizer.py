#!/usr/bin/env python3
"""
Created by Tanmay Patil
Copyright © 2025 Tanmay Patil. All rights reserved.

This module implements a UCB multi-armed bandit algorithm for algorithm selection.
It is optimized for low-end hardware by using minimal iterations and lightweight computations.
"""

import numpy as np
import time

algorithms = ["AES", "CHACHA20", "POSTQUANTUM", "TWOFISH", "CAMELLIA", "AESGCM", "RSAOAEP"]

counts = np.zeros(len(algorithms))
rewards = np.zeros(len(algorithms))

def measure_performance(algo):
    """
    Simulate performance measurement with a simple random function.
    Lower performance time yields a higher reward.
    """
    perf_time = np.random.uniform(0.8, 1.5)
    return 1.0 / perf_time

def run_optimization(iterations=10):
    global counts, rewards
    print("Running UCB-based optimization for algorithm selection...")
    for t in range(1, iterations + 1):
        ucb_values = np.zeros(len(algorithms))
        for i in range(len(algorithms)):
            if counts[i] == 0:
                ucb_values[i] = float('inf')
            else:
                average_reward = rewards[i] / counts[i]
                ucb_values[i] = average_reward + np.sqrt(2 * np.log(t) / counts[i])
        chosen_index = int(np.argmax(ucb_values))
        chosen_algo = algorithms[chosen_index]
        reward = measure_performance(chosen_algo)
        counts[chosen_index] += 1
        rewards[chosen_index] += reward
        print(f"Iteration {t}: Chose {chosen_algo}, Reward = {reward:.4f}")
        time.sleep(0.2)
    print("Optimization complete. Final counts and rewards:")
    for i, algo in enumerate(algorithms):
        print(f"{algo}: Count = {counts[i]}, Total Reward = {rewards[i]:.4f}")

if __name__ == "__main__":
    run_optimization()
