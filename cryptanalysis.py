#!/usr/bin/env python3
"""
Created by Tanmay Patil
Copyright © 2025 Tanmay Patil. All rights reserved.

This module simulates cryptanalysis using a lightweight genetic algorithm.
It uses vectorized NumPy operations to evolve candidate password guesses efficiently.
"""

import numpy as np
import time

def fitness_function(passwords):
    """
    Vectorized fitness function that simulates decryption error.
    Lower error indicates a better candidate.
    """
    # Convert each password string to a numerical value using the sum of character ordinals
    values = np.array([sum(map(ord, p)) for p in passwords])
    target = 1000  # Simulated target value
    errors = np.abs(values - target)
    return errors

def select_parents(passwords, errors, num_parents):
    """Select the best candidates (lowest error) as parents."""
    idx = np.argsort(errors)
    return [passwords[i] for i in idx[:num_parents]]

def crossover(parent1, parent2):
    """Simple crossover: combine halves from two parents."""
    pivot = len(parent1) // 2
    return parent1[:pivot] + parent2[pivot:]

def mutate(password, mutation_rate=0.1):
    """Mutate a password string by randomly changing characters."""
    password = list(password)
    for i in range(len(password)):
        if np.random.rand() < mutation_rate:
            password[i] = chr(np.random.randint(97, 123))  # a-z
    return "".join(password)

def run_simulation(generations=3, population_size=10, num_parents=5):
    print("Running cryptanalysis simulation using genetic algorithm...")
    population = ["".join(np.random.choice(list("abcdefghijklmnopqrstuvwxyz"), 8)) for _ in range(population_size)]
    for g in range(generations):
        errors = fitness_function(population)
        best_error = np.min(errors)
        print(f"Generation {g+1}: Best error = {best_error}")
        parents = select_parents(population, errors, num_parents)
        offspring = []
        while len(offspring) < population_size - num_parents:
            p1, p2 = np.random.choice(parents, 2, replace=False)
            child = crossover(p1, p2)
            child = mutate(child, mutation_rate=0.2)
            offspring.append(child)
        population = parents + offspring
        time.sleep(0.3)
    print("Cryptanalysis simulation complete.")
    print("Final population:", population)

if __name__ == "__main__":
    run_simulation()
