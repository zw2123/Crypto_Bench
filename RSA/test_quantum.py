'''
How does this work:
he script specifically simulates this for large key sizes like 2048 and 4096 bits to gauge how long it might take a quantum 
computer to break such encryption.

1. Constructs a quantum circuit tailored to perform Shor's algorithm. It initializes with a quantum Fourier transform (QFT) on 
   all qubits, which is a critical part of the algorithm for finding the periodicity in the function used by Shor's algorithm.

2. Calls create_shor_circuit to get the quantum circuit for the simulation. It runs the circuit on Aer's quantum simulator, 
   measuring performance across multiple shots to average the results. The function measures the circuit depth and execution time, 
   which provides insight into the computational effort required for quantum simulation of Shor's algorithm.

3. It assumes a constant time per iteration and calculates total time in years.  
'''
import argparse
import time
import json
import math
from qiskit import QuantumCircuit, transpile
from qiskit.circuit.library import QFT
from qiskit_aer import Aer

def create_shor_circuit(n_bits):
    """Create a quantum circuit for Shor's algorithm using the full capacity of 30 qubits."""
    max_qubits = 25  # Use the maximum qubits available
    qc = QuantumCircuit(max_qubits, max_qubits)  # Circuit with equal number of classical bits for measurement

    # Initial state preparation using Hadamard gates on all qubits
    qc.h(range(max_qubits))  # Apply Hadamard gate to all qubits to create superposition

    # Implement Quantum Fourier Transform on all qubits
    qc.append(QFT(max_qubits).inverse(), range(max_qubits))

    # Measurement of all qubits
    qc.measure(range(max_qubits), range(max_qubits))
    return qc

def simulate_shor(n_bits):
    qc = create_shor_circuit(n_bits)
    simulator = Aer.get_backend('aer_simulator')
    
    num_shots = 10
    total_time = 0
    total_depth = 0

    for shot_number in range(1, num_shots + 1):
        print(f"Shot {shot_number} is running...")
        start_time = time.time()
        transpiled_circuit = transpile(qc, simulator)
        job = simulator.run(transpiled_circuit, shots=1)
        result = job.result()
        end_time = time.time()
        simulation_time = end_time - start_time
        total_time += simulation_time
        total_depth += transpiled_circuit.depth()

    average_time = total_time / num_shots
    average_depth = total_depth / num_shots
    log_iterations = (n_bits / 2) * math.log(2)

    estimated_break_time_years = estimate_break_time_years(log_iterations)

    print(f"Simulated with 30 qubits for RSA-{n_bits} bits.")
    print(f"Average quantum circuit depth: {average_depth}")
    print(f"Average simulation time per shot: {average_time:.2f} seconds")
    print(f"Estimated time to break RSA-{n_bits}: {estimated_break_time_years}")


def estimate_break_time_years(log_iterations):
    """ Calculate the estimated time to break RSA based on logarithm of iterations directly, avoiding overflow. """
    # Logarithm of the hypothetical time per iteration for future quantum computers (in seconds)
    log_future_time_per_iteration = math.log(1e-6)  # log of 1 microsecond per iteration

    # Calculate total log time in seconds using log properties to avoid overflow
    log_total_time_seconds = log_iterations + log_future_time_per_iteration

    # Convert log seconds to log years to avoid direct large number computations
    log_seconds_per_year = math.log(60 * 60 * 24 * 365)
    log_total_time_years = log_total_time_seconds - log_seconds_per_year

    # If you really need the direct year count, use a large number approximation if it's too large
    if log_total_time_years > 709:  # 709 is a safe value to avoid overflow in exp
        return "extremely large number of years (>1e+308)"
    else:
        total_time_years = math.exp(log_total_time_years)
        return f"{total_time_years:.2e} years"  # Format to scientific notation for readability




def main():
    parser = argparse.ArgumentParser(description="Simulate Shor's Algorithm impact on RSA.")
    parser.add_argument('key_size', type=int, choices=[2048, 4096], help='RSA key size to simulate')
    args = parser.parse_args()
    simulate_shor(args.key_size)

if __name__ == "__main__":
    main()