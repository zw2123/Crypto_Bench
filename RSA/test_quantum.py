import argparse
import time
import json
import math
from qiskit import QuantumCircuit, transpile
from qiskit.circuit.library import QFT
from qiskit_aer import Aer

def create_shor_circuit(n_bits):
    """Create a quantum circuit for Shor's algorithm using the full capacity of 30 qubits."""
    max_qubits = 27  # Use the maximum qubits available
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

    # Correctly computing the logarithm of iterations directly
    log_iterations = (n_bits / 2) * math.log(2)

    data = {
        'average_time': average_time,
        'average_depth': average_depth,
        'log_iterations': log_iterations
    }
    with open('simulation_data.json', 'w') as f:
        json.dump(data, f)

    log_estimated_break_time_years = estimate_break_time_years(log_iterations)

    print(f"Simulated with 30 qubits for RSA-{n_bits} bits.")
    print(f"Average quantum circuit depth: {average_depth}")
    print(f"Logarithm of the number of iterations (est.): {log_iterations:.2f}")
    print(f"Average simulation time per shot: {average_time:.2f} seconds")
    print(f"Log of estimated time to break RSA-{n_bits}: {log_estimated_break_time_years:.2e} years (log scale)")

def estimate_break_time_years(log_iterations):
    """ Calculate the estimated time to break RSA based on logarithm of iterations directly. """
    log_time_per_iteration = math.log(0.001)  # in seconds, take log of 0.001
    log_total_time_seconds = log_iterations + log_time_per_iteration
    log_total_time_years = log_total_time_seconds - math.log(60 * 60 * 24 * 365)

    return log_total_time_years  # Returning logarithm of the time in years

def main():
    parser = argparse.ArgumentParser(description="Simulate Shor's Algorithm impact on RSA.")
    parser.add_argument('key_size', type=int, choices=[2048, 4096], help='RSA key size to simulate')
    args = parser.parse_args()
    simulate_shor(args.key_size)

if __name__ == "__main__":
    main()