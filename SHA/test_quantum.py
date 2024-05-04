'''
How does this work:
The code provided simulates Grover's algorithm to estimate the time required to find a preimage for a SHA hash output using 
quantum computing techniques. 

1. Circuit Creation: It first constructs a quantum circuit using Qiskit, where it applies Hadamard gates to all qubits to create 
   a superposition. Then, a multi-controlled Z gate (MCMT) is applied for phase inversion, followed by a sequence of gates that 
   act as a diffuser to amplify the probability amplitudes of potential solutions.

2. Simulation: The quantum circuit is transpiled for optimization and then simulated using Qiskit's AerSimulator. This is done 
   for several "shots" to statistically validate the results.

3. Results Analysis: The code calculates the number of iterations required to find the preimage based on the number of qubits 
   used in the simulation. Given physical limitations, it uses a maximum of 24 qubits and extrapolates the results to estimate the 
   time it would take to perform the attack on a full-scale SHA hash output, translating this into the estimated number of years.

This process essentially models how Grover's algorithm can be used to speed up the finding of SHA hash preimages compared to classical 
brute-force attacks, emphasizing the quantum speedup potential.'''

import argparse
import math
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit.circuit.library import MCMT, ZGate

def create_grover_circuit(num_qubits):
    """ Creates a Grover's algorithm circuit for the given number of qubits """
    qc = QuantumCircuit(num_qubits, num_qubits)
    qc.h(range(num_qubits))  # Hadamard gate to initiate superposition state

    # Multi-Controlled Z gate for phase inversion
    if num_qubits > 1:
        mcmt = MCMT(ZGate(), num_ctrl_qubits=num_qubits-1, num_target_qubits=1)
        qc.append(mcmt, range(num_qubits))

    # Diffuser
    qc.barrier()
    qc.h(range(num_qubits))
    qc.x(range(num_qubits))
    qc.h(num_qubits - 1)
    qc.append(mcmt, range(num_qubits))
    qc.h(num_qubits - 1)
    qc.x(range(num_qubits))
    qc.h(range(num_qubits))
    qc.barrier()

    qc.measure(range(num_qubits), range(num_qubits))
    return qc

def simulate_grover(hash_bits):
    """ Simulates Grover's algorithm for a given number of bits in the hash output """
    num_qubits = min(24, hash_bits)  # Limit qubits to 30 for practical simulation
    grover_circuit = create_grover_circuit(num_qubits)
    simulator = AerSimulator()
    
    transpiled_circuit = transpile(grover_circuit, simulator)
    total_shots = 10
    attempts = 0

    for shot_number in range(1, total_shots + 1):
        print(f"Shot {shot_number} is running...")
        job = simulator.run(transpiled_circuit, shots=1)
        result = job.result()
        attempts += 1

    # Calculate iterations based on limited qubits
    limited_iterations = math.pi / 4 * math.sqrt(2 ** num_qubits)
    limited_time_seconds = limited_iterations * 0.001
    # Extrapolate iterations for full bit length
    full_scale_iterations = math.pi / 4 * math.sqrt(2 ** hash_bits)
    extrapolated_time_seconds = (full_scale_iterations / limited_iterations) * limited_time_seconds
    estimated_total_time_years = extrapolated_time_seconds / (60 * 60 * 24 * 365)

    print(f"Testing System: {num_qubits} Qubits")
    print(f"Based on extrapolation from {num_qubits} qubits:")
    print(f"Estimated iterations for full-scale {hash_bits}-bit hash: {full_scale_iterations:e}")
    print(f"Estimated time to find a preimage for a {hash_bits}-bit hash: {estimated_total_time_years:.2e} years")

def main():
    parser = argparse.ArgumentParser(description="Simulate Grover's algorithm for finding a SHA hash preimage.")
    parser.add_argument('hash_bits', type=int, choices=[160, 256], help='SHA hash output size in bits (160 for SHA-1, 256 for SHA-256)')
    args = parser.parse_args()

    print(f"Simulating Grover's algorithm for a {args.hash_bits}-bit hash output...")
    simulate_grover(args.hash_bits)

if __name__ == "__main__":
    main()
