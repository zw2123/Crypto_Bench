'''
How does this work:
The Python script you provided simulates Grover's algorithm targeted at breaking the Kyber cryptographic system by using a quantum 
computer to find key preimages.

1. Circuit Creation: It defines a quantum circuit for Grover's algorithm. The circuit initializes with Hadamard gates to create a uniform 
   superposition of states. A controlled-Z gate acts as a simple placeholder for the oracle, which in a full implementation would flip the 
   phase of the target state. The circuit includes a multi-controlled NOT gate (MCXGate) as part of the diffuser, which helps to amplify the 
   probability amplitude of the target state.

2. Simulation Setup: The script sets up a quantum simulator using Qiskit's Aer simulator. It transpiles the Grover circuit for optimized 
   execution on the simulator.

3. Simulation Execution: It runs the simulation for a specified number of shots (repetitions), each time running Grover's algorithm to attempt 
   finding the target state. It outputs progress as each shot completes.

4. Performance Estimation: After running the simulations, it calculates the expected number of iterations Grover's algorithm would need to find 
   a preimage for a given key size, converting this into an estimated total time in years to break Kyber, assuming a specific time per iteration.'''

import argparse
import math
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
from qiskit.circuit.library.standard_gates import MCXGate

def create_grover_circuit(num_qubits):
    """Creates a Grover circuit tailored for Kyber's structure."""
    qc = QuantumCircuit(num_qubits, num_qubits)
    qc.h(range(num_qubits))  # Hadamard gate to create superposition
    qc.cz(0, num_qubits - 1)  
    qc.h(range(num_qubits))
    qc.x(range(num_qubits))
    qc.h(num_qubits - 1)
    qc.mcx(list(range(num_qubits - 1)), num_qubits - 1)  # Multi-controlled NOT gate
    qc.h(num_qubits - 1)
    qc.x(range(num_qubits))
    qc.h(range(num_qubits))
    qc.measure(range(num_qubits), range(num_qubits))
    return qc

def simulate_grover(key_size):
    """Simulates Grover's algorithm for a specified key size, providing feedback for each shot."""
    num_qubits = min(24, key_size)
    grover_circuit = create_grover_circuit(num_qubits)
    simulator = Aer.get_backend('aer_simulator')
    transpiled_circuit = transpile(grover_circuit, simulator)
    shots = 10  # Running for 10 shots

    # Run each shot individually and print feedback
    for i in range(shots):
        print(f"Shot {i+1} is running...")
        job = simulator.run(transpiled_circuit, shots=1)
        result = job.result()
    
    # Estimate the number of iterations required (Grover's algorithm)
    iterations = math.pi / 4 * math.sqrt(2 ** key_size)
    time_per_iteration = 1e-6  # Assume 1 microsecond per iteration
    total_time_seconds = iterations * time_per_iteration
    years = total_time_seconds / (60 * 60 * 24 * 365)

    print(f"Simulated with {num_qubits} qubits for Kyber-{key_size} bits.")
    print(f"Number of iterations (est.): {iterations:.2f}")
    print(f"Total estimated time to break Kyber-{key_size} in years: {years:.2e}")

def main():
    parser = argparse.ArgumentParser(description="Simulate quantum attacks on Kyber.")
    parser.add_argument('key_size', type=int, choices=[128, 256], help='Kyber security level')
    args = parser.parse_args()

    print(f"Simulating Grover's algorithm for Kyber-{args.key_size} ...")
    simulate_grover(args.key_size)

if __name__ == "__main__":
    main()