import argparse
import math
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit.circuit.library import MCMT, ZGate

def create_grover_circuit(num_qubits, target_state):
    qc = QuantumCircuit(num_qubits, num_qubits)
    qc.h(range(num_qubits))  # Apply Hadamard gate to all qubits to initiate superposition state

    for i in range(num_qubits // 2):
        qc.cx(i, num_qubits - i - 1)

    # Multi-Controlled Z gate for phase inversion
    if num_qubits > 1:
        mcmt = MCMT(ZGate(), num_ctrl_qubits=num_qubits-1, num_target_qubits=1)
        qc.append(mcmt, range(num_qubits))

    # Amplitude amplification (diffuser)
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

def simulate_grover(key_size):
    num_qubits = 24  # Number of qubits is equal to the key size
    target_state = format(0b101010101010101010101010, f'0{num_qubits}b')
    grover_circuit = create_grover_circuit(num_qubits, target_state)
    simulator = AerSimulator()
    
    transpiled_circuit = transpile(grover_circuit, simulator)
    total_shots = 10
    for shot_number in range(1, total_shots + 1):
        print(f"Shot {shot_number} is running...")
        job = simulator.run(transpiled_circuit, shots=1)  # Run one shot at a time
        result = job.result()  # Obtain result for the current shot


    print("All shots completed.")
    
    iterations = int(math.pi / 4 * math.sqrt(2**num_qubits))
    estimated_time_seconds = iterations * 0.001
    full_scale_iterations = math.pi / 4 * math.sqrt(2 ** key_size)
    estimated_full_scale_time_seconds = full_scale_iterations * 0.001
    estimated_total_time_years = estimated_full_scale_time_seconds / (60 * 60 * 24 * 365)

    print(f"Testing System: {num_qubits} Qubits")
    print(f"Estimated iterations needed for a full-scale {key_size}-bit ChaCha20: {full_scale_iterations:e}")
    print(f"Estimated time to break ChaCha20-{key_size}: {estimated_total_time_years:.2e} years")

def main():
    parser = argparse.ArgumentParser(description="Simulate Grover's algorithm for ChaCha20 key search.")
    parser.add_argument('key_size', type=int, choices=[128, 256], help='ChaCha20 encryption key size')
    args = parser.parse_args()

    print(f"Simulating Grover's algorithm for ChaCha20-{args.key_size}...")
    simulate_grover(args.key_size)

if __name__ == "__main__":
    main()
