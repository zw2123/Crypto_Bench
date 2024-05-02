import argparse
import math
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit.circuit.library import MCMT, ZGate

def create_grover_circuit(num_qubits, target_state):
    qc = QuantumCircuit(num_qubits, num_qubits)
    qc.h(range(num_qubits))  # Hadamard gate to initiate superposition state

    # More complex Oracle with conditional operations
    for i in range(num_qubits // 2):
        qc.cx(i, num_qubits - i - 1)

    # Multi-Controlled Z gate for larger qubit systems
    if num_qubits > 1:
        mcmt = MCMT(ZGate(), num_ctrl_qubits=num_qubits-1, num_target_qubits=1)
        qc.append(mcmt, range(num_qubits))

    # Complex diffuser
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
    num_qubits = 24  # Increased number of qubits for more complex simulation
    target_state = format(0b11001100110011001100, f'0{num_qubits}b')
    grover_circuit = create_grover_circuit(num_qubits, target_state)
    simulator = AerSimulator()
    
    transpiled_circuit = transpile(grover_circuit, simulator)
    total_shots = 20
    for shot_number in range(1, total_shots + 1):
        print(f"Shot {shot_number} is running...")
        job = simulator.run(transpiled_circuit, shots=1)  # Run one shot at a time
        result = job.result()  # Obtain result for the current shot
        # Optionally, process the result here

    print("All shots completed.")
    
    iterations = int(math.pi / 4 * math.sqrt(2**num_qubits))
    estimated_time_seconds = iterations * 0.001
    full_scale_iterations = math.pi / 4 * math.sqrt(2 ** key_size)
    estimated_full_scale_time_seconds = full_scale_iterations * 0.001
    estimated_total_time_years = estimated_full_scale_time_seconds / (60 * 60 * 24 * 365)

    print(f"Testing System: {num_qubits} Qubits")
    print(f"Estimated iterations needed for a full-scale {key_size}-bit AES: {full_scale_iterations:e}")
    print(f"Estimated time to break AES-{key_size} CTR: {estimated_total_time_years:.2e} years")

def main():
    parser = argparse.ArgumentParser(description="Simulate Grover's algorithm for AES CTR key search.")
    parser.add_argument('key_size', type=int, choices=[128, 256], help='AES encryption key size')
    args = parser.parse_args()

    print(f"Simulating Grover's algorithm for AES-{args.key_size} CTR ...")
    simulate_grover(args.key_size)

if __name__ == "__main__":
    main()