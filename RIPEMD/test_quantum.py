import argparse
import math
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit.circuit.library import MCMT, ZGate

def create_grover_circuit(num_qubits, target_state):
    qc = QuantumCircuit(num_qubits, num_qubits)
    qc.h(range(num_qubits))  # Hadamard gate to create superposition state

    # where we assume the target state is known
    for i in range(num_qubits // 2):
        qc.cx(i, num_qubits - i - 1)

    if num_qubits > 1:
        mcmt = MCMT(ZGate(), num_ctrl_qubits=num_qubits-1, num_target_qubits=1)
        qc.append(mcmt, range(num_qubits))

    # Diffuser (inversion about the mean)
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
    num_qubits = 24  
    target_state = format(0b11001100110011001100, f'0{num_qubits}b')
    grover_circuit = create_grover_circuit(num_qubits, target_state)
    simulator = AerSimulator()
    
    transpiled_circuit = transpile(grover_circuit, simulator)
    total_shots = 10
    for shot_number in range(1, total_shots + 1):
        print(f"Shot {shot_number} is running...")
        job = simulator.run(transpiled_circuit, shots=1)  # Single shot to mimic actual quantum measurements
        result = job.result()  # Get result

    print("All shots completed.")
    
    iterations = int(math.pi / 4 * math.sqrt(2**num_qubits))
    estimated_time_seconds = iterations * 0.001
    full_scale_iterations = math.pi / 4 * math.sqrt(2 ** key_size)
    estimated_full_scale_time_seconds = full_scale_iterations * 0.001
    estimated_total_time_years = estimated_full_scale_time_seconds / (60 * 60 * 24 * 365)

    print(f"Testing System: {num_qubits} Qubits")
    print(f"Estimated iterations needed for a full-scale {key_size}-bit RIPEMD-160: {full_scale_iterations:e}")
    print(f"Estimated time to find a collision in RIPEMD-160: {estimated_total_time_years:.2e} years")

def main():
    parser = argparse.ArgumentParser(description="Simulate Grover's algorithm for RIPEMD-160 hash collision search.")
    parser.add_argument('key_size', type=int, choices=[160], help='RIPEMD hash output size')
    args = parser.parse_args()

    print(f"Simulating Grover's algorithm for RIPEMD-{args.key_size}...")
    simulate_grover(args.key_size)

if __name__ == "__main__":
    main()
