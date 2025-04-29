import os
import yaml
import subprocess
import time
from datetime import datetime
from tabulate import tabulate

base_path = 'Lemur-program-verification/lemur/benchmarks/sv_comp/c/'
c_files = [f for f in os.listdir(base_path) if f.endswith('.c')]
file_pairs = []
yml_files = []
for c_file in c_files:
    base_name = os.path.splitext(c_file)[0]
    yml_file = base_name + '.yml'
    yml_files.append(yml_file)
    yml_path = os.path.join(base_path, yml_file)
    c_path = os.path.join(base_path, c_file)
    if os.path.exists(yml_path):
        with open(c_path, 'r') as f:
            c_code = f.read()
        with open(yml_path, 'r') as f:
            yml_data = yaml.safe_load(f)
        file_pairs.append({
            'name': base_name,
            'c_code': c_code,
            'yml': yml_data
        })

def run_cbmc_verification(yml_path, base_dir):
    full_yml_path = os.path.join(base_dir, yml_path)
    with open(full_yml_path, 'r') as f:
        meta = yaml.safe_load(f)

    c_file = os.path.join(base_dir, meta['input_files'])
    properties = meta.get('properties', [])
    
    cbmc_flags = ['--unwind', '50', '--no-standard-checks','--unwinding-assertions']
    property_map = {
        'no-overflow': ['--signed-overflow-check', '--unsigned-overflow-check'],
        'unreach-call': [],
        'valid-deref': ['--pointer-check'],
        'valid-free': ['--pointer-check', '--memory-leak-check'],
        'valid-memtrack': ['--memory-leak-check'],
        'termination': ['function','main'],
        'memory-safety': ['--pointer-check', '--memory-leak-check', '--bounds-check'],
        'coverage': []  
    }

    found_properties = []
    for prop in properties:
        prop_file = prop['property_file']
        found_property = False
        for pattern, flags in property_map.items():
            if pattern in prop_file:
                found_property = True
                found_properties.append(pattern)
                for flag in flags:
                    if flag not in cbmc_flags:
                        cbmc_flags.append(flag)
                if pattern == 'coverage':
                    print(f"Skipping coverage properties (unsupported)")
                break
        if not found_property:
            print(f"Unknown property: {prop_file}")

    expected_verdicts = []
    for prop in properties:
        if 'expected_verdict' in prop:
            expected_verdicts.append({
                'property': prop['property_file'],
                'verdict': prop['expected_verdict']
            })

    cmd = ['cbmc', c_file] + cbmc_flags
    print(f"\nRunning: {' '.join(cmd)}")
    start_time = time.time()
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        output = result.stdout + '\n' + result.stderr
        execution_time = time.time() - start_time
    except subprocess.TimeoutExpired:
        execution_time = time.time() - start_time
        return {
            'cbmc_verdict': 'TIMEOUT',
            'expected_verdicts': expected_verdicts,
            'properties': found_properties,
            'time': execution_time,
            'match': False,
            'output': "CBMC timed out"
        }

    cbmc_success = "VERIFICATION SUCCESSFUL" in output
    cbmc_failure = "VERIFICATION FAILED" in output
    cbmc_verdict = None

    if cbmc_success:
        cbmc_verdict = "SUCCESS"
    elif cbmc_failure:
        cbmc_verdict = "FAILURE"
    else:
        print(f"Warning: CBMC output unclear for {c_file}")
        cbmc_verdict = "UNKNOWN"

    if len(expected_verdicts) == 0:
        match = "UNKNOWN"
    else:
        expected_overall = all(v['verdict'] for v in expected_verdicts)
        match = (cbmc_verdict == "SUCCESS") == expected_overall

    return {
        'cbmc_verdict': cbmc_verdict,
        'expected_verdicts': expected_verdicts,
        'properties': found_properties,
        'time': execution_time,
        'match': match,
        'output': output
    }


results = []
print(f"\n Verifying {len(yml_files)} benchmarks...\n")
matches = 0
mismatches = 0
timeouts = 0
for yml_path in yml_files:
    base_name = os.path.basename(yml_path).replace('.yml', '')
    print(f"Verifying {base_name}...")
    result = run_cbmc_verification(yml_path, base_path)
    expected_str = ", ".join([f"{os.path.basename(v['property'])}: {v['verdict']}" 
                             for v in result['expected_verdicts']]) if result['expected_verdicts'] else "N/A"
    properties_str = ", ".join(result['properties']) if result['properties'] else "N/A"
    if result['cbmc_verdict'] == 'TIMEOUT':
        match_str = "TIMEOUT"
        timeouts += 1
    elif result['match']:
        match_str = "MATCH"
        matches += 1
    else:
        match_str = "MISMATCH"
        mismatches += 1
        print(f"\n Mismatch for: {base_name}")
        print(f" Expected: {expected_str}")
        print(f" CBMC said: {result['cbmc_verdict']}")
    results.append([
        base_name,
        properties_str,
        expected_str,
        result['cbmc_verdict'],
        f"{result['time']:.2f}s",
        match_str
    ])
results.sort(key=lambda x: (0 if "MISMATCH" in x[5] else (1 if "TIMEOUT" in x[5] else 2), x[0]))
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_filename = f"verification_report_{timestamp}.txt"
headers = ["Benchmark", "Properties", "Expected Verdict", "CBMC Verdict", "Time", "Match Status"]
table = tabulate(results, headers=headers, tablefmt="grid")
with open(report_filename, "w") as f:
    f.write(f"CBMC Verification Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    f.write(table)
    f.write(f"\n\nSummary: {matches} matches, {mismatches} mismatches, {timeouts} timeouts\n")
print(f"\n Summary: {matches} matches, {mismatches} mismatches, {timeouts} timeouts")
csv_filename = f"verification_report_{timestamp}.csv"
with open(csv_filename, "w") as f:
    f.write(",".join(headers) + "\n")
    for row in results:
        cleaned_row = [str(cell).replace(",", ";") for cell in row]
        f.write(",".join(cleaned_row) + "\n")
