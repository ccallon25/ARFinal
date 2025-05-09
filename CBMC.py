import os
import yaml
import subprocess
import time
from datetime import datetime
from tabulate import tabulate
import shutil

# simpler benchmarks
#benchmark_dirs = [
    #'sv-benchmarks/c/floats-cbmc-regression',
    #'sv-benchmarks/c/bitvector-regression',
    #'sv-benchmarks/c/loop-simple',
    #'sv-benchmarks/c/floats-esbmc-regression'
#]
#harder
benchmark_dirs = [
    'Lemur-program-verification/lemur/benchmarks/sv_comp/c/'
]

def get_yml_files(directories):
    all_yml_files = []
    for directory in directories:
        if os.path.exists(directory) and os.path.isdir(directory):
            yml_files = [os.path.join(directory, f) for f in os.listdir(directory) if f.endswith('.yml')]
            all_yml_files.extend(yml_files)
            print(f"Found {len(yml_files)} benchmark YAML files in {directory}")
        else:
            print(f"Warning: Directory {directory} does not exist or is not accessible")
    
    return all_yml_files

def debug_yml_file(yml_path):
    #just extracting properties and verdicts of the .yml files
    try:
        with open(yml_path, 'r') as f:
            meta = yaml.safe_load(f)
        dir_path = os.path.dirname(yml_path)
        print(f"\nDebug info for {os.path.basename(yml_path)}:")
        print(f"From directory: {dir_path}")
        print(f"Input files: {meta.get('input_files', 'NOT FOUND')}")
        input_file = meta.get('input_files')
        if input_file:
            full_input_path = os.path.join(dir_path, input_file)
            if os.path.exists(full_input_path):
                print(f"Input file exists: {full_input_path}")
                file_size = os.path.getsize(full_input_path)
                print(f"File size: {file_size} bytes")
            else:
                print(f"Input file DOES NOT exist: {full_input_path}")
        properties = meta.get('properties', [])
        print(f"Properties: {len(properties)}")
        for i, prop in enumerate(properties):
            print(f"  Property {i+1}:")
            print(f"    File: {prop.get('property_file', 'NOT FOUND')}")
            if 'expected_verdict' in prop:
                print(f"    Expected verdict: {prop['expected_verdict']} (type: {type(prop['expected_verdict'])})")
            else:
                print(f"    No expected verdict found")
    except Exception as e:
        print(f"Error parsing {yml_path}: {str(e)}")

def run_cpachecker_verification(yml_path, cpachecker_path=None):
    
    dir_path = os.path.dirname(yml_path)
    #some debugging in case the fails to be loaded
    try:
        with open(yml_path, 'r') as f:
            meta = yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading YAML file {yml_path}: {str(e)}")
        return {
            'benchmark_dir': os.path.basename(dir_path),
            'cpa_verdict': 'ERROR',
            'expected_verdicts': [],
            'properties': [],
            'time': 0,
            'match': "ERROR",
            'output': f"Error loading YAML: {str(e)}",
            'additional_info': ''
        }
    input_file = meta.get('input_files')
    if not input_file:
        return {
            'benchmark_dir': os.path.basename(dir_path),
            'cpa_verdict': 'ERROR',
            'expected_verdicts': [],
            'properties': [],
            'time': 0,
            'match': "ERROR",
            'output': "No input file specified in YAML",
            'additional_info': ''
        }
    c_file = os.path.join(dir_path, input_file)
    if not os.path.exists(c_file):
        return {
            'benchmark_dir': os.path.basename(dir_path),
            'cpa_verdict': 'ERROR',
            'expected_verdicts': [],
            'properties': [],
            'time': 0,
            'match': "ERROR",
            'output': f"Input file not found: {c_file}",
            'additional_info': ''
        }
    #looking for cpachecker implementation
    if cpachecker_path is None:
        cpachecker_script = shutil.which('cpachecker')
        if cpachecker_script:
            cpachecker_path = os.path.dirname(os.path.dirname(cpachecker_script))
        else:
            search_paths = [
                os.path.join(os.getcwd(), "CPAchecker-2.2-unix"),
                os.path.join(os.path.dirname(os.getcwd()), "CPAchecker-2.2-unix"),
                "/opt/cpachecker",
                os.path.expanduser("~/CPAchecker-2.2-unix")
            ]
            for path in search_paths:
                if os.path.isdir(path):
                    cpachecker_path = path
                    break
            if cpachecker_path is None:
                return {
                    'benchmark_dir': os.path.basename(dir_path),
                    'cpa_verdict': 'ERROR',
                    'expected_verdicts': [],
                    'properties': [],
                    'time': 0,
                    'match': "ERROR",
                    'output': "CPAchecker not found",
                    'additional_info': ''
                }
    if os.path.isdir(cpachecker_path):
        cpa_launcher = os.path.join(cpachecker_path, "scripts", "cpa.sh")
        if not os.path.exists(cpa_launcher):
            cpa_launcher = os.path.join(cpachecker_path, "bin", "cpachecker")
    else:
        cpa_launcher = cpachecker_path
    properties = meta.get('properties', [])
    output_dir = os.path.join(os.getcwd(), "cpachecker_output")
    os.makedirs(output_dir, exist_ok=True)
    config_dir = os.path.join(cpachecker_path, "config")
    #mapping .yml properties to CPAchecker properties
    property_map = {
        'no-overflow': [os.path.join(config_dir, "default--overflow.properties")],
        'unreach-call': [os.path.join(config_dir, "default.properties")],
        'valid-deref': [os.path.join(config_dir, "predicateAnalysis-PredAbsRefiner-ABEl-UF.properties")],
        'valid-free': [os.path.join(config_dir, "predicateAnalysis-PredAbsRefiner-ABEl-UF.properties")],
        'valid-memtrack': [os.path.join(config_dir, "predicateAnalysis-PredAbsRefiner-ABEl-UF.properties")],
        'termination': [os.path.join(config_dir, "termination.properties")],
        'memory-safety': [os.path.join(config_dir, "predicateAnalysis-PredAbsRefiner-ABEl-UF.properties")],
        'coverage': [os.path.join(config_dir, "components/coverage-branches.properties")]
    }

    found_properties = []
    config_file = None
    spec_file = None
    for prop in properties:
        prop_file = prop.get('property_file', '')
        abs_prop_file = os.path.join(dir_path, prop_file)
        for pattern, config in property_map.items():
            if pattern in prop_file:
                found_properties.append(pattern)
                if config_file is None:
                    config_file = config[0]
                spec_file = abs_prop_file
                break
    if config_file is None:
        config_file = os.path.join(config_dir, "default.properties")
    expected_verdicts = []
    for prop in properties:
        raw_verdict = prop.get('expected_verdict')
        if raw_verdict is not None:
            if isinstance(raw_verdict, bool):
                bool_verdict = raw_verdict
            elif isinstance(raw_verdict, str):
                bool_verdict = raw_verdict.lower() == 'true'
            else:
                bool_verdict = bool(raw_verdict)
            expected_verdicts.append({
                'property': prop.get('property_file', 'unknown'),
                'raw_verdict': raw_verdict,
                'verdict': bool_verdict
            })
    cmd = [cpa_launcher, "-config", config_file]
    if spec_file:
        cmd.extend(["-spec", spec_file])
    cmd.extend(["-setprop", f"output.path={output_dir}", "-setprop", "analysis.timeLimit=900s", c_file])
    print(f"\nRunning: {' '.join(cmd)}")
    start_time = time.time()
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
        output = result.stdout + '\n' + result.stderr
        execution_time = time.time() - start_time
    except subprocess.TimeoutExpired:
        execution_time = time.time() - start_time
        return {
            'benchmark_dir': os.path.basename(dir_path),
            'cpa_verdict': 'TIMEOUT',
            'expected_verdicts': expected_verdicts,
            'properties': found_properties,
            'time': execution_time,
            'match': "TIMEOUT",
            'output': "CPAchecker timed out",
            'additional_info': ''
        }
    if "Verification result: TRUE" in output:
        cpa_verdict = "SUCCESS"
    elif "Verification result: FALSE" in output or "Error location(s) reached" in output:
        cpa_verdict = "FAILURE"
    else:
        cpa_verdict = "UNKNOWN"
        print(f"Warning: CPAchecker output unclear for {c_file}")
        print(f"Output snippet: {output[:200]}...")
    if len(expected_verdicts) == 0:
        match = "UNKNOWN"
    else:
        expected_overall = all(v['verdict'] for v in expected_verdicts)
        actual_success = cpa_verdict == "SUCCESS"
        match = actual_success == expected_overall

    return {
        'benchmark_dir': os.path.basename(dir_path),
        'cpa_verdict': cpa_verdict,
        'expected_verdicts': expected_verdicts,
        'properties': found_properties,
        'time': execution_time,
        'match': match,
        'output': output,
    }


def run_cbmc_verification(yml_path):
    #very similar to cpachecker but instead for cbmc
    dir_path = os.path.dirname(yml_path)
    try:
        with open(yml_path, 'r') as f:
            meta = yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading YAML file {yml_path}: {str(e)}")
        return {
            'benchmark_dir': os.path.basename(dir_path),
            'cbmc_verdict': 'ERROR',
            'expected_verdicts': [],
            'properties': [],
            'time': 0,
            'match': "ERROR",
            'output': f"Error loading YAML: {str(e)}"
        }
    input_file = meta.get('input_files')
    if not input_file:
        print(f"No input file specified in {yml_path}")
        return {
            'benchmark_dir': os.path.basename(dir_path),
            'cbmc_verdict': 'ERROR',
            'expected_verdicts': [],
            'properties': [],
            'time': 0,
            'match': "ERROR",
            'output': "No input file specified in YAML"
        }
    c_file = os.path.join(dir_path, input_file)
    if not os.path.exists(c_file):
        print(f"Input file does not exist: {c_file}")
        return {
            'benchmark_dir': os.path.basename(dir_path),
            'cbmc_verdict': 'ERROR',
            'expected_verdicts': [],
            'properties': [],
            'time': 0,
            'match': "ERROR",
            'output': f"Input file not found: {c_file}"
        }
    
    properties = meta.get('properties', [])
    
    # Determine the appropriate CBMC flags based on benchmark directory and file extension
    cbmc_flags = ['--unwind', '50', '--no-standard-checks', '--unwinding-assertions']
    #additional properties to check for float
    if 'float' in dir_path.lower():
        cbmc_flags.extend(['--float-div-by-zero-check', '--floatbv'])
    #additional properties to check for loops
    if 'loop' in dir_path.lower():
        cbmc_flags.extend(['--bounds-check', '--pointer-check'])
    property_map = {
        'no-overflow': ['--signed-overflow-check', '--unsigned-overflow-check'],
        'unreach-call': [],
        'valid-deref': ['--pointer-check'],
        'valid-free': ['--pointer-check', '--memory-leak-check'],
        'valid-memtrack': ['--memory-leak-check'],
        'termination': ['--function', 'main'],
        'memory-safety': ['--pointer-check', '--memory-leak-check', '--bounds-check'],
        'coverage': []  
    }
    found_properties = []
    for prop in properties:
        prop_file = prop.get('property_file', '')
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
        if not found_property and prop_file:
            print(f"Unknown property: {prop_file}")
    expected_verdicts = []
    for prop in properties:
        if 'expected_verdict' in prop:
            raw_verdict = prop['expected_verdict']
            if isinstance(raw_verdict, bool):
                bool_verdict = raw_verdict
            elif isinstance(raw_verdict, str):
                bool_verdict = raw_verdict.lower() == 'true'
            else:
                print(f"Warning: Unexpected verdict type: {type(raw_verdict)}")
                bool_verdict = bool(raw_verdict)   
            expected_verdicts.append({
                'property': prop.get('property_file', 'unknown'),
                'raw_verdict': raw_verdict,
                'verdict': bool_verdict
            })

    #actually run CBMC
    cmd = ['cbmc', c_file] + cbmc_flags
    print(f"\nRunning: {' '.join(cmd)}")
    start_time = time.time()
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        output = result.stdout + '\n' + result.stderr
        execution_time = time.time() - start_time
    except subprocess.TimeoutExpired:
        execution_time = time.time() - start_time
        return {
            'benchmark_dir': os.path.basename(dir_path),
            'cbmc_verdict': 'TIMEOUT',
            'expected_verdicts': expected_verdicts,
            'properties': found_properties,
            'time': execution_time,
            'match': "TIMEOUT",
            'output': "CBMC timed out"
        }
    cbmc_success = "VERIFICATION SUCCESSFUL" in output
    cbmc_failure = "VERIFICATION FAILED" in output
    if cbmc_success:
        cbmc_verdict = "SUCCESS"
    elif cbmc_failure:
        cbmc_verdict = "FAILURE"
    else:
        print(f"Warning: CBMC output unclear for {c_file}")
        print(f"Output snippet: {output[:200]}...")
        cbmc_verdict = "UNKNOWN"
    if len(expected_verdicts) == 0:
        match = "UNKNOWN" 
        print(f"No expected verdicts to compare against")
    else:
        expected_overall = all(v['verdict'] for v in expected_verdicts)
        actual_success = cbmc_verdict == "SUCCESS"
        if cbmc_verdict == "UNKNOWN":
            match = "UNKNOWN"
        else:
            match = actual_success == expected_overall
        print(f"Expected verdict(s): {', '.join([str(v['raw_verdict']) for v in expected_verdicts])}")
        print(f"Converted to: {expected_overall}")
        print(f"CBMC verdict: {cbmc_verdict}")
        print(f"Match: {match}")

    return {
        'benchmark_dir': os.path.basename(dir_path),
        'cbmc_verdict': cbmc_verdict,
        'expected_verdicts': expected_verdicts,
        'properties': found_properties,
        'time': execution_time,
        'match': match,
        'output': output
    }

yml_files = get_yml_files(benchmark_dirs)
if not yml_files:
    print("No benchmark YAML files found in the specified directories.")
    exit(1)
for i, yml_file in enumerate(yml_files[:5]):
    debug_yml_file(yml_file)
    if i >= 4: 
        print(f"\n({len(yml_files) - 5} more files not shown)")
        break
results = []
print(f"\nVerifying {len(yml_files)} benchmarks\n")
matches = 0
mismatches = 0
timeouts = 0
unknowns = 0
errors = 0
for yml_path in yml_files:
    base_name = os.path.basename(yml_path).replace('.yml', '')
    print(f"\nVerifying {base_name}...")
    result = run_cpachecker_verification(yml_path)
    expected_str = ", ".join([f"{os.path.basename(v['property'])}: {v['raw_verdict']}" 
                             for v in result['expected_verdicts']]) if result['expected_verdicts'] else "N/A"                  
    properties_str = ", ".join(result['properties']) if result['properties'] else "N/A"
    match_status = result['match']
    if match_status == "TIMEOUT":
        match_str = "TIMEOUT"
        timeouts += 1
    elif match_status == "UNKNOWN":
        match_str = "UNKNOWN"
        unknowns += 1
    elif match_status == "ERROR":
        match_str = "ERROR"
        errors += 1
    elif match_status:
        match_str = "MATCH"
        matches += 1
    else:
        match_str = "MISMATCH"
        mismatches += 1
        print(f"\n Mismatch for: {base_name}")
        print(f" Expected: {expected_str}")
        print(f" CPA said: {result['cpa_verdict']}")
    results.append([
        base_name,
        result['benchmark_dir'],
        properties_str,
        expected_str,
        result['cpa_verdict'],
        f"{result['time']:.2f}s",
        match_str
    ])
results.sort(key=lambda x: (
    0 if "ERROR" in x[6] else (
        1 if "MISMATCH" in x[6] else (
            2 if "UNKNOWN" in x[6] else (
                3 if "TIMEOUT" in x[6] else 4
            )
        )
    ), 
    x[1], 
    x[0] 
))

#creating a table
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_filename = f"verification_report_{timestamp}.txt"
headers = ["Benchmark", "Directory", "Properties", "Expected Verdict", "CPAChecker Verdict", "Time", "Match Status"]
table = tabulate(results, headers=headers, tablefmt="grid")
with open(report_filename, "w") as f:
    f.write(f"CBMC Verification Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    f.write(table)
    f.write(f"\n\nSummary: {matches} matches, {mismatches} mismatches, {timeouts} timeouts, {unknowns} unknowns, {errors} errors\n")
print(f"\nSummary")
print(f"{matches} matches, {mismatches} mismatches, {timeouts} timeouts, {unknowns} unknowns, {errors} errors")
print(f"Report saved to {report_filename}")
#creating a csv
csv_filename = f"verification_report_{timestamp}.csv"
with open(csv_filename, "w") as f:
    f.write(",".join(headers) + "\n")
    for row in results:
        cleaned_row = [str(cell).replace(",", ";") for cell in row]
        f.write(",".join(cleaned_row) + "\n")
print(f"CSV saved to {csv_filename}")
directory_stats = {}
for result in results:
    directory = result[1]
    status = result[6]
    if directory not in directory_stats:
        directory_stats[directory] = {
            'MATCH': 0, 'MISMATCH': 0, 'TIMEOUT': 0, 'UNKNOWN': 0, 'ERROR': 0, 'total': 0
        }
    directory_stats[directory][status] += 1
    directory_stats[directory]['total'] += 1
print("\nResults by Directory")
dir_table = []
for directory, stats in directory_stats.items():
    success_rate = (stats['MATCH'] / stats['total'] * 100) if stats['total'] > 0 else 0
    dir_table.append([
        directory,
        stats['total'],
        stats['MATCH'],
        stats['MISMATCH'],
        stats['TIMEOUT'],
        stats['UNKNOWN'],
        stats['ERROR'],
        f"{success_rate:.1f}%"
    ])
dir_headers = ["Directory", "Total", "Matches", "Mismatches", "Timeouts", "Unknowns", "Errors", "Success Rate"]
print(tabulate(dir_table, headers=dir_headers, tablefmt="grid"))
with open(report_filename, "a") as f:
    f.write("\n\n===== Results by Directory =====\n")
    f.write(tabulate(dir_table, headers=dir_headers, tablefmt="grid"))


