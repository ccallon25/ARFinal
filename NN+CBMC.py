import os
import yaml
import time
from datetime import datetime
from tabulate import tabulate
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import subprocess

base_path = 'sv-benchmarks/c/floats-esbmc-regression'
model_name = "claudios/VulBERTa-MLP-Devign" #can change to other hugging face models
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

def run_cbmc_verification(yml_path, base_dir):
    full_yml_path = yml_path
    with open(full_yml_path, 'r') as f:
        meta = yaml.safe_load(f)
    c_file = os.path.join(base_dir, meta['input_files'])
    properties = [
        p for p in meta.get('properties', [])
        if 'expected_verdict' in p
    ]
    cbmc_flags = ['--unwind', '50', '--no-standard-checks']
    property_map = {
        'no-overflow': ['--signed-overflow-check', '--unsigned-overflow-check', '--div-by-zero-check'],
        'unreach-call': ['--unwinding-assertions', '--bounds-check'],
        'valid-deref': ['--pointer-check', '--bounds-check'],
        'valid-free': ['--pointer-check', '--memory-leak-check'],
        'valid-memtrack': ['--memory-leak-check', '--bounds-check'],
        'termination': ['--unwinding-assertions', '--bounds-check'],
        'memory-safety': ['--pointer-check', '--memory-leak-check', '--bounds-check', '--div-by-zero-check'],
        'coverage': ['--cover-assertions']
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
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
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
        cbmc_verdict = "UNKNOWN"
    if len(expected_verdicts) == 0:
        print("No expected verdicts specified, cannot compare.")
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

def run_model(code):
    inputs = tokenizer(
        code,
        padding='max_length',
        truncation=True,
        max_length=512,  #need to explicitly set this for simpler datasets
        return_tensors="pt"
    )
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probabilities = torch.softmax(logits, dim=1)
    vulnerability_score = probabilities[0][1].item()
    confidence = max(probabilities[0]).item()
    return {
        'vulnerability_score': vulnerability_score,
        'confidence': confidence
    }
def interpret_cbmc_result(cbmc_result, expected_verdict_str):
    if cbmc_result['cbmc_verdict'] == 'SUCCESS':
        return "true"  
    elif cbmc_result['cbmc_verdict'] == 'FAILURE':
        return "false"  
    else:
        return "unknown" 
    
c_files = [f for f in os.listdir(base_path) if f.endswith('.c')]
file_pairs = []
for c_file in c_files:
    base_name = os.path.splitext(c_file)[0]
    yml_file = base_name + '.yml'
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
            'yml': yml_data,
            'c_path': c_path,
            'yml_path': yml_path
        })
results = []
properties_analyzed = 0
properties_with_no_verdict = 0
nn_correct_predictions = 0
cbmc_correct_predictions = 0
combined_correct_predictions = 0
cbmc_runs = 0
for pair in file_pairs:
    base_name = pair['name']
    print(f"Analyzing {base_name}...")
    yml_data = pair['yml']
    properties = yml_data.get('properties', [])
    if not properties:
        print(f"No properties in YML for {base_name}")
        continue
    start_time = time.time()
    nn_result = run_model(pair['c_code'])
    nn_execution_time = time.time() - start_time
    for prop in properties:
        property_file = prop.get('property_file', 'unknown')
        property_name = os.path.basename(property_file)
        expected_verdict = prop.get('expected_verdict')
        if expected_verdict is None:
            print(f"⚠️ No expected verdict for property {property_name} in {base_name}")
            properties_with_no_verdict += 1
            continue
        properties_analyzed += 1    
        threshold = 0.8 #setting threshold
        predicted_verdict = "true" if nn_result['vulnerability_score'] <= threshold else "false"
        expected_verdict_str = "true" if expected_verdict else "false"
        nn_correct = predicted_verdict == expected_verdict_str
        if nn_correct:
            nn_correct_predictions += 1
            combined_correct_predictions += 1 
            cbmc_verdict = "NOT RUN"
            cbmc_predicted_verdict = "N/A"
            cbmc_match = "N/A"
            cbmc_time = "N/A"
            combined_verdict = predicted_verdict
        else:
            # Only run CBMC when NN prediction is wrong
            cbmc_runs += 1
            cbmc_result = run_cbmc_verification(pair['yml_path'], base_path)
            cbmc_verdict = cbmc_result['cbmc_verdict']
            cbmc_match = cbmc_result['match']
            cbmc_time = f"{cbmc_result['time']:.2f}s"
            cbmc_predicted_verdict = interpret_cbmc_result(cbmc_result, expected_verdict_str)
            cbmc_correct = cbmc_predicted_verdict == expected_verdict_str
            if cbmc_correct:
                cbmc_correct_predictions += 1
                combined_correct_predictions += 1 
            combined_verdict = cbmc_predicted_verdict if cbmc_predicted_verdict != "unknown" else predicted_verdict
        results.append([
            base_name,
            property_name,
            expected_verdict_str,
            predicted_verdict,
            f"{nn_result['vulnerability_score']:.4f}",
            f"{nn_result['confidence']:.4f}",
            f"{nn_execution_time:.2f}s",
            cbmc_verdict,
            cbmc_predicted_verdict,
            cbmc_time,
            combined_verdict,
            "✓" if combined_verdict == expected_verdict_str else "✗"
        ])
#create a table
results.sort(key=lambda x: (x[0], x[1]))
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_filename = f"Optimized_Verification_{timestamp}.txt"
headers = ["Benchmark", "Property", "Expected", "NN Verdict", 
           "Bug Score", "Model Confidence", "NN Time", 
           "CBMC Result", "CBMC Verdict", "CBMC Time",
           "Combined Verdict", "Combined Correct"]
table = tabulate(results, headers=headers, tablefmt="grid")
nn_accuracy = nn_correct_predictions / properties_analyzed if properties_analyzed else 0.0
cbmc_correction_rate = cbmc_correct_predictions / cbmc_runs if cbmc_runs else 0.0
combined_accuracy = combined_correct_predictions / properties_analyzed if properties_analyzed else 0.0
improvement = combined_accuracy - nn_accuracy
cbmc_savings = properties_analyzed - cbmc_runs
with open(report_filename, "w") as f:
    f.write(f"Optimized Verification Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    f.write(table)
    f.write(f"\n\nSummary:\n")
    f.write(f"Properties analyzed: {properties_analyzed}\n")
    f.write(f"Properties without verdict: {properties_with_no_verdict}\n")
    f.write(f"Neural Network accuracy: {nn_accuracy:.2%}\n")
    f.write(f"CBMC runs: {cbmc_runs} (only when NN was wrong)\n")
    f.write(f"CBMC correction rate: {cbmc_correction_rate:.2%} of wrong NN predictions\n")
    f.write(f"Combined accuracy: {combined_accuracy:.2%}\n")
    f.write(f"Improvement over NN: {improvement:.2%}\n")
    f.write(f"Computation saved: {cbmc_savings} CBMC runs avoided ({cbmc_savings/properties_analyzed:.2%} of total)\n")
print(f"\nSummary:")
print(f"Properties analyzed: {properties_analyzed}")
print(f"Properties without verdict: {properties_with_no_verdict}")
print(f"Neural Network accuracy: {nn_accuracy:.2%}")
print(f"CBMC runs: {cbmc_runs} (only when NN was wrong)")
print(f"CBMC correction rate: {cbmc_correction_rate:.2%} of wrong NN predictions")
print(f"Combined accuracy: {combined_accuracy:.2%}")
print(f"Improvement over NN: {improvement:.2%}")
print(f"Computation saved: {cbmc_savings} CBMC runs avoided ({cbmc_savings/properties_analyzed:.2%} of total)")
csv_filename = f"Optimized_Verification_{timestamp}.csv"
with open(csv_filename, "w") as f:
    f.write(",".join(headers) + "\n")
    for row in results:
        cleaned_row = [str(cell).replace(",", ";") for cell in row]
        f.write(",".join(cleaned_row) + "\n")