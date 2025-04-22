import os
import yaml
import time
from datetime import datetime
from tabulate import tabulate
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

base_path = 'Lemur-program-verification/lemur/benchmarks/sv_comp/c/'
model_name = "claudios/VulBERTa-MLP-Devign" #can change this to other hugging face models... maybe research a little more
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

def run_model(code):
    inputs = tokenizer(code, padding=True, truncation=True, return_tensors="pt")
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


c_files = [f for f in os.listdir(base_path) if f.endswith('.c')]
file_pairs = []
#this is essentially just matching teh c code with yml files
for c_file in c_files:
    base_name = os.path.splitext(c_file)[0]
    yml_file = base_name + '.yml'
    yml_path = os.path.join(base_path, yml_file)
    c_path = os.path.join(base_path, c_file)
    
    if os.path.exists(yml_path):
        # Read both files
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
#i.e. sometimes the yml file just has unreach: ...
properties_with_no_verdict = 0
correct_predictions = 0
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
    threshold = 0.5
    predicted_verdict = "true" if nn_result['vulnerability_score'] >= threshold else "false"
    execution_time = time.time() - start_time
    for prop in properties:
        property_file = prop.get('property_file', 'unknown')
        property_name = os.path.basename(property_file)
        expected_verdict = prop.get('expected_verdict')
        
        if expected_verdict is None:
            print(f"⚠️ No expected verdict for property {property_name} in {base_name}")
            properties_with_no_verdict += 1
            continue
        properties_analyzed += 1    
        threshold = 0.5
        predicted_verdict = "true" if nn_result['vulnerability_score'] >= threshold else "false"
        expected_verdict_str = "true" if expected_verdict else "false"
        if predicted_verdict == expected_verdict_str:
            correct_predictions += 1
        results.append([
            base_name,
            property_name,
            expected_verdict_str,
            predicted_verdict,
            f"{nn_result['vulnerability_score']:.4f}",
            f"{nn_result['confidence']:.4f}",
            f"{execution_time:.2f}s"
        ])

results.sort(key=lambda x: (x[0], x[1]))
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_filename = f"NN_bugs{timestamp}.txt"
headers = ["Benchmark", "Property", "Expected Verdict", "Predicted Verdict", 
           "Bug Confidence Score", "Model Confidence", "Analysis Time"]
table = tabulate(results, headers=headers, tablefmt="grid")
accuracy = correct_predictions / properties_analyzed if properties_analyzed else 0.0
with open(report_filename, "w") as f:
    f.write(f"Neural Network Property Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    f.write(table)
    f.write(f"\n\nSummary: {properties_analyzed} properties analyzed, "
            f"{properties_with_no_verdict} properties without verdict, "
            f"accuracy = {accuracy:.2%}\n")
print(f"\nSummary: {properties_analyzed} properties analyzed, "
      f"{properties_with_no_verdict} properties without verdict, "
      f"accuracy = {accuracy:.2%}")
csv_filename = f"NN_bugs{timestamp}.csv"
with open(csv_filename, "w") as f:
    f.write(",".join(headers) + "\n")
    for row in results:
        cleaned_row = [str(cell).replace(",", ";") for cell in row]
        f.write(",".join(cleaned_row) + "\n")
