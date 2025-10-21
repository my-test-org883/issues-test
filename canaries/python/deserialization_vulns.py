import pickle
import yaml
import json
from flask import Flask, request
import base64
import os

app = Flask(__name__)

# Deserialization vulnerability #1: pickle.loads
@app.route('/deserialize')
def deserialize_pickle():
    data = request.args.get('data')

    # Vulnerable: pickle.loads with user input
    if data:
        decoded_data = base64.b64decode(data)
        obj = pickle.loads(decoded_data)
        return f"Deserialized object: {obj}"

    return "No data provided"

# Deserialization vulnerability #2: yaml.load (unsafe)
@app.route('/load_config')
def load_yaml_config():
    config_data = request.form.get('config')

    # Vulnerable: yaml.load without safe_load
    if config_data:
        config = yaml.load(config_data)
        return f"Config loaded: {config}"

    return "No config provided"

# Deserialization vulnerability #3: exec with user input
@app.route('/execute')
def execute_code():
    code = request.args.get('code')

    # Vulnerable: exec with user input
    if code:
        result = {}
        exec(code, result)
        return f"Execution result: {result}"

    return "No code provided"

# Deserialization vulnerability #4: eval with user input
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')

    # Vulnerable: eval with user input
    if expression:
        result = eval(expression)
        return f"Result: {result}"

    return "No expression provided"

# Vulnerability #5: Loading pickle from file
def load_user_session(session_file):
    # Vulnerable: loading pickled data from file
    with open(session_file, 'rb') as f:
        session_data = pickle.load(f)
    return session_data

# Vulnerability #6: YAML with full_load (still unsafe)
def load_dangerous_yaml(yaml_content):
    # Vulnerable: full_load is still unsafe
    return yaml.full_load(yaml_content)

if __name__ == '__main__':
    app.run(debug=True)