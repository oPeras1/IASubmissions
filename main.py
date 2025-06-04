from flask import Flask, request, redirect, url_for, render_template, Response
import os
import subprocess
import threading
import uuid
import time
import glob
import json
import shutil
import ast

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

streams_lock = threading.Lock()
streams = {}

def append_stream(file_id, msg):
    with streams_lock:
        if file_id not in streams:
            streams[file_id] = []
        streams[file_id].append(msg)  # ← This should append to the list

app.config['MAX_CONTENT_LENGTH'] = 102400  # bytes

DANGEROUS_MODULES = {"os", "subprocess", "shutil", "socket", "requests"}
DANGEROUS_FUNCTIONS = {"eval", "exec", "compile", "open", "input"}

def is_script_safe(code):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False  # código inválido não é seguro
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in DANGEROUS_MODULES:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module in DANGEROUS_MODULES:
                return False
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_FUNCTIONS:
                return False
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in DANGEROUS_FUNCTIONS or node.func.attr in DANGEROUS_MODULES:
                    return False
    return True


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']

    # Ler conteúdo e verificar segurança
    content = file.read().decode('utf-8', errors='ignore')
    if not is_script_safe(content):
        return "❌ O ficheiro contém código potencialmente perigoso.", 400

    file.seek(0)

    file_id = str(uuid.uuid4())
    sandbox_dir = os.path.join("temp_runs", file_id)
    os.makedirs(sandbox_dir, exist_ok=True)

    script_path = os.path.join(sandbox_dir, "script.py")
    file.save(script_path)

    for dep in ["search.py", "utils.py"]:
        shutil.copy(os.path.join("dependencies", dep), sandbox_dir)

    streams[file_id] = []
    threading.Thread(target=run_tests, args=(file_id, script_path, sandbox_dir), daemon=True).start()

    return redirect(url_for('results', file_id=file_id))

@app.route('/results/<file_id>')
def results(file_id):
    return render_template('results.html', file_id=file_id)

@app.route('/stream/<file_id>')
def stream(file_id):
    def event_stream():
        last_index = 0
        while True:
            time.sleep(1)
            updates = streams.get(file_id, [])[last_index:]
            for update in updates:
                yield f"data: {update}\n\n"
            last_index += len(updates)
    return Response(event_stream(), content_type='text/event-stream')

def run_tests(file_id, script_path, sandbox_dir):
    try:
        with open("tests/timeouts.json", "r") as f:
            timeout_map = json.load(f)
    except Exception as e:
        streams[file_id].append(f"⚠️ Erro ao carregar timeouts.json: {e}")
        return

    test_files = sorted(glob.glob("tests/test*.txt"))
    if not test_files:
        streams[file_id].append("⚠️ Nenhum teste encontrado na pasta 'tests'.")
        return

    # Copiar as dependências já feitas na upload, então não precisa copiar aqui

    # Executar cada teste
    for input_path in test_files:
        test_name = os.path.basename(input_path).replace(".txt", "")
        output_path = input_path.replace(".txt", ".out")

        if not os.path.exists(output_path):
            streams[file_id].append(f"[{test_name}] ❌ Output esperado não encontrado: {output_path}")
            continue

        timeout = timeout_map.get(test_name, 2)

        streams[file_id].append(f"[{test_name}] Em execução com timeout={timeout}s...")

        try:
            with open(input_path, "r") as f:
                test_input = f.read()
            with open(output_path, "r") as f:
                expected_output = f.read()

            # Executa o script dentro da sandbox (sandbox_dir)
            proc = subprocess.run(
                ["python3", os.path.basename(script_path)],
                cwd=sandbox_dir,
                input=test_input,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                text=True,
                shell=False
            )

            real_out_file = os.path.join(sandbox_dir, f"real_out.txt")
            exp_out_file = os.path.join(sandbox_dir, f"exp_out.txt")

            with open(real_out_file, "w") as f:
                f.write(proc.stdout)
            with open(exp_out_file, "w") as f:
                f.write(expected_output)

            # Usa diff para comparar resultados
            start_time = time.perf_counter()
            diff_result = subprocess.run(
                ["diff", "--strip-trailing-cr", real_out_file, exp_out_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            elapsed = time.perf_counter() - start_time

            if diff_result.returncode == 0:
                streams[file_id].append(f"[{test_name}] ✅ PASSOU em {elapsed:.5f}s")
            else:
                streams[file_id].append(f"[{test_name}] ❌ FALHOU")
                streams[file_id].append("Diferença:")
                streams[file_id].extend(diff_result.stdout.splitlines())

            os.remove(real_out_file)
            os.remove(exp_out_file)

        except subprocess.TimeoutExpired:
            streams[file_id].append(f"[{test_name}] ⏱️ Timeout após {timeout}s")
        except Exception as e:
            streams[file_id].append(f"[{test_name}] 💥 Erro: {e}")

        time.sleep(0.5)

    streams[file_id].append("=== Testes Concluídos ===")

    # Limpar ficheiros temporários
    if os.path.exists(script_path):
        os.remove(script_path)

    if os.path.exists(sandbox_dir):
        shutil.rmtree(sandbox_dir)


if __name__ == "__main__":
    app.run(debug=True, port=5000)