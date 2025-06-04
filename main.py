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
import sqlite3
from datetime import datetime
import resource
import redis
import pickle

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Redis connection for shared state across workers
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=False)

# Remove the in-memory streams dictionary and lock
# streams_lock = threading.Lock()  # Not needed anymore
# streams = {}  # Not needed anymore

def init_db():
    conn = sqlite3.connect('stats.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_name TEXT,
            status TEXT,
            execution_time REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def append_stream(file_id, msg):
    """Append message to Redis list for the given file_id"""
    key = f"stream:{file_id}"
    redis_client.lpush(key, msg)
    # Set expiration to clean up old data (24 hours)
    redis_client.expire(key, 86400)

def get_stream_messages(file_id, start_index=0):
    """Get messages from Redis list starting from start_index"""
    key = f"stream:{file_id}"
    # Get all messages and reverse to maintain chronological order
    messages = redis_client.lrange(key, 0, -1)
    messages.reverse()  # Redis LPUSH adds to front, so reverse for chronological order
    
    # Convert bytes to strings
    messages = [msg.decode('utf-8') for msg in messages]
    
    # Return messages from start_index onwards
    return messages[start_index:]

app.config['MAX_CONTENT_LENGTH'] = 102400  # bytes

DANGEROUS_MODULES = {"os", "subprocess", "shutil", "socket", "requests"}
DANGEROUS_FUNCTIONS = {"eval", "exec", "compile", "open", "input"}

def is_script_safe(code):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    
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
            elif isinstance(node, ast.Attribute):
                if node.func.attr in DANGEROUS_FUNCTIONS or node.func.attr in DANGEROUS_MODULES:
                    return False
    return True

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']

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

    # Initialize the stream in Redis
    append_stream(file_id, "Iniciando testes...")
    
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
            try:
                # Get new messages from Redis
                updates = get_stream_messages(file_id, last_index)
                for update in updates:
                    yield f"data: {update}\n\n"
                last_index += len(updates)
                
                # Check if tests are completed
                if updates and "=== Testes Concluídos ===" in updates:
                    break
                    
                time.sleep(1)  # Use time.sleep instead of gevent.sleep
            except Exception as e:
                yield f"data: Erro na stream: {str(e)}\n\n"
                break
    
    return Response(event_stream(), content_type='text/event-stream')

def limit_memory():
    mem_bytes = 10 * 1024 * 1024 * 1024  # 10 GB limit for user scripts
    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    # Also limit RSS (physical memory) if available
    try:
        resource.setrlimit(resource.RLIMIT_RSS, (mem_bytes, mem_bytes))
    except (AttributeError, OSError):
        pass  # RLIMIT_RSS not available on all systems

def run_tests(file_id, script_path, sandbox_dir):
    try:
        with open("tests/timeouts.json", "r") as f:
            timeout_map = json.load(f)
    except Exception as e:
        append_stream(file_id, f"⚠️ Erro ao carregar timeouts.json: {e}")
        return

    test_files = sorted(glob.glob("tests/test*.txt"))
    if not test_files:
        append_stream(file_id, "⚠️ Nenhum teste encontrado na pasta 'tests'.")
        return

    for input_path in test_files:
        test_name = os.path.basename(input_path).replace(".txt", "")
        output_path = input_path.replace(".txt", ".out")

        if not os.path.exists(output_path):
            append_stream(file_id, f"[{test_name}] ❌ Output esperado não encontrado: {output_path}")
            continue

        timeout = timeout_map.get(test_name, 60)
        append_stream(file_id, f"[{test_name}] Em execução com timeout={timeout}s...")

        try:
            with open(input_path, "r") as f:
                test_input = f.read()
            with open(output_path, "r") as f:
                expected_output = f.read()

            start_time = time.perf_counter()
            proc = subprocess.run(
                ["python3", os.path.basename(script_path)],
                cwd=sandbox_dir,
                input=test_input,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                text=True,
                shell=False,
                preexec_fn=limit_memory
            )
            elapsed = time.perf_counter() - start_time

            real_out_file = os.path.join(sandbox_dir, f"real_out.txt")
            exp_out_file = os.path.join(sandbox_dir, f"exp_out.txt")

            with open(real_out_file, "w") as f:
                f.write(proc.stdout)
            with open(exp_out_file, "w") as f:
                f.write(expected_output)

            diff_result = subprocess.run(
                ["/usr/bin/diff", "-w", "--strip-trailing-cr", real_out_file, exp_out_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            conn = sqlite3.connect('stats.db')
            cursor = conn.cursor()

            if diff_result.returncode == 0:
                append_stream(file_id, f"[{test_name}] ✅ PASSOU em {elapsed:.5f}s")
                cursor.execute("INSERT INTO test_results (test_name, status, execution_time) VALUES (?, ?, ?)",
                             (test_name, 'PASSED', elapsed))
            else:
                append_stream(file_id, f"[{test_name}] ❌ FALHOU")
                append_stream(file_id, "Diferença:")
                for line in diff_result.stdout.splitlines():
                    append_stream(file_id, line)
                cursor.execute("INSERT INTO test_results (test_name, status, execution_time) VALUES (?, ?, ?)",
                             (test_name, 'FAILED', elapsed))

            conn.commit()
            conn.close()

            os.remove(real_out_file)
            os.remove(exp_out_file)

        except subprocess.TimeoutExpired:
            append_stream(file_id, f"[{test_name}] ⏱️ Timeout após {timeout}s")

            conn = sqlite3.connect('stats.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO test_results (test_name, status, execution_time) VALUES (?, ?, ?)",
                         (test_name, 'TIMEOUT', timeout))
            conn.commit()
            conn.close()
        except Exception as e:
            append_stream(file_id, f"[{test_name}] 💥 Erro: {e}")

            conn = sqlite3.connect('stats.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO test_results (test_name, status, execution_time) VALUES (?, ?, ?)",
                         (test_name, 'ERROR', 0))
            conn.commit()
            conn.close()

        time.sleep(0.5)

    append_stream(file_id, "=== Testes Concluídos ===")

    # Cleanup
    if os.path.exists(script_path):
        os.remove(script_path)
    if os.path.exists(sandbox_dir):
        shutil.rmtree(sandbox_dir)

@app.route('/stats')
def stats():
    conn = sqlite3.connect('stats.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT status, COUNT(*) FROM test_results GROUP BY status")
    status_counts = dict(cursor.fetchall())
    
    cursor.execute("SELECT test_name, AVG(execution_time) FROM test_results WHERE status='PASSED' GROUP BY test_name")
    avg_times = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(DISTINCT timestamp) FROM test_results")
    total_submissions = cursor.fetchone()[0]
    
    conn.close()
    
    return render_template('stats.html', 
                         status_counts=status_counts,
                         avg_times=avg_times,
                         total_submissions=total_submissions)

if __name__ == "__main__":
    app.run(debug=True, port=5000)