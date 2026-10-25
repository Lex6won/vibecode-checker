import subprocess
task = 'summarize'
subprocess.run(['claude', '-p', task, '--dangerously-skip-permissions'])
