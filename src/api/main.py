# Ensure the command is constructed safely without using shell=True
command = ["ping", "-c", "4", safe_ip]
result = subprocess.run(
    command,
    capture_output=True,
    text=True,
)