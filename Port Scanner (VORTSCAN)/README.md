# VORTSCAN

VORTSCAN is a Python TCP port scanner. It checks whether ports on a hostname
or IP address accept TCP connections.

## Requirements

- Python 3
- A terminal

Check that Python is installed:

```bash
python3 --version
```

## Running VORTSCAN

Open Terminal in the project directory and run the program:

### Interactive mode

Run the program without arguments:

```bash
python3 port.py
```

You will be prompted for the target, starting port, and ending port.

### Command-line mode

```bash
python3 port.py TARGET START_PORT END_PORT
```

For example, to scan ports 1 through 1024 on your local computer:

```bash
python3 port.py localhost 1 1024
```

To scan a website, use its hostname without `https://`, a path, or a trailing
slash:

```bash
python3 port.py example.com 1 1024
```

You can scan all TCP ports, with optional timeout and thread settings:

```bash
python3 port.py example.com 1 65535 --timeout 1 --threads 100
```

View all available options:

```bash
python3 port.py --help
```

## Cancelling a scan

Press (`Ctrl+C`) in the same Terminal window where the scan is
running. This sends an interrupt and stops the Python process.

If the terminal does not return immediately, press `Ctrl+C` once more. You can
then close the terminal or run another command.

## Permission and responsible use

Only scan systems that you own or have explicit permission to test. Port
scanning systems without authorization may violate laws, terms of service, or
network policies.
