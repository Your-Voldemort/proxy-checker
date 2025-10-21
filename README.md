# Asynchronous Proxy Checker

A fast, modern, and asynchronous proxy checker and validator written in Python. This tool allows you to test a list of proxies from a file or standard input, checking for connectivity, latency, anonymity, and geolocation. It supports HTTP, HTTPS, SOCKS4, and SOCKS5 protocols and can output results in human-readable text, JSON, or CSV formats.

## Features

- **High-Speed & Asynchronous:** Built with `asyncio` and `aiohttp` for high-concurrency checking.
- **Multi-Protocol Support:** Validates HTTP, HTTPS, SOCKS4, and SOCKS5 proxies.
- **Comprehensive Validation:**
    - **Connectivity:** Checks if the proxy is online and reachable.
    - **Latency:** Measures the response time in milliseconds.
    - **Anonymity Level:** Detects if the proxy is Elite, Anonymous, or Transparent.
    - **Geolocation:** Looks up the proxy's country and city.
- **Flexible Input/Output:**
    - Read proxies from a file or pipe them via `stdin`.
    - Output results to the console or a file.
    - Choose between `text`, `json`, or `csv` formats.
- **Modern Codebase:** Fully type-hinted, modular, and easily extensible.

## Installation

You can install the proxy checker directly from PyPI.

```bash
pip install async-proxy-checker
```

Alternatively, for development, you can clone the repository and install the dependencies:

```bash
git clone https://github.com/example/proxy-checker.git
cd proxy-checker
pip install -r requirements.txt
```

## Usage

The tool can be run from the command line as `proxy-checker`.

### Basic Usage

Check proxies from the default `proxies.txt` file:

```bash
proxy-checker proxies.txt
```

### Reading from Standard Input

You can pipe proxies directly into the tool:

```bash
cat my_proxies.txt | proxy-checker
```

### Output Formats

**JSON Output**

```bash
proxy-checker proxies.txt --format json --output working_proxies.json
```

**CSV Output**

```bash
proxy-checker proxies.txt --format csv > working_proxies.csv
```

### Adjusting Concurrency and Timeout

Control the performance with concurrency and timeout settings:

```bash
# Run with 200 concurrent checks and a 5-second timeout
proxy-checker proxies.txt --concurrency 200 --timeout 5
```

### Verbose Logging

For debugging or more detailed insight into the process, use the `--verbose` flag:

```bash
proxy-checker proxies.txt --verbose
```

### Command-Line Arguments

```
usage: proxy-checker [-h] [-o OUTPUT] [-f {text,json,csv}] [-v] [-c CONCURRENCY] [-t TIMEOUT] [proxy_source]

Asynchronous Proxy Checker.

positional arguments:
  proxy_source          Path to the file containing proxies. If not provided, reads from stdin.

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Path to the output file. If not provided, writes to stdout.
  -f {text,json,csv}, --format {text,json,csv}
                        Output format. Defaults to 'text'.
  -v, --verbose         Enable verbose logging output.
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent checks. Defaults to 100.
  -t TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds. Defaults to 10.
```

## Proxy Formats

The tool supports the following proxy string formats:

- `HOST:PORT`
- `PROTOCOL://HOST:PORT`
- `PROTOCOL://USERNAME:PASSWORD@HOST:PORT`
- `HOST:PORT:USERNAME:PASSWORD`

## Contributing

Contributions are welcome! If you'd like to improve the project, please feel free to fork the repository and submit a pull request.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.