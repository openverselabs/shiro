<p align="center">
    <img src="https://i.ibb.co.com/hJng7rrj/shiro.png" alt="shiro" border="0">
</p>

<h1 align="center">Shiro</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go-blue.svg" alt="Language Go">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Release-v1.0.0-orange.svg" alt="Release">
</p>

Shiro is a high-concurrency, blazingly fast passive subdomain enumeration tool built in Go. Designed for bug hunters and security engineers, it rapidly aggregates subdomains from multiple public sources without actively interacting with the target infrastructure.

## Features

* High Concurrency: Leverages Go routines to fetch data from multiple APIs simultaneously.
* 8 Passive Sources: Integrates crt.sh, AlienVault, HackerTarget, JLDC, ThreatMiner, ThreatCrowd, URLScan, and Wayback Machine.
* Pipeline Ready: Seamlessly reads from stdin and streams output for easy chaining with other tools (e.g., httpx, nuclei).
* Real-Time Deduplication: Thread-safe map ensures subdomains are printed only once, saving processing time.
* Aggressive Optimization: Built with JSON streaming decoders, custom HTTP transports, and disabled keep-alives for maximum speed and minimal memory footprint.

## Installation

### One-Liner Install
You can easily install Shiro by running the following command in your terminal:

```bash
curl -sSL https://raw.githubusercontent.com/openverselabs/shiro/main/install.sh | bash

```

### Manual Build

Ensure you have Go installed on your system, then run:

```bash
git clone https://github.com/openverselabs/shiro.git
cd shiro
go build -ldflags="-s -w" -o shiro main.go
sudo mv shiro /usr/local/bin/

```

## Usage

Shiro can process a single domain, read from a file, or accept input via standard input (stdin).

**Single Domain Enumeration:**

```bash
shiro -d target.com

```

**Reading from a File and Saving Output:**

```bash
shiro -l targets.txt -o subdomains.txt

```

**Pipelining with Other Tools (Silent Mode):**

```bash
cat targets.txt | shiro -silent -t 5 | httpx -silent

```

## Flags

| Flag | Description | Default |
| --- | --- | --- |
| `-c` | Maximum concurrency for processing multiple domains | `10` |
| `-d` | Single target domain | `""` |
| `-l` | File containing a list of domains to check | `""` |
| `-o` | File to write the output to | `""` |
| `-silent` | Show only results in the output (hides the banner) | `false` |
| `-t` | API Timeout in seconds | `7` |

## License and Contributions

* **License**: Distributed under the MIT License.
* **Contributing**: Pull requests are welcome. For major changes, please open an issue first to discuss the proposed updates.
