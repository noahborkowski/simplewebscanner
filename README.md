# simplewebscanner

A lightweight web security scanner written in Go. It crawls a target site,
checks for missing security headers, looks for login/admin pages, and tests
basic input fields for reflected XSS or SQL injection payloads.

## Building

```
go build -o scanner scanner.go
```

## Usage

```
./scanner -url https://target.com -depth 2 -workers 5 -o report.json
```

The `-o` option writes a JSON report of issues found.
