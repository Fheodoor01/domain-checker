# Domain Checker

A comprehensive PHP-based domain configuration validation tool that checks various DNS and email security configurations.

## Features

- **DNS Checks**
  - DNSSEC validation
  - MX record verification
  - Nameserver validation
  - Domain existence verification

- **Email Security**
  - SPF record validation
  - DMARC configuration check
  - DANE/TLSA record validation
  - TLS support verification
  - MTA-STS configuration check
  - BIMI record validation
  - TLS reporting configuration

## Requirements

- PHP 7.0 or higher
- `dig` command-line tool
- DNS resolution capabilities
- OpenSSL support in PHP

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/domain-checker.git
cd domain-checker
```

2. Ensure required PHP extensions are installed:
```bash
php -m | grep openssl
php -m | grep json
```

3. Verify dig is installed:
```bash
which dig
```

## Usage

### As a Command Line Tool
```bash
php check.php example.com
```

### As a Web Interface
1. Place the files in your web server directory
2. Access index.php through your web browser
3. Enter the domain name to check

## Security Considerations

- All user inputs are sanitized using `escapeshellarg()`
- Command execution is limited to specific DNS queries
- Buffer overflow protection implemented
- Timeouts set for external queries
- Error handling for all external calls

## Configuration

The tool supports the following checks (all enabled by default):
- DNSSEC
- SPF
- DMARC
- DANE
- TLS
- MTA-STS
- BIMI

## Output Format

The tool returns results in the following format:
```json
{
    "status": "good|bad|error",
    "message": "Detailed status message",
    "details": {
        "dnssec": {...},
        "dane": {...},
        "spf": {...},
        ...
    }
}
```

## Error Handling

- DNS resolution failures
- Command execution timeouts
- Invalid domain formats
- Missing required tools
- Network connectivity issues

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

APACHE

## Credits

Developed by Immutec BV/P.Verleye
