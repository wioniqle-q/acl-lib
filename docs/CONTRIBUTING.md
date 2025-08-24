# Contributing to Acl.Fs

## How to Contribute

### Pull Requests

1. Fork the repository
2. Create a branch
3. Make your changes
4. Add tests for new functionality
6. Update documentation if needed
7. Commit with clear messages
8. Push and create a pull request

### Development Setup

```bash
# Clone the repository
git clone <repo-url>
cd acl-lib

# Restore dependencies
dotnet restore

# Build the solution
dotnet build

# Run tests
dotnet test
```

### Security Guidelines

- Never commit secrets or keys
- For security issues, please see [SECURITY.md](../SECURITY.md) for reporting guidelines

## Project Structure

- `src/` - Main library code
- `tests/` - Unit and integration tests  
- `samples/` - Example applications
- `docs/` - Documentation

## Questions?

Feel free to open an issue for questions about contributing.
