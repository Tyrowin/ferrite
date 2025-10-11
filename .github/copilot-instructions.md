# GitHub Copilot Instructions

## Project Overview
Ferrite is a fast, type-safe backend service built with Rust, Axum, and Diesel. It provides secure APIs for notes, bookmarks, and todos.

## Technology Stack
- **Language**: Rust
- **Web Framework**: Axum
- **Database ORM**: Diesel
- **Focus**: Type safety, performance, and security

## Coding Standards
- Follow the official Rust Style Guide (`https://doc.rust-lang.org/nightly/style-guide/`)
- Use `rustfmt` for code formatting
- Use `clippy` for linting and catching common mistakes
- Prefer idiomatic Rust patterns and practices
- Write comprehensive error handling using `Result` types
- Avoid using `unwrap()` in production code; prefer proper error handling

## Development Guidelines
- **Type Safety**: Leverage Rust's type system to catch errors at compile time
- **Error Handling**: Use `anyhow` or `thiserror` for application errors
- **Async/Await**: Use async/await patterns with Tokio runtime for Axum handlers
- **Database**: Use Diesel for type-safe database queries
- **Security**: 
  - Validate all user inputs
  - Use proper authentication and authorization
  - Sanitize data before database operations
  - Follow OWASP security best practices

## Code Organization
- Keep route handlers thin; move business logic to separate modules
- Use middleware for cross-cutting concerns (logging, auth, etc.)
- Organize code by feature/domain rather than technical layers
- Write unit tests alongside implementation code

## Testing
- Write unit tests for business logic
- Write integration tests for API endpoints
- Aim for meaningful test coverage, not just high percentages
- Use `cargo test` to run the test suite

## Documentation
- Write clear doc comments for public APIs using `///`
- Include examples in documentation where helpful
- Keep README.md up to date with setup and usage instructions

## Workflow
- Use feature branches with descriptive names
- Write clear, concise commit messages
- Ensure code compiles and tests pass before committing
- Run `cargo fmt` and `cargo clippy` before committing
