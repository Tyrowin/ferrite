# Ferrite

A fast, type-safe backend service built with Rust, Axum, and Diesel. Secure APIs for notes, bookmarks, and todos.

## Security Tooling

- **Dependency auditing**
  - Install the RustSec scanner once with `cargo install --locked cargo-audit`.
  - Run `cargo audit` from the repository root; the `audit.toml` in this project enforces database freshness and fails the build on advisory warnings.
  - If you must temporarily silence a specific advisory, add its `RUSTSEC-` identifier under `ids` in `audit.toml` along with a rationale.
- **Static analysis**
  - Run `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery -W clippy::future_not_send -W clippy::print_stdout -W clippy::print_stderr -W clippy::dbg_macro` before every commit.
  - The `clippy.toml` shipped with the repo bans `unwrap`/`expect`, unchecked indexing, direct process spawning, and `dbg!` usage to surface high-risk patterns early; the extra command-line flags elevate the broader pedantic and nursery lint groups.
