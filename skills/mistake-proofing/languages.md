# What each language can enforce

For the `mistake-proofing` skill. Before proposing a device, know what the language at hand can check, and what has to be in place for the check to count. A type annotation in a project whose type checker is not a required check is documentation, not a device.

## TypeScript and JavaScript

**What has to be in place:** `strict: true` and the type check as a required step (`tsc --noEmit` in the project's verification). `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes` catch real mistakes that `strict` leaves. In plain JavaScript none of the type-level devices exist; what remains is runtime parsing, lint rules and the database.

- **Distinct concepts:** typing is structural, so `type UserId = string` distinguishes nothing. A branded type (an intersection with a phantom, unique-symbol property) does, at no runtime cost. Pair its constructor with a check and it becomes a parse.
- **Parse at the boundary:** a schema library that validates and brands in one step, applied at every edge: request handlers, queue consumers, the environment, other services' responses, file reads. `JSON.parse` returns `any`.
- **Legal states only:** a discriminated union instead of optional fields; a field of one variant is not reachable until the code has narrowed to that variant.
- **Exhaustiveness:** a `default` arm that calls a function taking `never` breaks the build at every switch a new variant has to reach; the lint rule for switch exhaustiveness enforces it across the project.
- **Order:** a builder whose methods return a different type per completed step, with `this` typed on the method that needs all of them, makes the early call a compile error. A required idempotency key is a device; an optional one is a suggestion.
- **Lint rules that prevent mistakes** (as errors, not warnings): floating and misused promises, switch exhaustiveness, explicit `any` and the unsafe-assignment family, empty blocks, strict equality, focused tests.
- **Limits:** types are gone at run time, so anything that crosses a boundary needs a runtime schema; `as` is unchecked and belongs inside parse functions only; use after close cannot be prevented by types, only scoped: a `using` / `await using` declaration (TypeScript 5.2, `Symbol.dispose`) or a callback that receives the resource.

## Python

**What has to be in place:** a type checker in strict mode as a required check, and a linter at error level. Without the first, annotations are not enforced by anything.

- **Distinct concepts:** `NewType` separates two identifiers of the same shape for the checker at no runtime cost. It validates nothing.
- **Parse at the boundary:** a validating model at every edge (request bodies, queue messages, other services' responses, files), set to forbid unknown fields, so that a misspelt field is an error and not an ignored key. Freezing a model stops reassignment of its fields; a list or dictionary inside it is still mutable.
- **Keyword-only arguments** (`def f(*, source, target)`): the swap can no longer be written positionally. For more than two parameters, and always when two share a type.
- **Exhaustiveness:** `assert_never` in the last arm of a `match` or `if` chain over a `Literal` or an enumeration; the type checker reports the unhandled variant.
- **Configuration:** one settings object parsed at start, without defaults for values that have no safe default, passed down; no environment lookups inside handlers.
- **Value objects:** a frozen dataclass with slots and keyword-only fields: no mutation after validation, no attribute created by a typo, no positional swap.
- **Release:** every acquire and release pair as a context manager that re-raises.
- **Traps to look for every time:** a mutable default argument; a bare `except`; `assert` used for validation (removed under `-O`); `datetime.now()` without a zone; floating-point money; `is` on strings and numbers; a task created without keeping a reference.
- **Limits:** annotations are not enforced at run time; an untyped dependency brings `Any` back; monkey-patching means no encapsulation is absolute, so an invariant that must hold goes into the database.

## Go

Go leaves most compile-time expressiveness out on purpose. Say so when proposing a device: "prevented" is often not reachable, and a required linter or the database does the work.

- **Distinct concepts:** a defined type (`type UserID string`), never an alias (`type UserID = string`).
- **Options instead of flags:** functional options or an options struct; `time.Duration` instead of a bare number.
- **Order and release:** a constructor that returns a ready value and an error; `defer` right after the error check of the acquisition (`f, err := os.Open(p); if err != nil { return err }; defer f.Close()`): a `defer` placed before the check runs on a nil value.
- **Exhaustiveness and errors:** only through linters, as a required check: unchecked errors, non-exhaustive switches over typed constants, unclosed bodies and rows, dropped contexts.
- **Limits:** no exhaustive matching, no non-nullable references, no immutability, no typestate. Zero values are valid, so a struct with a missing field looks initialised. More invariants belong in the database and in required checks than in a language with a richer type system.

## Rust

The type system reaches "prevented" for more shapes than any other mainstream language.

- **Distinct concepts and parsing:** a newtype with a private field and a fallible constructor; holding the value is the proof.
- **Legal states only:** an enum whose variants carry exactly their data; a `match` without a wildcard arm in domain logic, so that a new variant breaks the build.
- **Order:** typestate with ownership: each transition consumes the old state, so a stale copy cannot be used.
- **Errors:** `#[must_use]`, and lints that deny `unwrap`, `panic!`, unchecked indexing and float comparison.
- **Limits:** `unsafe` and `unwrap` are the ways out, to be denied by lint with a stated reason per exception; a panic is "announced", not "prevented"; deserialised input still needs a schema; typestate has a real cost in ergonomics and is for dangerous sequences only.
