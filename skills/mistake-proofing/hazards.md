# Hazards: the shapes that make mistakes available

Working vocabulary for the `mistake-proofing` skill, under its three ways of looking. For each shape: what it looks like, why it bites, and the device that closes it with the level it reaches (prevented, announced, found later). It is what the three questions usually turn up, not a list to run from top to bottom.

## Fit: can the wrong thing be passed?

| Shape | What it looks like | Why it bites | Device |
|---|---|---|---|
| Neighbouring parameters of one type | `transfer(source: str, target: str)`, `resize(w, h)`, `slice(start, end)` | Swapped arguments build, pass review and give a plausible wrong result | A distinct type per concept: prevented. Keyword-only arguments where types cannot help: the swap becomes visible at the call |
| Boolean that selects behaviour | `create_user(name, True, False)` | Unreadable at the call site; a second flag makes it worse | An enumeration or a named option per axis, or two functions: prevented. A single flag passed by keyword under a name that reads well is fine |
| A primitive at a boundary | `str` for an e-mail address, a path, a tenant id; `int` for a percentage | Every function below has to check again or trust; a check that returns true or false throws the proof away | Parse once into a type that can only be built by parsing: prevented |
| Closed set written as text | `status: str` with the values in a comment | A typo builds; a new value added elsewhere never reaches this code | An enumeration or literal union, matched exhaustively: prevented |
| Number without its unit | `timeout: int`, `distance: float` | A factor of a thousand is silent | A unit-carrying type: prevented. The unit in the name (`timeout_ms`) helps a reader and produces no diagnostic |
| Money as floating point | `price: float`, `==` on amounts | Rounding errors add up and the books stop reconciling | Integer minor units or a decimal type, in a type that carries its currency: prevented |
| External input used as it comes | A decoded request body, an environment variable, another service's response, used field by field | The failure shows far from the boundary, after the bad data was half processed or stored | A schema at every edge, the service's own responses included: prevented |
| A bag of optional fields | `{status, data?, error?, retry_at?}` | N optional fields claim 2^N states; each consumer guesses which are real | A tagged union with exactly the legal variants: prevented |
| Time without a zone, clock read in place | `datetime.now()` and `new Date()` inside business logic | Right on the developer's machine, wrong in production, wrong twice a year | Zone-aware types, UTC at rest, a clock passed in: prevented, and the code becomes testable at a boundary date |

## Completeness: can an incomplete or oversized set pass?

| Shape | What it looks like | Why it bites | Device |
|---|---|---|---|
| Branching that is not exhaustive | A `switch` or `match` over a closed set with a default that does nothing | A new variant silently takes the default at every site that should have changed | Exhaustiveness the compiler or type checker enforces (`assert_never`, a `never` arm, a match without a catch-all, a linter where the language has none): prevented |
| Destructive operation without a bound | A delete or update built from a filter that can be empty; `rm -rf "$VAR"`; a bulk send over a query result | Irreversible, and an empty filter often means everything | Refuse an empty predicate; require an explicit "all"; cap the count; dry run by default: prevented |
| A default that hides a decision | `retries=3`, `currency="USD"`, `tenant=None` | The caller never considers it, and the result is confidently wrong | Make it required; keep defaults for values that are right for nearly everyone and harmless for the rest: prevented |
| Configuration found missing at run time | An environment lookup inside a request handler | The service starts, reports healthy and fails on the one path that needs the key | Parse the whole configuration into a typed object at start and exit when something is missing: prevented |
| Several writes without a transaction | A write, an external call, another write | A failure in the middle leaves a state the code does not model | A transaction; external effects moved outside it (an outbox); an idempotent sequence: prevented for the transaction |
| Invariant kept only in application code | Uniqueness checked with a read before the insert; a nullability rule only in a model class | It races, and every other program that touches the data goes around it | The schema: `NOT NULL`, `UNIQUE`, `CHECK`, foreign keys. Prevented, for everything that touches the data |
| Input without a bound | Pagination without a maximum; an upload without a size limit; unbounded retries | Resource exhaustion by an ordinary user with a large account | A cap at the boundary, in the parsing type where possible: prevented |

## Order: can the steps happen wrongly?

| Shape | What it looks like | Why it bites | Device |
|---|---|---|---|
| A call that must come first | `init()`, `connect()`, "call X before Y" in the documentation | Nothing enforces it; the result is a half-configured object | A constructor or factory that returns a ready object, or a type per state so that the later methods exist only on the ready one: prevented |
| A retried effect that is not idempotent | A charge, an e-mail or an external write reachable from a retry, a queue consumer or a button, without an idempotency key, or with an optional one | Delivery at least once is the norm; the duplicate is expensive and public | A required key, reserved in the same transaction as the effect, tied to the request's content, with the stored result returned to the second caller: prevented. A uniqueness constraint alone rejects the duplicate without telling the caller whether the first attempt worked |
| A state changed by assignment from many places | A `status` field written in several modules; a refund reachable before a charge | Each site has to know the whole state machine, and one does not | One transition function as the only way to a new state, or a type per state: prevented. A row-level `CHECK` sees one row's values, not where the row is coming from |
| A resource that has to be released | Separate `open` and `close`, `acquire` and `release`, with a return or an exception possible in between | The error path leaks, and shows under load | Scope-bound acquisition (`with`, `defer`, `using`, a callback that receives the resource): prevented |
| Check, then act | `if not exists(x): create(x)`; read, modify, write on a shared value | Right in every test, wrong under concurrency | Make it atomic: a uniqueness constraint with an upsert, a conditional update with the expected version, a lock: prevented |
| Asynchronous work nobody waits for | A promise not awaited, a task with no reference kept, a background write nobody joins | Errors vanish, and the process can exit before the work is done | A lint rule for floating promises and tasks, structured concurrency: announced |
| A migration that depends on deploy order | A column dropped or renamed in the same deploy as the code that stops using it | During the rollout old code runs against the new schema | Expand, migrate, contract over several deploys, with a check that keeps destructive schema changes apart from code changes: prevented by the check |

## Devices that were taken out

Treat these with more suspicion than a device that was never there: whoever wrote the code around them knew the failure was possible.

| Shape | What it looks like | Device |
|---|---|---|
| Swallowed error | An empty `catch`, `except: pass`, a logged error after which execution continues | Handle it or let it propagate; where absorbing is right, catch the one expected type and say why continuing is safe. Announced by a lint rule; a handler that logs and carries on passes that rule and needs a reader (`silent-failure-hunter`) |
| Silent coercion or fallback | `value or default` where zero or an empty string is legal; a parse wrapped in a handler that returns a default | An explicit parse with an error branch at the boundary: prevented |
| A switched-off check | A skip marker or focus marker without a reason | Report to the user; never delete or mutate existing tests without explicit user approval (`GEMINI.md` Rule 9). An unapproved skip marker blocks the `verify_invariants.py` gate |
| An escape from the type system | `any`, a double cast, a non-null assertion, `# type: ignore`, `unsafe` | Parse at the boundary instead; a lint rule with a short, justified exception list: announced |
| Mutable state shared by accident | A mutable default argument; a module-level dictionary used as a cache; class attributes used as instance state | A `None` default with construction inside; immutable value types; construction per request: announced by a lint rule for the default argument, prevented by immutable types |
