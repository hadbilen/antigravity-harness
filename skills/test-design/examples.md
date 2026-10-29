# Test design: examples

Python is used for illustration; the rules are the same in every language.

## Behaviour through the interface

```python
# Coupled to the implementation: breaks on a refactor, says nothing about the result
def test_checkout_calls_payment_process(monkeypatch):
    calls = []
    monkeypatch.setattr(payment_service, "process", lambda total: calls.append(total))
    checkout(cart, method)
    assert calls == [cart.total]

# Observable behaviour at the seam
def test_user_can_check_out_with_a_valid_cart():
    cart = Cart()
    cart.add(product)
    assert checkout(cart, method).status == "confirmed"
```

## Verify through the interface, not around it

```python
# Bypasses the interface: passes while get_user is broken
def test_create_user_saves_a_row():
    create_user(name="Alice")
    assert db.query("SELECT * FROM users WHERE name = ?", ["Alice"]) is not None

# Through the interface
def test_created_user_can_be_retrieved():
    user = create_user(name="Alice")
    assert get_user(user.id).name == "Alice"
```

## Independent expected values

```python
# Tautology: the expected value is computed the way the code computes it
def test_total_sums_line_items():
    items = [{"price": 10}, {"price": 5}]
    assert calculate_total(items) == sum(item["price"] for item in items)

# Mirror assertion: the same builder produces both sides
def test_search_query():
    assert build_search_query(tag="urgent") == build_search_query(tag="urgent")

# A known literal
def test_total_sums_line_items():
    assert calculate_total([{"price": 10}, {"price": 5}]) == 15

# A table of literal cases
CASES = [("", 0), ("a", 1), ("a b", 2), ("  a   b  ", 2)]

def test_word_count():
    for text, expected in CASES:
        assert word_count(text) == expected, text
```

## Test the behaviour that depends on a decision, not the decision

```python
# Change detector: fails when the constant is retuned, never when retrying is broken
def test_max_retries():
    assert MAX_RETRIES == 5

# The behaviour that depends on it
def test_a_failing_call_is_retried_five_times_and_no_more():
    client = FailingClient()
    with pytest.raises(UpstreamError):
        fetch(client)
    assert client.attempts == 6  # the first call plus five retries
```

## The mock earns no assertions; never patch the code under test

```python
# Asserts on the stand-in: true while the stand-in is present, whatever the page does
def test_page_has_a_sidebar(monkeypatch):
    monkeypatch.setattr(page, "render_sidebar", lambda: "<sidebar-mock>")
    assert "<sidebar-mock>" in page.render()

# Replaces the function the change is about: the test cannot see a regression in it
def test_discount(monkeypatch):
    monkeypatch.setattr(pricing, "apply_discount", lambda total, code: 90)
    assert checkout_total(100, "TEN") == 90

# Real code; only the external rate service is replaced, with a complete response
def test_discount_is_applied_before_tax():
    rates = FixedRates({"TEN": Decimal("0.10")})
    assert checkout_total(Decimal("100"), "TEN", rates=rates) == Decimal("90")
```

## Mock the slow level, keep what the test depends on

```python
# The stand-in swallows the config write that duplicate detection reads
monkeypatch.setattr(catalog, "discover_and_cache", lambda: None)

# Only the slow server start is replaced; the config write stays real
monkeypatch.setattr(server_manager, "start", lambda: FakeServer())
```

## Confirm the red

```text
FAILED tests/test_slug.py::test_spaces_become_hyphens - AssertionError: 'hello world' != 'hello-world'
```

This is a red: the test ran to its assertion and the message is the expected one. These are not:

```text
ERROR tests/test_slug.py - ModuleNotFoundError: No module named 'slug'
ERROR tests/test_slug.py::test_spaces_become_hyphens - TypeError: slugify() takes 0 positional arguments
```

An import or signature error shows that the test cannot run yet, not that the behaviour is wrong. Make it run, then watch it fail on the assertion.
