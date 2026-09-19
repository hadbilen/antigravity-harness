---
name: database-migrations
description: "Database migration best practices for schema changes, data migrations, rollbacks, and zero-downtime deployments across PostgreSQL, MySQL, and common ORMs (Prisma, Drizzle, Kysely, Django, TypeORM, golang-migrate). Invoke when: writing or reviewing database schema migrations, column/index changes, zero-downtime migrations, or when user mentions 'migration', 'alter table', 'schema migration', 'database rollback'."
metadata:
  origin: ECC
---

# Database Migration Patterns & Zero-Downtime Playbook

This skill enforces safe schema evolutions, rollback strategies, and zero-downtime migrations.

## When to Activate

- Creating or modifying database tables, columns, indexes, or constraints
- Writing data backfill migrations
- Planning database deployments under active production traffic
- Designing rollbacks for failed or reverted deployments

## Core Principles

1. **Backward Compatibility:** Every migration must be deployable before the new application code without breaking existing running instances.
2. **Non-Blocking Execution:** Avoid long-held table locks (`ACCESS EXCLUSIVE`) that cause request queues and outages.
3. **Reversible by Design:** Every schema change must have an explicit down/rollback strategy or documented forward-fix procedure.
4. **Idempotency:** Migrations must succeed cleanly if retried or re-executed where supported (`IF EXISTS`, `IF NOT EXISTS`).

---

## PostgreSQL Zero-Downtime Patterns

### 1. Adding Columns Safely
```sql
-- SAFE (PostgreSQL 11+): Fast metadata-only change
ALTER TABLE users ADD COLUMN bio TEXT DEFAULT '' NOT NULL;

-- CAUTION (< PG 11): Volatile default functions (e.g. random()) rewrite the entire table.
-- Pattern: Add nullable column -> backfill -> add NOT NULL constraint.
```

### 2. Creating Indexes Without Downtime
```sql
-- ALWAYS use CONCURRENTLY on production tables to prevent write-blocking locks:
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email ON users (email);

-- NOTE: CONCURRENTLY cannot execute inside a transaction block.
-- Ensure ORM / migration runner executes this outside the default transaction.
```

### 3. Renaming Columns (Expand-Contract Pattern)
Never rename columns in-place in production. Follow the four-step expand-contract cycle:
1. **Expand:** Add new column as nullable (`ALTER TABLE users ADD COLUMN display_name TEXT;`).
2. **Backfill & Dual-Write:** Backfill historical data in batches. Update application to write to both columns, read from old (fallback to new).
3. **Switch Read:** Deploy application reading from new column, writing to new column.
4. **Contract:** Drop old column after verifying all instances are updated (`ALTER TABLE users DROP COLUMN username;`).

### 4. Batched Data Migrations (Prevent Table Locks)
```sql
-- Batch updates to prevent holding exclusive row locks or filling WAL:
DO $$
DECLARE
  batch_size INT := 5000;
  rows_updated INT;
BEGIN
  LOOP
    UPDATE users
    SET normalized_email = LOWER(email)
    WHERE id IN (
      SELECT id FROM users
      WHERE normalized_email IS NULL
      LIMIT batch_size
      FOR UPDATE SKIP LOCKED
    );
    GET DIAGNOSTICS rows_updated = ROW_COUNT;
    EXIT WHEN rows_updated = 0;
    COMMIT;
  END LOOP;
END $$;
```

---

## Migration Tooling Quick Reference & Gotchas

* **Prisma:**
  * Cannot generate `CONCURRENTLY` automatically. Use `npx prisma migrate dev --create-only` and add `CONCURRENTLY` manually.
  * Production deploy: `npx prisma migrate deploy`
* **Drizzle:**
  * Generate: `npx drizzle-kit generate`
  * Migrate: `npx drizzle-kit migrate`
  * Do not run `push` in production; always use versioned migration files.
* **Kysely:**
  * Execute migrations programmatically via `Migrator` or CLI (`kysely-ctl`).
  * Ensure transactions are disabled when running concurrent index creations.
* **Django:**
  * Zero-downtime model rename: Use `SeparateDatabaseAndState` to decouple model state from physical schema drops.
  * Always check SQL generated with `python manage.py sqlmigrate <app> <migration_number>`.
* **golang-migrate:**
  * Keep reversible `.up.sql` and `.down.sql` pairs.
  * Resolve dirty state with `migrate force <version>` only after inspecting manual failures.

---

## Pre-Migration Safety Checklist

- [ ] Does adding this constraint/index require a table rewrite or exclusive lock?
- [ ] Are all new production indexes created `CONCURRENTLY`?
- [ ] Is new column addition backward-compatible with current production application instances?
- [ ] Has the rollback step been tested and verified locally?
- [ ] Are heavy data backfills decoupled into asynchronous batch jobs rather than synchronous DDL steps?
