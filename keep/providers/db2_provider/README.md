# IBM DB2 Provider

## Overview

The DB2 Provider enables Keep to interact with IBM DB2 databases for querying data, enriching alerts, and executing database operations within workflows.

## Features

- **Query Execution**: Execute SQL queries against DB2 databases
- **Data Enrichment**: Enrich alerts with data from DB2 tables
- **Write Operations**: Support for INSERT, UPDATE, DELETE operations
- **Parameter Substitution**: Support for dynamic query parameters

## Configuration

### Required Parameters

- `username`: DB2 database username
- `password`: DB2 database password (sensitive)
- `host`: DB2 server hostname
- `database`: DB2 database name

### Optional Parameters

- `port`: DB2 server port (default: 50000)
- `protocol`: Connection protocol (default: TCPIP)

## Usage Examples

### Basic Query

```yaml
steps:
  - name: query-db2
    provider:
      type: db2
      config: " {{ providers.db2-prod }} "
      with:
        query: "SELECT * FROM employees FETCH FIRST 10 ROWS ONLY"
```

### Query with Parameters

```yaml
steps:
  - name: query-with-params
    provider:
      type: db2
      config: " {{ providers.db2-prod }} "
      with:
        query: "SELECT * FROM employees WHERE department = '{dept}' AND salary > {min_salary}"
        dept: "IT"
        min_salary: 50000
```

### Query as Dictionary

```yaml
steps:
  - name: query-as-dict
    provider:
      type: db2
      config: " {{ providers.db2-prod }} "
      with:
        query: "SELECT id, name, email FROM users"
        as_dict: true
```


### Write Operation

```yaml
actions:
  - name: update-status
    provider:
      type: db2
      config: " {{ providers.db2-prod }} "
      with:
        query: "UPDATE alerts SET status = 'resolved' WHERE id = {alert_id}"
        alert_id: 12345
```

## Dependencies

The DB2 provider requires the `ibm_db` Python package, which is automatically included in Keep's dependencies.

## Connection String

The provider builds a DB2 connection string using the following format:

```
DATABASE={database};HOSTNAME={host};PORT={port};PROTOCOL={protocol};UID={username};PWD={password};
```

## Error Handling

- Connection errors are logged and returned in scope validation
- Query errors raise appropriate exceptions

## Best Practices

1. **Use FETCH FIRST**: DB2 syntax for limiting results: `FETCH FIRST n ROWS ONLY`
2. **Parameter Safety**: Use parameter substitution instead of string concatenation
3. **Connection Management**: Connections are automatically closed after each operation
4. **Schema Qualification**: Always qualify table names with schema: `SCHEMA.TABLE`

## Examples

See the example workflows in `examples/workflows/`:
- `create_alerts_from_db2.yml` - Sync alerts from DB2 to Keep
- `query_db2.yml` - Various DB2 query patterns

## Notes

- The provider uses `ibm_db` for low-level DB2 operations
- The provider uses `ibm_db_dbi` for Python DB-API 2.0 compatibility
- All queries are executed with automatic connection management
- Write operations are automatically committed