# PostgreSQL Tab Completion in Authly

Tab completion is now enabled in the psql shell. Here's how to use it:

## Interactive Usage

When you enter the container and run `psql`, tab completion works for:

### SQL Commands
- Type `SEL` and press TAB → completes to `SELECT`
- Type `INS` and press TAB → completes to `INSERT`
- Type `UPD` and press TAB → completes to `UPDATE`
- Type `DEL` and press TAB → completes to `DELETE`

### Table Names
- Type `SELECT * FROM oa` and press TAB → shows oauth_ tables
- Type `SELECT * FROM oauth_c` and press TAB → completes to oauth_clients
- Type `\d us` and press TAB → completes to `\d users`

### Column Names
After typing a table name:
- Type `SELECT ` then press TAB → shows column names
- Type `SELECT user` and press TAB → shows columns starting with "user"

### Common Patterns
- `\d` + TAB → shows all tables
- `\dt oa` + TAB → shows tables starting with "oa"
- `\di` + TAB → shows all indexes
- `\df` + TAB → shows all functions

## Testing Tab Completion

To test if tab completion is working:

```bash
# Enter the container
docker exec -it authly-test bash

# Start psql
authly> psql

# In psql, try these:
authly=# SEL[TAB]           # Should complete to SELECT
authly=# \dt oa[TAB]         # Should show oauth_ tables  
authly=# SELECT * FROM us[TAB]  # Should complete to users
authly=# :ta[TAB]            # Should complete to :tables
```

## Features Enabled

✅ **SQL keyword completion** - All SQL commands
✅ **Table name completion** - All tables in the database
✅ **Column name completion** - After FROM clause
✅ **Function completion** - Built-in PostgreSQL functions
✅ **Schema completion** - Schema names
✅ **Shortcut completion** - Custom shortcuts like `:tables`, `:stats`

## Notes

- Tab completion requires an interactive terminal (use `docker exec -it`)
- Completion is case-insensitive for keywords
- Custom shortcuts (`:tables`, `:stats`, etc.) also support tab completion
- Readline history is preserved between sessions in `~/.psql_history`