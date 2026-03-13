import sqlite3

c = sqlite3.connect(r".\data\ledger.db")
print("Tables:", c.execute("select name from sqlite_master where type='table'").fetchall())
print("Jobs:", c.execute("select count(*) from jobs").fetchone())
print("Baselines:", c.execute("select count(*) from baselines").fetchone())
c.close()