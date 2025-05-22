import sqlite3
conn = sqlite3.connect('app.db')
c = conn.cursor()
c.execute('DROP TABLE IF EXISTS alembic_version')
conn.commit()
conn.close() 