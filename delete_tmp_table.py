import sqlite3

conn = sqlite3.connect('app.db')
cursor = conn.cursor()
try:
    cursor.execute('DROP TABLE IF EXISTS _alembic_tmp_user')
    print('Tablo silindi veya zaten yok.')
except Exception as e:
    print('Hata:', e)
conn.commit()
conn.close() 