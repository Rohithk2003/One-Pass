import sqlite3
a = sqlite3.connect('users.db')
my_cursor = a.cursor()
my_cursor.execute('select email_id from data_input where username = (?)',('rohith',))
a = my_cursor.fetchall()
print(a)
