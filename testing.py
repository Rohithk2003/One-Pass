import mysql.connector
x = mysql.connector.connect(host='localhost',user='root',password='rohithk123')
y = x.cursor()
y.execute('use users')
y.execute("select no_of_accounts from data_input where username = (%s)",('1234',))

p = y.fetchall()
for i in p:
        print(i[0])