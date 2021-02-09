from delete  import file
file.main("aes")
import mysql.connector as m
a = m.connect(host = 'localhost',user = 'root', passwd = 'rohithk123')
x = a.cursor()
x.execute('drop database users')

