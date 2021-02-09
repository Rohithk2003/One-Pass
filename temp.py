import mysql.connector as m
from delete import file
file.main("aes")
file.main("bin")

a = m.connect(host='localhost', user='root', passwd='rohithk123')
x = a.cursor()
x.execute('drop database if exists users')
