import mysql.connector

my_database = mysql.connector.connect(
    host='localhost', user='root', password='rohithk123')
my_cursor = my_database.cursor()
my_cursor.execute("set autocommit=1")
try:
    my_cursor.execute('create database USERS')
    my_cursor.execute('use USERS')