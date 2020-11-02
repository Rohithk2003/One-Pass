import mysql.connector


class Mysql:
    def __init__(self, host, user, password, database, table, db, cursor):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.table = table
        self.db = db
        self.cursor = cursor

    def connect(self):
        self.db = mysql.connector.connect(
            host=self.host, user=self.user, password=self.password
        )
        self.cursor = my_db.cursor()
        my_cursor.execute("set autocommit=1")

    def create(self):
        self.cursor.execute(
            "create database if not exists (%s) DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci",
            (self.database),
        )
        self.cursor.execute("use (%s)", (self.database))
        self.cursor.execute(
            "create table if not exists (%s) (username varchar(100) primary key , email_id varchar(100), password blob set character utf8 COLLATE utf8_general_c",
            (self.table),
        )
