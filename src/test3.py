#!/home/hiro/Projects/tcpsniff/bin/python3.5
import psycopg2

cars ={"make":"Honda", "model":"civic"}
try:
    conn=psycopg2.connect( "dbname='hiro' user='hiro' ")
except psycopg2.Error as e:
    print("I am unable to connect to the database.")
    print(e.pgerror)
cur = conn.cursor()
try:
    insert = """insert into cars (make, model, buyer)
                select %s, %s, personid from persons
                where lastname='Davis'"""
    values = [cars["make"], cars["model"]]
    cur.execute(insert, values)
    cur.connection.commit()
except psycopg2.Error as e:
    print(e.pgerror)
