using MySQLClient
using Test

@testset "MySQLClient.jl" begin
    # Write your tests here.
    conn = MySQLClient.connect(host="127.0.0.1", username="root", password="test", port=3306)
    MySQLClient.execute(conn, "drop database if exists foo")
    MySQLClient.execute(conn, "create database foo")
    MySQLClient.execute(conn, "create table foo.bar (id int, name varchar(255))")
    MySQLClient.execute(conn, "insert into foo.bar values (1, 'hoge')")
    MySQLClient.execute(conn, "insert into foo.bar values (2, 'piyo')")

    query = "SELECT * FROM foo.bar"
    MySQLClient.execute(conn, query)

    MySQLClient.execute(conn, "do 1;")
    MySQLClient.execute(conn, "desc foo.bar")
end
