using MySQLClient
using Test

@testset "MySQLClient.jl" begin
    # Write your tests here.
    conn = MySQLClient.connect(host="127.0.0.1", username="root", password="test", port=3306)
    query = "SELECT * FROM foo.bar"
    MySQLClient.execute(conn, query)

    MySQLClient.execute(conn, "do 1;")
end
