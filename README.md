# MySQLClient

[![Build Status](https://travis-ci.com/goropikari/MySQLClient.jl.svg?branch=master)](https://travis-ci.com/goropikari/MySQLClient.jl)
[![Build Status](https://ci.appveyor.com/api/projects/status/github/goropikari/MySQLClient.jl?svg=true)](https://ci.appveyor.com/project/goropikari/MySQLClient-jl)
[![Coverage](https://codecov.io/gh/goropikari/MySQLClient.jl/branch/master/graph/badge.svg)](https://codecov.io/gh/goropikari/MySQLClient.jl)

This is yet another mysql client written in pure Julialang.
This is a toy implementation to study [MySQL protocol](https://dev.mysql.com/doc/dev/mysql-server/8.0.12/PAGE_PROTOCOL.html).

Prepare environment
```bash
git clone --depth 1 https://github.com/goropikari/MySQLClient.jl.git
docker run --rm -e MYSQL_ROOT_PASSWORD=test -p 3306:3306 -d mysql:5.7
mysql -h 127.0.0.1 -uroot -ptest -e "CREATE DATABASE foo"
mysql -h 127.0.0.1 -uroot -ptest -e "CREATE TABLE foo.bar (id int, name varchar(10))"
mysql -h 127.0.0.1 -uroot -ptest -e "INSERT INTO foo.bar values (1, 'taro')"
mysql -h 127.0.0.1 -uroot -ptest -e "INSERT INTO foo.bar values (2, 'hanako')"
```

```
cd MySQLClient.jl
./client
 Activating environment at `~/workspace/MySQLClient.jl/Project.toml`
host: localhost
username: root
password:
port: 3306
Welcome to the MySQL monitor
Your MySQL connection id is 27
Server version: 5.7.30


mysql: select * from foo.bar
	id	name
------------------------------
	1	taro
	2	hanako
```
