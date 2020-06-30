module MySQLClient

import Sockets
import SHA

const CLIENT_PROTOCOL_41 = 0x0200
const CLIENT_SECURE_CONNECTION = 0x8000
const CLIENT_LONG_PASSWORD = 0x0004
const CLIENT_TRANSACTIONS = 0x2000
const CLIENT_LONG_FLAG = 0x0004
const CLIENT_PLUGIN_AUTH = 0x00080000

const Byte = UInt8

struct MySQLPacket
    payload_payload_length::Int
    sequence_id::Int
    payload::Vector{Byte}

    function MySQLPacket(header, payload)
        new(
            _little_endian_int(header[1:3]),
            Int(header[4]),
            payload
        )
    end
end
MySQLPacket(sock) = MySQLPacket(_read_packet(sock)...)

struct MySQLConnection end


function connect(host, username, password, port=3306)
    sock = Sockets.connect(host, port)

    function handshake()
        packet = MySQLPacket(sock)
        payload = IOBuffer(copy(packet.payload))

        # https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
        protocol_version = Int(read(payload, 1)[])

        mysql_server_version = String(readuntil(payload, 0x0))
        connection_id = _little_endian_int(read(payload, 4))
        auth_plugin_data_part1 = read(payload, 8)
        filter = read(payload, 1)
        capability_lower = read(payload, 2)
        charset = read(payload, 1)
        status = _little_endian_int(read(payload, 2))
        capability_upper = read(payload, 2)
        capability = reinterpret(UInt32, vcat(capability_lower, capability_upper))[]

        if capability & CLIENT_PLUGIN_AUTH > 0
            len_auth_plugin_data = Int(read(payload, 1)[])
            skip(payload, 10) # reserved

            if capability & CLIENT_SECURE_CONNECTION > 0
                auth_plugin_data_part2 = read(payload, max(13, len_auth_plugin_data - 8))
            end
            auth_plugin_name = String(readuntil(payload, 0x0))
        end


        # hankshake response packet
        #
        ## https://dev.mysql.com/doc/internals/en/secure-password-authentication.html#packet-Authentication::Native41
        # sha1(password) xor concat("20-bytes random data from server", sha1(sha1(password)))
        random_data = vcat(auth_plugin_data_part1, auth_plugin_data_part2)[1:20]
        auth_response = SHA.sha1(SHA.sha1(password))
        auth_response = vcat(random_data, auth_response)
        auth_response = SHA.sha1(auth_response)
        auth_response = xor.(SHA.sha1(password), auth_response)

        # header, capability flags, max-packet size, charset, reserved
        buffer_size = 4 + 4 + 4 + 1 + 23
        buffer_size += length(username) + 1 # 1 = null termination
        buffer_size += 1 # length of auth-response
        buffer_size += length(auth_response)
        buffer_size += length(auth_plugin_name) + 1 # 1 = null termination
        buffer = IOBuffer(maxsize=buffer_size)
        payload_size = buffer_size - 4

        # header
        write(buffer, reinterpret(Byte, [payload_size])[1:3])
        write(buffer, 0x01) # sequence_id 決め打ち

        # payload
        capability_flags = Int32(CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
                                  | CLIENT_LONG_PASSWORD | CLIENT_TRANSACTIONS
                                  | CLIENT_LONG_FLAG)
        write(buffer, reinterpret(Byte, [capability_flags])[1:4])
        write(buffer, zeros(Byte, 4)) # max packet size は 0 でいいので skip
        write(buffer, charset)
        write(buffer, zeros(Byte, 23)) # reserved
        write(buffer, transcode(Byte, username))
        write(buffer, 0x0)
        write(buffer, Byte(length(auth_response)))
        write(buffer, auth_response)
        write(buffer, transcode(Byte, auth_plugin_name))
        write(buffer, 0x0)

        write(sock, buffer.data)


        header, payload = _read_packet(sock)
        if (iszero(payload[1]))
            println("Welcome to the MySQL monitor")
            println("Your MySQL connection id is $(connection_id)")
            println("Server version: $(mysql_server_version)")
        else
            println("Connection failed")
        end
    end
    handshake()

    # return MySQLConnection(sock)
    return sock
end


function execute(sock, query)
    write(sock, _com_query(query))

    packet = MySQLPacket(sock)

    payload = copy(packet.payload)
    if payload[1] == 0x00
        println("OK")
        return
    end
    column_count, _ = _read_lenenc_int(payload)

    col_names = String[]
    while (true)
        packet = MySQLPacket(sock)
        payload = copy(packet.payload)
        if payload[1] == 0xfe
            break
        elseif payload[1] == 0x00
            error("Unsupported query result")
        else
            offset = 1
            catalog, len = _read_lenenc_str(payload[offset:end])
            offset += len
            schema, len = _read_lenenc_str(payload[offset:end])
            offset += len
            table, len = _read_lenenc_str(payload[offset:end])
            offset += len
            org_table, len = _read_lenenc_str(payload[offset:end])
            offset += len
            col_name, len = _read_lenenc_str(payload[offset:end])
            push!(col_names, col_name)
            offset += len
            org_name, len = _read_lenenc_str(payload[offset:end])
            offset += len
            offset += 1 # length of fixed length fields
            charset = _little_endian_int(payload[offset:offset+1])
            offset += 2
            column_length = _little_endian_int(payload[offset:offset+3])
            offset += 4
            column_type = payload[offset]
            offset += 1
            flags = _little_endian_int(payload[offset:offset+1])
            offset += 2
            decimals = payload[offset]
            offset += 1
        end
    end

    for col in col_names
        print("\t$(col)")
    end
    println()
    println("-"^30)

    while (true)
        packet = MySQLPacket(sock)
        payload = copy(packet.payload)
        if payload[1] == 0xfe
            break
        else
            offset = 1
            for i in 1:column_count
                value, len = _read_lenenc_str(payload[offset:end])
                offset += len
                print("\t$(value)")
            end
            println()
        end
    end
end

function query(conn::MySQLConnection) end

function _read_packet(sock)
    header = read(sock, 4)
    payload_size = _little_endian_int(header[1:3])
    payload = read(sock, payload_size)

    return header, payload
end

function _little_endian_int(arr::Vector{Byte})
    num = Int64(0)
    for (i, c) in enumerate(arr)
        num += Int64(c) << (8 * (i - 1))
    end
    return num
end

# https://dev.mysql.com/doc/internals/en/com-query.html
function _com_query(query)
    payload_size = length(query) + 1 # 1 = for command_id
    buffer = IOBuffer(maxsize=payload_size+4)
    write(buffer, reinterpret(UInt8, [payload_size])[1:3])
    write(buffer, 0x00) # sequence_id
    write(buffer, 0x03) # command_id
    write(buffer, transcode(UInt8, query))

    return buffer.data
end

function _read_lenenc_int(payload::Vector{Byte})
    io = IOBuffer(copy(payload))
    c = read(io, 1)[]
    offset = 1
    if c == 0xfb
        println("ERROR")
        return 0, offset
    elseif c == 0xfc
        result = _little_endian_int(read(io, 2))
        offset = 3
    elseif c == 0xfd
        result = _little_endian_int(read(io. 3))
        offset = 4
    elseif c == 0xfe
        result = _little_endian_int(read(io. 8))
        offset = 9
    elseif c == 0xff
        println("ERROR PACKET")
    else
        result = Int64(c)
    end

    return result, offset
end

function _read_lenenc_str(payload::Vector{Byte})
    payload = copy(payload)
    len, offset = _read_lenenc_int(payload)
    offset += 1

    result = payload[offset:offset+len-1]

    return String(result), offset + len - 1
end

end # module
