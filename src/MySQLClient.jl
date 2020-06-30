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

        # initial packet
        # payload = IOBuffer(
        #  [                    0x0a,0x35,0x2e,0x36,0x2e,0x32,0x30,0x00,0x01,0x00,0x00,0x00,
        #   0x21,0x4b,0x3a,0x7e,0x30,0x6f,0x61,0x78,0x00,0xff,0xf7,0x21,0x02,0x00,0x7f,0x80,
        #   0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x58,0x30,0x26,0x6a,0x64,
        #   0x3a,0x34,0x33,0x45,0x40,0x53,0x5e,0x00,0x6d,0x79,0x73,0x71,0x6c,0x5f,0x6e,0x61,
        #   0x74,0x69,0x76,0x65,0x5f,0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,0x00])

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
        write(buffer, reinterpret(UInt8, [payload_size])[1:3])
        write(buffer, 0x01) # sequence_id 決め打ち

        # payload
        capability_flags = Int32(CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
                                  | CLIENT_LONG_PASSWORD | CLIENT_TRANSACTIONS
                                  | CLIENT_LONG_FLAG)
        write(buffer, reinterpret(UInt8, [capability_flags])[1:4])
        write(buffer, zeros(UInt8, 4)) # max packet size は 0 でいいので skip
        write(buffer, charset)
        write(buffer, zeros(UInt8, 23)) # reserved
        write(buffer, transcode(UInt8, username))
        write(buffer, 0x0)
        write(buffer, UInt8(length(auth_response)))
        write(buffer, auth_response)
        write(buffer, transcode(UInt8, auth_plugin_name))
        write(buffer, 0x0)

        write(sock, buffer.data)


        header, payload = _read_packet(sock)
        if (iszero(payload[1]))
            println("OK")
        else
            println("Connection failed")
        end
    end
    handshake()

    # return MySQLConnection(sock)
    return sock
end

function query(conn::MySQLConnection) end

function _read_packet(sock)
    header = read(sock, 4)
    payload_size = _little_endian_int(header[1:3])
    payload = read(sock, payload_size)

    return header, payload
end

function _little_endian_int(arr::Vector{UInt8})
    num = Int64(0)
    for (i, c) in enumerate(arr)
        num += Int64(c) << (8 * (i - 1))
    end
    return num
end

end #module
