module MySQLClient

import Sockets
import SHA

const CLIENT_LONG_PASSWORD = 0x00000001
const CLIENT_FOUND_ROWS = 0x00000002
const CLIENT_LONG_FLAG = 0x00000004
const CLIENT_CONNECT_WITH_DB = 0x00000008
const CLIENT_NO_SCHEMA = 0x00000010
const CLIENT_COMPRESS = 0x00000020
const CLIENT_ODBC = 0x00000040
const CLIENT_LOCAL_FILES = 0x00000080
const CLIENT_IGNORE_SPACE = 0x00000100
const CLIENT_PROTOCOL_41 = 0x00000200
const CLIENT_INTERACTIVE = 0x00000400
const CLIENT_SSL = 0x00000800
const CLIENT_IGNORE_SIGPIPE = 0x00001000
const CLIENT_TRANSACTIONS = 0x00002000
const CLIENT_RESERVED = 0x00004000
const CLIENT_SECURE_CONNECTION = 0x00008000
const CLIENT_MULTI_STATEMENTS = 0x00010000
const CLIENT_MULTI_RESULTS = 0x00020000
const CLIENT_PS_MULTI_RESULTS = 0x00040000
const CLIENT_PLUGIN_AUTH = 0x00080000
const CLIENT_CONNECT_ATTRS = 0x00100000
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
const CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 0x00400000
const CLIENT_SESSION_TRACK = 0x00800000
const CLIENT_DEPRECATE_EOF = 0x01000000

const SERVER_SESSION_STATE_CHANGED = 0x4000

const OK_PACKET_HEADER = 0x00
const ERROR_PACKET_HEADER = 0xff

const Byte = UInt8

struct MySQLPacket
    payload_length::Int
    sequence_id::Int
    payload::Vector{Byte}
end
MySQLPacket(header, payload) = MySQLPacket(_little_endian_int(header[1:3]), Int(header[4]), payload)

mutable struct MySQLConnection
    sock::Sockets.TCPSocket
    host::AbstractString
    port::Integer
    username::AbstractString
    password::AbstractString
    database::AbstractString
    protocol_version::Int
    server_version::VersionNumber
    character_set_uint8::Byte
    connection_id::Integer
    capability::UInt32
    sequence_id::Byte
    auth_plugin_name::String
    auth_plugin_data::Vector{Byte}
    ssl::Bool

    function MySQLConnection(;sock,
                             host,
                             port,
                             username,
                             password,
                             database,
                             protocol_version=-1,
                             server_version=v"0.0.0",
                             character_set_uint8=0x00,
                             connection_id=-1,
                             capability=UInt32(0),
                             sequence_id=0x01,
                             auth_plugin_name="",
                             auth_plugin_data=UInt8[],
                             ssl=false)
        conn = new()
        conn.sock = sock
        conn.host = host
        conn.port = port
        conn.username = username
        conn.password = password
        conn.database = database
        conn.protocol_version = protocol_version
        conn.server_version = server_version
        conn.character_set_uint8 = character_set_uint8
        conn.connection_id = connection_id
        conn.capability = capability
        conn.sequence_id = sequence_id
        conn.auth_plugin_name = auth_plugin_name
        conn.auth_plugin_data = auth_plugin_data
        conn.ssl = ssl

        return conn
    end
end

mutable struct MySQLStmt end
mutable struct MySQLResult end

Base.write(conn::MySQLConnection, x::Vector{Byte}) = write(conn.sock, x)
function Base.write(conn::MySQLConnection, packet::MySQLPacket)
    data = reinterpret(Byte, [packet.payload_length])[1:3]
    push!(data, Byte(packet.sequence_id))
    append!(data, packet.payload)
    write(conn, data)
end
Base.read(conn::MySQLConnection) = read(conn.sock)
Base.read(conn::MySQLConnection, x) = read(conn.sock, x)
Base.isopen(conn::MySQLConnection) = isopen(conn.sock)

function connect(;host="127.0.0.1", username, password="", port=3306, database="")
    sock = Sockets.connect(host, port)
    conn = MySQLConnection(sock=sock,
                           host=host,
                           port=port,
                           username=username,
                           password=password,
                           database=database)
    _handshake!(conn)

    return conn
end

function execute(conn::MySQLConnection, query)
    # https://dev.mysql.com/doc/internals/en/com-query.html
    write(conn.sock, _com_query(query))

    # https://dev.mysql.com/doc/internals/en/com-query-response.html
    packet = MySQLPacket(_read_packet(conn.sock)...)
    payload = copy(packet.payload)
    if payload[1] == OK_PACKET_HEADER
        _parse_ok_packet(payload, conn.capability)
        return
    elseif payload[1] == ERROR_PACKET_HEADER
        error_code, sql_state, error_message = _parse_error_packet(payload, conn.capability)
        error("$(error_code) ($(sql_state)) $(error_message)") # TODO: Make MySQLERROR
        return
    elseif payload[1] == 0xfb
        # TODO
        # GET_MORE_CLIENT_DATA
    end

    column_count, _ = _lenenc_int(payload)

    # schema information
    # https://dev.mysql.com/doc/internals/en/com-field-list-response.html
    col_names = String[]
    while (true)
        packet = MySQLPacket(_read_packet(conn.sock)...)
        payload = copy(packet.payload)
        if payload[1] == 0xfe
            # https://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
            break
        elseif payload[1] == 0x00
            error("Unsupported query result")
        else
            # https://dev.mysql.com/doc/internals/en/com-query-response.html#column-definition
            offset = 1
            catalog, _read = _lenenc_str(payload[offset:end]) # always `def`
            offset += _read
            schema, _read = _lenenc_str(payload[offset:end])
            offset += _read
            table, _read = _lenenc_str(payload[offset:end]) # virtual table-name
            offset += _read
            org_table, _read = _lenenc_str(payload[offset:end]) # physical table-name
            offset += _read
            col_name, _read = _lenenc_str(payload[offset:end]) # virtual column name
            push!(col_names, col_name)
            offset += _read
            org_name, _read = _lenenc_str(payload[offset:end]) # physical column name
            offset += _read
            offset += 1 # length of fixed length fields
            character_set = _little_endian_int(payload[offset:offset+1])
            offset += 2
            column_length = _little_endian_int(payload[offset:offset+3])
            offset += 4
            column_type = payload[offset]
            offset += 1
            flags = _little_endian_int(payload[offset:offset+1])
            offset += 2
            decimals = payload[offset]
            offset += 1
            # catalog, schema, table, org_table, col_name, org_name, character_set, column_length, column_type, flags, decimals
        end
    end

    for col in col_names
        print("\t$(col)")
    end
    println()
    println("-"^30)

    # row
    # https://dev.mysql.com/doc/internals/en/com-query-response.html#packet-ProtocolText::ResultsetRow
    while (true)
        packet = MySQLPacket(_read_packet(conn.sock)...)
        payload = copy(packet.payload)
        if payload[1] == 0xfe
            break
        else
            offset = 1
            for i in 1:column_count
                value, len = _lenenc_str(payload[offset:end])
                offset += len
                print("\t$(value)")
            end
            println()
        end
    end
end

####################
# Connection Phase
####################

# https://dev.mysql.com/doc/internals/en/initial-handshake.html
function _handshake!(conn::MySQLConnection)
    _parse_init_packet!(conn)
    response_packet, sequence_id = _make_handshake_response_packet(conn.username,
                                                        conn.password,
                                                        conn.auth_plugin_name,
                                                        conn.auth_plugin_data,
                                                        conn.sequence_id,
                                                        conn.character_set_uint8)
    conn.sequence_id = sequence_id
    write(conn, response_packet)
    header, payload = _read_packet(conn)
    iszero(payload[1]) || error("Connection failed")

    return nothing
end

# https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeV10
function _parse_init_packet!(conn::MySQLConnection)
    init_packet = MySQLPacket(_read_packet(conn)...)
    payload = IOBuffer(copy(init_packet.payload))

    # https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
    protocol_version = Int(read(payload, 1)[])

    conn.server_version = VersionNumber(String(readuntil(payload, 0x0)))
    conn.connection_id = _little_endian_int(read(payload, 4))
    auth_plugin_data_part1 = read(payload, 8)
    append!(conn.auth_plugin_data, auth_plugin_data_part1)
    filter = read(payload, 1)
    capability_lower = read(payload, 2)
    conn.character_set_uint8 = read(payload, 1)[]
    status = _little_endian_int(read(payload, 2))
    capability_upper = read(payload, 2)
    conn.capability = reinterpret(UInt32, vcat(capability_lower, capability_upper))[]

    if conn.capability & CLIENT_PLUGIN_AUTH > 0
        len_auth_plugin_data = Int(read(payload, 1)[])
        skip(payload, 10) # reserved

        if conn.capability & CLIENT_SECURE_CONNECTION > 0
            auth_plugin_data_part2 = read(payload, max(13, len_auth_plugin_data - 8))
            append!(conn.auth_plugin_data, auth_plugin_data_part2)
        end
        conn.auth_plugin_name = String(readuntil(payload, 0x0))
    end
end

# hankshake response packet
# https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse41
function _make_handshake_response_packet(username,
                              password,
                              auth_plugin_name,
                              auth_plugin_data,
                              sequence_id,
                              character_set_uint8)
    auth_response = _make_auth_response(auth_plugin_name, auth_plugin_data, password)

    # calc payload size
    payload_size = 4 + 4 + 1 + 23 # capability flags, max-packet size, character_set, reserved
    payload_size += length(username) + 1 # 1 = null termination
    payload_size += 1 # length of auth-response
    payload_size += length(auth_response)
    payload_size += length(auth_plugin_name) + 1 # 1 = null termination
    payload = IOBuffer(maxsize=payload_size)

    # Make header
    header = vcat(reinterpret(Byte, [payload_size])[1:3], sequence_id)
    sequence_id = mod1(sequence_id + 0x01, 0xff)

    # payload
    capability_flags = Int32(CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
                             | CLIENT_LONG_PASSWORD | CLIENT_TRANSACTIONS
                             | CLIENT_LONG_FLAG)
    write(payload, reinterpret(Byte, [capability_flags]))
    write(payload, zeros(Byte, 4)) # max packet size は 0 でいいので skip
    write(payload, [character_set_uint8])
    write(payload, zeros(Byte, 23)) # reserved
    write(payload, transcode(Byte, username))
    write(payload, 0x0)
    write(payload, Byte(length(auth_response)))
    write(payload, auth_response)
    write(payload, transcode(Byte, auth_plugin_name))
    write(payload, 0x0)

    return MySQLPacket(header, payload.data), sequence_id
end

# https://dev.mysql.com/doc/internals/en/secure-password-authentication.html#packet-Authentication::Native41
function _make_auth_response(auth_plugin_name, auth_plugin_data, password)
    auth_response = UInt8[]
    if auth_plugin_name == "mysql_native_password"
        # sha1(password) xor concat("20-bytes random data from server", sha1(sha1(password)))
        random_data = auth_plugin_data[1:20]
        auth_response = SHA.sha1(SHA.sha1(password))
        auth_response = vcat(random_data, auth_response)
        auth_response = SHA.sha1(auth_response)
        auth_response = xor.(SHA.sha1(password), auth_response)
    end

    return auth_response
end


################
# Command Phase
################

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

# OK Packet
function _parse_ok_packet(payload, capability)
    # https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
    offset = 2
    affected_rows, _read = _lenenc_int(payload[offset:end])
    offset += _read
    last_insert_id, _read = _lenenc_int(payload[offset:end])
    offset += _read

    status_flags = UInt16(0)
    warnings = UInt16(0)
    if capability &  CLIENT_PROTOCOL_41 > 0
        status_flags = reinterpret(UInt16, payload[offset:offset+1])[]
        offset += 2
        warnings = reinterpret(UInt16, payload[offset:offset+1])
        offset += 2
    elseif capability & CLIENT_TRANSACTIONS > 0
        status_flags = reinterpret(UInt16, payload[offset:offset+1])[]
        offset += 2
    end

    # if capability & CLIENT_SESSION_TRACK > 0
    #     @show info, _read = _lenenc_str(payload[offset:end])
    #     offset += _read + 1
    #
    #     if capability & SERVER_SESSION_STATE_CHANGED > 0
    #         session_state_changes, _read = _lenenc_str(payload[offset:end])
    #         offset += _read
    #     end
    # else
    #     info = String(payload[offset:end])
    # end

    return affected_rows, last_insert_id, status_flags, warnings
end

# Error Packet
function _parse_error_packet(payload, capability)
    # https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
    offset = 2
    error_code = _little_endian_int(payload[offset:offset+1])
    offset += 2

    if capability & CLIENT_PROTOCOL_41 > 0
        sql_state_marker = String([payload[offset]])
        offset += 1
        sql_state = String(payload[offset:offset+4])
        offset += 5
    end
    error_message = String(payload[offset:end])
    return error_code, sql_state, error_message
end

##################
# Utilities
##################
function _read_packet(sock)
    header = read(sock, 4)
    payload_size = _little_endian_int(header[1:3])
    payload = read(sock, payload_size)

    return header, payload
end
_read_packet(conn::MySQLConnection) = _read_packet(conn.sock)

function _little_endian_int(arr::Vector{Byte})
    num = Int64(0)
    for (i, c) in enumerate(arr)
        num += Int64(c) << (8 * (i - 1))
    end
    return num
end

# https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
function _lenenc_int(payload::Vector{Byte})
    io = IOBuffer(copy(payload))
    c = read(io, 1)[]
    _read = 1 # number of already read bytes
    result = 0
    err = 0x00
    if c == 0xfb # 251
        println("NULL")
        err = c
    elseif c == 0xfc # 252
        result = _little_endian_int(read(io, 2))
        _read += 2
    elseif c == 0xfd # 253
        result = _little_endian_int(read(io. 3))
        _read += 3
    elseif c == 0xfe # 254
        result = _little_endian_int(read(io. 8))
        _read += 8
    elseif c == 0xff # 255
        # https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
        err = c
    else
        result = Int64(c)
    end

    return result, _read
end

# https://dev.mysql.com/doc/internals/en/string.html#packet-Protocol::LengthEncodedString
function _lenenc_str(payload::Vector{Byte})
    payload = copy(payload)
    strlen, _read = _lenenc_int(payload)
    offset = _read + 1
    result = payload[offset : offset+strlen-1]

    return String(result), _read + strlen
end

end # module
