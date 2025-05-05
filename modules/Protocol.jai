#import "Basic";
#import "Socket";
#import "POSIX";

MAGIC                ::  0x43485447; // ("CHTG")
VERSION              ::  1;
FILENAME_MAX         ::  1024;
CHANNEL_NAME_MAX     ::  256;
MESSAGE_TEXT_MAX     ::  4096;
PASSWORD_HASH_LENGTH ::  32;         // bytes
PASSWORD_SALT_LENGTH ::  32;         // bytes
USERNAME_MAX         ::  128;
PASSWORD_MAX         ::  1024;
PACKET_HEADER_SIZE   ::  10;         // bytes

Packet_Type :: enum u8 {
    CLIENT_HEALTHCHECK :: 0x80; //MSB is sender (1 for client/0 for server)
    CLIENT_LOGIN;
    CLIENT_SEND_MESSAGE;
    CLIENT_SEND_MEDIA;
    CLIENT_GET_CHANNELS_LIST;
    CLIENT_GET_CHANNELS;
    CLIENT_GET_HISTORY;
    CLIENT_GET_USERS;
    CLIENT_GET_MEDIA;
    CLIENT_TYPING;

    SERVER_HEALTHCHECK ::  0;
    SERVER_USER_LOGIN_RESPONSE;
    SERVER_SEND_MESSAGE_ACK;
    SERVER_SEND_MEDIA_ACK;
    SERVER_CHANNELS_LIST;
    SERVER_CHANNELS;
    SERVER_HISTORY;
    SERVER_USERS;
    SERVER_MEDIA;
    SERVER_USER_TYPING;
}

Return_Status :: enum {
    SUCCESS :: 0;
    FAILED  :: 1;
};

Media_Type :: enum {
    MEDIA_RAW :: 0;
    MEDIA_TEXT;
    MEDIA_AUDIO;
    MEDIA_IMAGE;
    MEDIA_VIDEO;
};

Ping_Type :: enum u8 {
    PING :: 0;
    PONG :: 1;
}

to_little_endian :: inline (n: u32) -> u32 { return ntohl(n); }
to_big_endian    :: inline (n: u32) -> u32 { return htonl(n); }

to_little_endian :: inline (n: u16) -> u16 { return ntohs(n); }
to_big_endian    :: inline (n: u16) -> u16 { return htons(n); }

Packet :: struct {
    magic:   u32 = MAGIC;
    version: u8  = VERSION;
    type:    Packet_Type;
    length:  u32;
}

read_into :: (from_descriptor: s32, any: ..Any) {
    total_size: s64 = 0;
    for any {
        assert(it.type.type == .POINTER, "passed non pointer to read_into()");
        total_size += it.type.(*Type_Info_Pointer).pointer_to.runtime_size;
    }

    buffer := alloc(total_size);
    defer free(buffer);

    amount_read := read(from_descriptor, buffer, xx total_size);

    if amount_read != total_size {
        log("Tried reading % bytes, but only read % bytes", total_size, amount_read);
        exit(1); // @cleanup - should reconnect
    }

    cursor := 0;
    for any {
        value_type_info := it.type.(*Type_Info_Pointer).pointer_to;

        size := value_type_info.runtime_size;

        memcpy(it.value_pointer.(**u8).*, buffer + cursor, size);

        cursor += size;

        if value_type_info.type == .INTEGER {
            int_type_info := value_type_info.(*Type_Info_Integer);
            assert(int_type_info.signed == false, "signed reading not implemented");
            if size == {
                case 2;
                    number_pointer: *u16 = it.value_pointer.(**u16).*;
                    number_pointer.*     = to_little_endian(number_pointer.*);
                case 4;
                    number_pointer: *u32 = it.value_pointer.(**u32).*;
                    number_pointer.*     = to_little_endian(number_pointer.*);
                case 8;
                    assert(false, "endian convesion not implemented for 8 byte sized integers");
                case 1;
                case;
                    log("wtf?? %", size);
            }
        }
    }
}

write_into :: (to_descriptor: s32, any: ..Any) {

    total_size: s64 = 0;
    for any total_size += it.type.runtime_size;

    buffer := alloc(total_size);
    defer free(buffer);

    cursor := 0;
    for any {
        size := it.type.runtime_size;

        if it.type.type == .INTEGER {
            int_info := it.type.(*Type_Info_Integer);
            assert(int_info.signed == false, "signed writing not implemented");

            if size == {
                case 1;
                    memcpy(buffer + cursor, it.value_pointer, size);
                case 2;
                    send_me := to_big_endian(it.value_pointer.(*u16).*);
                    memcpy(buffer + cursor, *send_me, xx size);
                case 4;
                    send_me := to_big_endian(it.value_pointer.(*u32).*);
                    memcpy(buffer + cursor, *send_me, xx size);
                case 8;
                    assert(false, "endian convesion not implemented for 8 byte sized integers");
                case;
                    log("wtf?? %", size);
            }
        } else {
            memcpy(buffer + cursor, it.value_pointer, xx size);
        }

        cursor += size;
    }

    amount_sent := write(to_descriptor, buffer, xx total_size);

    if amount_sent != total_size {
        log("Tried sending % bytes but only sent % bytes", total_size, amount_sent);
        exit(1);
    }
}

read_header :: (descriptor: s32) -> Packet {
    using result: Packet;
    read_into(descriptor, *magic, *version, *type, *length);

    return result;
}

receive_packet :: (descriptor: s32) -> header: Packet, payload: []u8 {

    header := read_header(descriptor);

    payload: [..]u8;
    payload.count = header.length;
    payload.data  = alloc(header.length);
    read(descriptor, payload.data, header.length);

    return header, payload;
}

Message_Type :: enum u8 {
    TEXT;
}

Message :: struct {
    type: Message_Type;
    payload: []u8;

    union {

    }
}

Message_Type_Text :: struct {
    text: string;
}

get_message :: (descriptor: s32) -> Message {

    while true {
        packet, payload := receive_packet(descriptor);
        log("[server]: %", packet);

        if packet.type == {
            case .SERVER_HEALTHCHECK;
                response := Packet.{
                    type   = .CLIENT_HEALTHCHECK,
                    length = 1,
                };
                log("[client]: %", response);
                write_into(descriptor, response.magic, response.version, response.type, response.length, Ping_Type.PONG);
            case;
                log("unhandled packet type: %", packet.type);
                exit(1);
        }
    }
}
