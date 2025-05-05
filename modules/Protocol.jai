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

Return_Status :: enum u8 {
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

to_little_endian :: to_big_endian;
to_big_endian :: (n: $T) -> T {
    size :: size_of(T);

    bytes: [..]u8 = ---;
    bytes.data  = xx *n;
    bytes.count = size;

    for i : 0..(size / 2  - 1) {
        t := bytes[i];
        bytes[i] = bytes[size - 1 - i];
        bytes[size - 1 - i] = t;
    }

    return bytes.data.(*T).*;
}

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
                    number_pointer: *u64 = it.value_pointer.(**u64).*;
                    number_pointer.*     = to_little_endian(number_pointer.*);
                case 1;
                case;
                    log("wtf?? %", size);
            }
        }
    }
}

write_into :: (buffer: *[..]u8, any: ..Any) {
    total_size: s64 = 0;
    for any total_size += it.type.runtime_size;

    array_reserve(buffer, total_size);

    for any {
        size := it.type.runtime_size;

        if it.type.type == .INTEGER {
            int_info := it.type.(*Type_Info_Integer);
            assert(int_info.signed == false, "signed writing not implemented");

            if size == {
                case 1;
                    memcpy(buffer.data + buffer.count, it.value_pointer, size);
                case 2;
                    send_me := to_big_endian(it.value_pointer.(*u16).*);
                    memcpy(buffer.data + buffer.count, *send_me, xx size);
                case 4;
                    send_me := to_big_endian(it.value_pointer.(*u32).*);
                    memcpy(buffer.data + buffer.count, *send_me, xx size);
                case 8;
                    send_me := to_big_endian(it.value_pointer.(*u64).*);
                    memcpy(buffer.data + buffer.count, *send_me, xx size);
                case;
                    log("wtf?? %", size);
            }
        } else {
            memcpy(buffer.data + buffer.count, it.value_pointer, xx size);
        }

        buffer.count += size;
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
                    send_me := to_big_endian(it.value_pointer.(*u64).*);
                    memcpy(buffer + cursor, *send_me, xx size);
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

Message_Type :: enum u8 {
    TEXT;
}

Message :: struct {
    type: Message_Type;

    union {
        as_text_message: Message_Type_Text;
    }
}

Message_Type_Text :: struct {
    id: u64;
    sent_at: u64;
    user_id: u64;
    channel_id: u64;
    reply_id: u64;

    text: string;

    media: [..]u64;
}

get_messages :: (descriptor: s32, heap: Allocator) -> [..]Message {

    result: [..]Message;

    while true {
        packet := read_header(descriptor);

        assert(packet.magic   == MAGIC);
        assert(packet.version == VERSION);

        log("[server]: %", packet);

        if packet.type == {
            case .SERVER_HEALTHCHECK;
                assert(packet.length == 1);
                pong: Ping_Type;
                read(descriptor, *pong, 1);

                using response := Packet.{
                    type   = .CLIENT_HEALTHCHECK,
                    length = 1,
                };
                log("[client]: %", response);
                write_into(descriptor, magic, version, type, length, Ping_Type.PONG);

            case .SERVER_HISTORY;

                status: Return_Status;
                number_of_messages: u8;
                read_into(descriptor, *status, *number_of_messages);

                assert(status != .FAILED);

                for i : 0..number_of_messages-1 {
                    message: Message;
                    using message.as_text_message;

                    text_count: u16;

                    read_into(descriptor, *id, *sent_at, *user_id, *channel_id, *reply_id, *text_count);

                    text.count = text_count;
                    text.data  = alloc(text_count);
                    read(descriptor, text.data, text_count);

                    media_count: u8;
                    read_into(descriptor, *media_count);

                    array_reserve(*media, media_count);
                    read(descriptor, media.data, media_count * size_of(u64));
                    media.count = media_count;

                    message.type = .TEXT;
                    log("message: %", message);
                    array_add(*result, message);
                }

                return result;

            case;
                buffer := alloc(packet.length);
                read(descriptor, buffer, packet.length);
                log("unhandled packet type: %", packet.type);
                log("draining the read buffer of % bytes", packet.length);
                t: string;
                t.data = buffer;
                t.count = packet.length;
                log("buffer content: '%'", t);
                // exit(1);
        }

        reset_temporary_storage();
    }

    return result;
}

send_text_message :: (descriptor: s32, text: string, channel_id: u64, reply_id: u64 = 0) {

    using response := Packet.{
        type   = .CLIENT_SEND_MESSAGE,
        length = 8 + 8 + 1 + 0 + cast(u32)text.count,
    };

    buffer: [..]u8;
    defer free(buffer.data);

    number_of_media: u8 = 0;

    write_into(*buffer, magic, version, type, length, channel_id, reply_id, number_of_media);

    for text
        array_add(*buffer, it);

    amount_sent := write(descriptor, buffer.data, xx buffer.count);

    if amount_sent != buffer.count {
        log("Tried sending % bytes, but only sent % bytes", buffer.count, amount_sent);
        exit(1);
    }
}

send_login_message :: (descriptor: s32, username: string, password: string) {

    using response := Packet.{
        type   = .CLIENT_LOGIN,
        length = xx(username.count + password.count + 1),
    };

    builder: String_Builder;
    defer free_buffers(*builder);

    append(*builder, username);
    append(*builder, "\0");
    append(*builder, password);

    payload := builder_to_string(*builder);

    buffer: [..]u8;

    write_into(*buffer, magic, version, type, length);

    for payload array_add(*buffer, it);

    amount_sent := write(descriptor, buffer.data, xx buffer.count);

    if amount_sent != buffer.count {
        log("Tried sending % bytes, but only sent % bytes", buffer.count, amount_sent);
        exit(1);
    }
}
