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
PACKET_HEADER_SIZE   ::  10;         // bytes

MAGIC_BIG_ENDIAN :u32be: #run to_big_endian(MAGIC);

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
    PONG :: 0;
    PING :: 1;
}

u32be :: #type,distinct u32;
to_little_endian :: inline (n: u32be) -> u32   { return ntohl(xx n); }
to_big_endian    :: inline (n: u32)   -> u32be { return xx htonl(n); }

Packet :: struct {
    magic   : u32be = MAGIC_BIG_ENDIAN #align 1;
    version : u8    = VERSION          #align 1;
    type    : Packet_Type              #align 1;
    length  : u32be                    #align 1;
} #no_padding

#assert size_of(Packet) == PACKET_HEADER_SIZE;

Health_Check_Packet :: struct {
    #as using header: Packet #align 1;
    ping: Ping_Type          #align 1;
} #no_padding

make_health_check_packet :: (ping: Ping_Type) -> Health_Check_Packet {
    return Health_Check_Packet.{
        header = .{
            type   = .CLIENT_HEALTHCHECK,
            length = #run to_big_endian(1)
        },
        ping = ping
    };
}

send :: (packet: *Packet, descriptor: s32) {
    size_to_send := size_of(Packet) + to_little_endian(packet.length);

    bytes := cast(*[size_of(Packet)]u8) packet;
    log("sending bytes: %", bytes.*);

    amount_sent  := write(descriptor, packet, size_to_send);
    assert(amount_sent == size_to_send);
}

receive_packet :: (descriptor: s32) -> *Packet {
    header: Packet;
    amount_read := read(descriptor, *header, size_of(Packet));
    if amount_read  != size_of(Packet) {
        log("Expected to read % bytes, but read % bytes", size_of(Packet), amount_read);
        exit(1);
    }

    assert(header.magic == MAGIC_BIG_ENDIAN);

    payload_length := to_little_endian(header.length);

    buffer := alloc(size_of(Packet) + payload_length);
    memcpy(buffer, *header, size_of(Packet));

    amount_read = read(descriptor, buffer + size_of(Packet) + 1, payload_length);
    assert(amount_read == payload_length);

    return buffer;
}


printer_with_big_endian :: (builder: *String_Builder, any: Any, struct_printer_data: *void) -> bool {
    info := any.type;
    if info.type == .VARIANT {
        variant_info := info.(*Type_Info_Variant);
        if (variant_info.variant_flags & .DISTINCT) && (variant_info.name == "u32be") {
            print_to_builder(builder, "%", to_little_endian(any.value_pointer.(*u32be).*));
            return true;
        }
    }

    return false;
}
