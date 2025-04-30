#import "Basic";

MAGIC                ::  0x43485447; // ("CHTG")
VERSION              ::  1;
FILENAME_MAX         ::  1024;
CHANNEL_NAME_MAX     ::  256;
MESSAGE_TEXT_MAX     ::  4096;
PASSWORD_HASH_LENGTH ::  32;         // bytes
PASSWORD_SALT_LENGTH ::  32;         // bytes
USERNAME_MAX         ::  128;
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

write_header :: (buffer: *[..]u8, type: Packet_Type, length: u32) {

    push_bytes :: inline (buffer: *[..]u8, item: $T) {
        memcpy(buffer.data + buffer.count, *item, size_of(T));
        buffer.count += size_of(T);
    }

    magic        : u32 = htonl(MAGIC);
    version      : u8  = VERSION;
    htonl_length : u32 = htonl(length);

    SIZE :: size_of(type_of(magic)) + size_of(type_of(version)) + size_of(type_of(type)) + size_of(type_of(length));
    #assert SIZE == PACKET_HEADER_SIZE;

    array_reserve(buffer, SIZE + length);

    push_bytes(buffer, magic);
    push_bytes(buffer, version);
    push_bytes(buffer, type);
    push_bytes(buffer, htonl_length);
}

make_health_check_packet :: (ping: bool) -> []u8 {
    result: [..]u8;
    write_header(*result, .CLIENT_HEALTHCHECK, 1);
    array_add(*result, xx (ifx ping then 1 else 0));
    return result;
}

#scope_file

htonl :: (hostlong:  u32) -> u32 #foreign libc;
htons :: (hostlong:  u32) -> u32 #foreign libc;
