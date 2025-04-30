//
// This file was auto-generated using the following command:
//
// jai first.jai
//



CHTG_MAGIC :: 0x43485447;
CHTG_VERSION :: 1;
CHTG_FILENAME_MAX :: 1024;
CHTG_CHANNEL_NAME_MAX :: 256;
CHTG_MESSAGE_TEXT_MAX :: 4096;
CHTG_PASSWORD_HASH_LENGTH :: 32;
CHTG_PASSWORD_SALT_LENGTH :: 32;
CHTG_USERNAME_MAX :: 128;
CHTG_PACKET_HEADER_SIZE :: 10;

chtg_magic: u32 : 1128813639; // ("CHTG")
chtg_version: u8 : 1;

chtg_network_buffer :: struct {
    buffer: *u8;
    length: u64;
    cursor: u64;
}

packet_sendertype :: enum u32 {
    CLIENT_HEALTHCHECK         :: 128;
    CLIENT_LOGIN               :: 129;
    CLIENT_SEND_MESSAGE        :: 130;
    CLIENT_SEND_MEDIA          :: 131;
    CLIENT_GET_CHANNELS_LIST   :: 132;
    CLIENT_GET_CHANNELS        :: 133;
    CLIENT_GET_HISTORY         :: 134;
    CLIENT_GET_USERS           :: 135;
    CLIENT_GET_MEDIA           :: 136;
    CLIENT_TYPING              :: 137;

    SERVER_HEALTHCHECK         :: 0;
    SERVER_USER_LOGIN_RESPONSE :: 1;
    SERVER_SEND_MESSAGE_ACK    :: 2;
    SERVER_SEND_MEDIA_ACK      :: 3;
    SERVER_CHANNELS_LIST       :: 4;
    SERVER_CHANNELS            :: 5;
    SERVER_HISTORY             :: 6;
    SERVER_USERS               :: 7;
    SERVER_MEDIA               :: 8;
    SERVER_USER_TYPING         :: 9;
}

packet_sendertype_t :: packet_sendertype;

return_status :: enum u32 {
    SUCCESS :: 0;
    FAILED  :: 1;

    STATUS_SUCCESS :: SUCCESS;
    STATUS_FAILED  :: FAILED;
}

media_type :: enum u32 {
    RAW   :: 0;
    TEXT  :: 1;
    AUDIO :: 2;
    IMAGE :: 3;
    VIDEO :: 4;

    MEDIA_RAW   :: RAW;
    MEDIA_TEXT  :: TEXT;
    MEDIA_AUDIO :: AUDIO;
    MEDIA_IMAGE :: IMAGE;
    MEDIA_VIDEO :: VIDEO;
}

/* typedef struct { */
/*   uint32_t magic   : 32; */
/*   uint8_t  version : 8; */
/*   uint8_t  sender  : 1; */
/*   uint8_t  type    : 7; */
/*   uint32_t length  : 32; */
/* } __attribute__((packed)) packet_header_t; */
chtg_packet_header :: struct {
    __bitfield: [5] u8;
    /* 
        magic: u32; /* 32 bits */
        version: u8; /* 8 bits */;
    */

    union {
        packet_id: u8; /* 8 bits */
        struct {
            __bitfield_1: u8;
            /* 
                packet_kind: u8; /* 7 bits */ // LSBs
                sender: u8; /* 1 bits */ // MSB;
            */
        }
    }

    length:     u32; /* 32 bits */
}

packet_header :: struct {
    __bitfield: [5] u8;
    /* 
        magic: u32; /* 32 bits */
        version: u8; /* 8 bits */;
    */

    union {
        type: u8; /* 8 bits */
        struct {
            __bitfield_1: u8;
            /* 
                subtype: u8; /* 7 bits */
                sender: u8; /* 1 bits */ //MSB;
            */
        }
    }

    length:     u32 #align 2; /* 32 bits */
} #no_padding

packet_header_t :: packet_header;

// TODO: dynamic array? This would make `protocol.h` probably fully dependent on `nob.h` instead of standalone
packet :: struct {
    header:   packet_header_t;
    content:  *u8;
    max_size: u64; //of packet_content
}

// TODO: dynamic array? This would make `protocol.h` probably fully dependent on `nob.h` instead of standalone
packet_t :: packet;

channel :: struct {
    channel_id: u64;
    icon_id:    u64;
    name:       [257] u8; //space for null-termination
}

channel_t :: channel;

message :: struct {
    message_id:     u64;
    sent_timestamp: u64; //unix timestamp
    user_id:        u64;
    channel_id:     u64;
    reply_id:       u64;
    message_text:   [4097] u8; //space for null-termination
    num_media:      u8;
    media_ids:      *u64;
}

message_t :: message;

media :: struct {
    filename: [1025] u8; //space for null-termination
    size:     u32;
    content:  *u8;
}

media_t :: media;

user :: struct {
    user_id:            u64;
    password_hash:      [32] u8;
    password_salt:      [32] u8;
    username:           [129] u8; //space for null-termination
    profile_picture_id: u64;
    bio_length:         u16;
    bio:                *u8;
}

user_t :: user;

chtg_ping_pong :: enum u32 {
    PING :: 0;
    PONG :: 1;

    CHTG_PING :: PING;
    CHTG_PONG :: PONG;
}

chtg_health_check_packet :: struct {
    ping_pong: chtg_ping_pong;
}

#scope_file

#import "Basic"; // For assert


#run {
    {
        info := type_info(chtg_network_buffer);
        for info.members {
            if it.name == {
                case "buffer";
                    assert(it.offset_in_bytes == 0, "chtg_network_buffer.buffer has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "chtg_network_buffer.buffer has unexpected size % instead of 8", it.type.runtime_size);
                case "length";
                    assert(it.offset_in_bytes == 8, "chtg_network_buffer.length has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "chtg_network_buffer.length has unexpected size % instead of 8", it.type.runtime_size);
                case "cursor";
                    assert(it.offset_in_bytes == 16, "chtg_network_buffer.cursor has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "chtg_network_buffer.cursor has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(chtg_network_buffer) == 24, "chtg_network_buffer has size % instead of 24", size_of(chtg_network_buffer));
    }

    {
        info := type_info(chtg_packet_header);
        for info.members {
            if it.name == {
                case "__bitfield";
                    assert(it.offset_in_bytes == 0, "chtg_packet_header.__bitfield has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 5, "chtg_packet_header.__bitfield has unexpected size % instead of 5", it.type.runtime_size);
                case "length";
                    assert(it.offset_in_bytes == 8, "chtg_packet_header.length has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "chtg_packet_header.length has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(chtg_packet_header) == 12, "chtg_packet_header has size % instead of 12", size_of(chtg_packet_header));
    }

    {
        info := type_info(packet_header);
        for info.members {
            if it.name == {
                case "__bitfield";
                    assert(it.offset_in_bytes == 0, "packet_header.__bitfield has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 5, "packet_header.__bitfield has unexpected size % instead of 5", it.type.runtime_size);
                case "length";
                    assert(it.offset_in_bytes == 6, "packet_header.length has unexpected offset % instead of 6", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "packet_header.length has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(packet_header) == 10, "packet_header has size % instead of 10", size_of(packet_header));
    }

    {
        info := type_info(packet);
        for info.members {
            if it.name == {
                case "header";
                    assert(it.offset_in_bytes == 0, "packet.header has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 10, "packet.header has unexpected size % instead of 10", it.type.runtime_size);
                case "content";
                    assert(it.offset_in_bytes == 16, "packet.content has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "packet.content has unexpected size % instead of 8", it.type.runtime_size);
                case "max_size";
                    assert(it.offset_in_bytes == 24, "packet.max_size has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "packet.max_size has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(packet) == 32, "packet has size % instead of 32", size_of(packet));
    }

    {
        info := type_info(channel);
        for info.members {
            if it.name == {
                case "channel_id";
                    assert(it.offset_in_bytes == 0, "channel.channel_id has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "channel.channel_id has unexpected size % instead of 8", it.type.runtime_size);
                case "icon_id";
                    assert(it.offset_in_bytes == 8, "channel.icon_id has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "channel.icon_id has unexpected size % instead of 8", it.type.runtime_size);
                case "name";
                    assert(it.offset_in_bytes == 16, "channel.name has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 257, "channel.name has unexpected size % instead of 257", it.type.runtime_size);
            }
        }
        assert(size_of(channel) == 280, "channel has size % instead of 280", size_of(channel));
    }

    {
        info := type_info(message);
        for info.members {
            if it.name == {
                case "message_id";
                    assert(it.offset_in_bytes == 0, "message.message_id has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "message.message_id has unexpected size % instead of 8", it.type.runtime_size);
                case "sent_timestamp";
                    assert(it.offset_in_bytes == 8, "message.sent_timestamp has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "message.sent_timestamp has unexpected size % instead of 8", it.type.runtime_size);
                case "user_id";
                    assert(it.offset_in_bytes == 16, "message.user_id has unexpected offset % instead of 16", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "message.user_id has unexpected size % instead of 8", it.type.runtime_size);
                case "channel_id";
                    assert(it.offset_in_bytes == 24, "message.channel_id has unexpected offset % instead of 24", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "message.channel_id has unexpected size % instead of 8", it.type.runtime_size);
                case "reply_id";
                    assert(it.offset_in_bytes == 32, "message.reply_id has unexpected offset % instead of 32", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "message.reply_id has unexpected size % instead of 8", it.type.runtime_size);
                case "message_text";
                    assert(it.offset_in_bytes == 40, "message.message_text has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4097, "message.message_text has unexpected size % instead of 4097", it.type.runtime_size);
                case "num_media";
                    assert(it.offset_in_bytes == 4137, "message.num_media has unexpected offset % instead of 4137", it.offset_in_bytes);
                    assert(it.type.runtime_size == 1, "message.num_media has unexpected size % instead of 1", it.type.runtime_size);
                case "media_ids";
                    assert(it.offset_in_bytes == 4144, "message.media_ids has unexpected offset % instead of 4144", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "message.media_ids has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(message) == 4152, "message has size % instead of 4152", size_of(message));
    }

    {
        info := type_info(media);
        for info.members {
            if it.name == {
                case "filename";
                    assert(it.offset_in_bytes == 0, "media.filename has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 1025, "media.filename has unexpected size % instead of 1025", it.type.runtime_size);
                case "size";
                    assert(it.offset_in_bytes == 1028, "media.size has unexpected offset % instead of 1028", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "media.size has unexpected size % instead of 4", it.type.runtime_size);
                case "content";
                    assert(it.offset_in_bytes == 1032, "media.content has unexpected offset % instead of 1032", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "media.content has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(media) == 1040, "media has size % instead of 1040", size_of(media));
    }

    {
        info := type_info(user);
        for info.members {
            if it.name == {
                case "user_id";
                    assert(it.offset_in_bytes == 0, "user.user_id has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "user.user_id has unexpected size % instead of 8", it.type.runtime_size);
                case "password_hash";
                    assert(it.offset_in_bytes == 8, "user.password_hash has unexpected offset % instead of 8", it.offset_in_bytes);
                    assert(it.type.runtime_size == 32, "user.password_hash has unexpected size % instead of 32", it.type.runtime_size);
                case "password_salt";
                    assert(it.offset_in_bytes == 40, "user.password_salt has unexpected offset % instead of 40", it.offset_in_bytes);
                    assert(it.type.runtime_size == 32, "user.password_salt has unexpected size % instead of 32", it.type.runtime_size);
                case "username";
                    assert(it.offset_in_bytes == 72, "user.username has unexpected offset % instead of 72", it.offset_in_bytes);
                    assert(it.type.runtime_size == 129, "user.username has unexpected size % instead of 129", it.type.runtime_size);
                case "profile_picture_id";
                    assert(it.offset_in_bytes == 208, "user.profile_picture_id has unexpected offset % instead of 208", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "user.profile_picture_id has unexpected size % instead of 8", it.type.runtime_size);
                case "bio_length";
                    assert(it.offset_in_bytes == 216, "user.bio_length has unexpected offset % instead of 216", it.offset_in_bytes);
                    assert(it.type.runtime_size == 2, "user.bio_length has unexpected size % instead of 2", it.type.runtime_size);
                case "bio";
                    assert(it.offset_in_bytes == 224, "user.bio has unexpected offset % instead of 224", it.offset_in_bytes);
                    assert(it.type.runtime_size == 8, "user.bio has unexpected size % instead of 8", it.type.runtime_size);
            }
        }
        assert(size_of(user) == 232, "user has size % instead of 232", size_of(user));
    }

    {
        info := type_info(chtg_health_check_packet);
        for info.members {
            if it.name == {
                case "ping_pong";
                    assert(it.offset_in_bytes == 0, "chtg_health_check_packet.ping_pong has unexpected offset % instead of 0", it.offset_in_bytes);
                    assert(it.type.runtime_size == 4, "chtg_health_check_packet.ping_pong has unexpected size % instead of 4", it.type.runtime_size);
            }
        }
        assert(size_of(chtg_health_check_packet) == 4, "chtg_health_check_packet has size % instead of 4", size_of(chtg_health_check_packet));
    }
}

