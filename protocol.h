// Chatger protocol v1 (see PROTOCOL.txt)
// chtg_ prefix for CHaTGer

#ifndef CHTG_PROTOCOL_H
#define CHTG_PROTOCOL_H

#include <assert.h>
#include <linux/limits.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h> // htons(), htonl(), ntohs(), ntohl()
                       // windows uses winsock2.h

// arpa/inet.h it doesn't provide htonll() and ntohll() so (from https://stackoverflow.com/a/28592202)
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

/*
magic_number: 0x43485447 ("CHTG") ?
version     : 0x01
user/server+packet_id: [[is_user|1bit][packet_id|7bit]]
length      : length of packet content in bytes
*/

const uint32_t chtg_magic   = 0x43485447; // ("CHTG")
const  uint8_t chtg_version = 1;

#define CHTG_MAGIC 0x43485447 // ("CHTG")
#define CHTG_VERSION 1
#define CHTG_FILENAME_MAX 1024
#define CHTG_CHANNEL_NAME_MAX 256
#define CHTG_MESSAGE_TEXT_MAX 4096
#define CHTG_PASSWORD_HASH_LENGTH 32 //bytes
#define CHTG_PASSWORD_SALT_LENGTH 32 //bytes
#define CHTG_USERNAME_MAX 128
#define CHTG_PACKET_HEADER_SIZE 10 // bytes

typedef struct chtg_network_buffer {
    char* buffer;
    size_t length;
    size_t cursor;
} chtg_network_buffer;


void chtg_netbuf_write_bytes(chtg_network_buffer* netbuf, const char* bytes, size_t count);
void chtg_netbuf_write_byte(chtg_network_buffer* netbuf, char byte);
void chtg_netbuf_write_sbyte(chtg_network_buffer* netbuf, signed char sbyte);
void chtg_netbuf_encode_int16(chtg_network_buffer* netbuf, int16_t value);
void chtg_netbuf_encode_uint16(chtg_network_buffer* netbuf, uint16_t value);
void chtg_netbuf_encode_int32(chtg_network_buffer* netbuf, int32_t value);
void chtg_netbuf_encode_uint32(chtg_network_buffer* netbuf, uint32_t value);
void chtg_netbuf_encode_int64(chtg_network_buffer* netbuf, int64_t value);
void chtg_netbuf_encode_uint64(chtg_network_buffer* netbuf, uint64_t value);

void chtg_netbuf_read_bytes(chtg_network_buffer* netbuf, char* out_bytes, size_t count);
char chtg_netbuf_read_byte(chtg_network_buffer* netbuf);
signed char chtg_netbuf_read_sbyte(chtg_network_buffer* netbuf);
int16_t chtg_netbuf_decode_int16(chtg_network_buffer* netbuf);
uint16_t chtg_netbuf_decode_uint16(chtg_network_buffer* netbuf);
int32_t chtg_netbuf_decode_int32(chtg_network_buffer* netbuf);
uint32_t chtg_netbuf_decode_uint32(chtg_network_buffer* netbuf);
int64_t chtg_netbuf_decode_int64(chtg_network_buffer* netbuf);
uint64_t chtg_netbuf_decode_uint64(chtg_network_buffer* netbuf);


typedef enum packet_sendertype {

    CLIENT_HEALTHCHECK = 0x80, //MSB is sender (1 for client/0 for server)
    CLIENT_LOGIN,
    CLIENT_SEND_MESSAGE,
    CLIENT_SEND_MEDIA,
    CLIENT_GET_CHANNELS_LIST,
    CLIENT_GET_CHANNELS,
    CLIENT_GET_HISTORY,
    CLIENT_GET_USERS,
    CLIENT_GET_MEDIA,
    CLIENT_TYPING,

    SERVER_HEALTHCHECK = 0,
    SERVER_USER_LOGIN_RESPONSE,
    SERVER_SEND_MESSAGE_ACK,
    SERVER_SEND_MEDIA_ACK,
    SERVER_CHANNELS_LIST,
    SERVER_CHANNELS,
    SERVER_HISTORY,
    SERVER_USERS,
    SERVER_MEDIA,
    SERVER_USER_TYPING,

}packet_sendertype_t;

enum return_status {
    STATUS_SUCCESS = 0,
    STATUS_FAILED  = 1
};

enum media_type {
    MEDIA_RAW = 0,
    MEDIA_TEXT,
    MEDIA_AUDIO,
    MEDIA_IMAGE,
    MEDIA_VIDEO,
};

/* typedef struct { */
/*   uint32_t magic   : 32; */
/*   uint8_t  version : 8; */
/*   uint8_t  sender  : 1; */
/*   uint8_t  type    : 7; */
/*   uint32_t length  : 32; */
/* } __attribute__((packed)) packet_header_t; */


typedef struct chtg_packet_header {
    uint32_t magic : 32;
    uint8_t version : 8;
    union {
        uint8_t packet_id : 8;
        struct {
            uint8_t packet_kind : 7; // LSBs
            uint8_t sender : 1; // MSB
        };
    };
    uint32_t length : 32;
} chtg_packet_header;


typedef struct packet_header {
    uint32_t magic : 32;
    uint8_t version : 8;
union{
    uint8_t type : 8;
    struct{
        uint8_t subtype : 7;
        uint8_t sender  : 1; //MSB
    };
};
    uint32_t length : 32;
}__attribute__((packed)) packet_header_t;



// TODO: dynamic array? This would make `protocol.h` probably fully dependent on `nob.h` instead of standalone
typedef struct packet {
    packet_header_t header;
    char *content;
    size_t max_size; //of packet_content
}packet_t;

typedef struct channel {
    uint64_t channel_id;
    uint64_t icon_id;
    char name[CHTG_CHANNEL_NAME_MAX+1]; //space for null-termination
}channel_t;

typedef struct message {
    uint64_t message_id;
    uint64_t sent_timestamp; //unix timestamp
    uint64_t user_id;
    uint64_t channel_id;
    uint64_t reply_id;
    char message_text[CHTG_MESSAGE_TEXT_MAX+1]; //space for null-termination
    uint8_t num_media;
    uint64_t *media_ids;
}message_t;


typedef struct media {
    char filename[CHTG_FILENAME_MAX+1]; //space for null-termination
    uint32_t size;
    uint8_t *content;
}media_t;

typedef struct user {
    uint64_t user_id;
    uint8_t password_hash[CHTG_PASSWORD_HASH_LENGTH];
    uint8_t password_salt[CHTG_PASSWORD_SALT_LENGTH];
    char username[CHTG_USERNAME_MAX+1]; //space for null-termination
    uint64_t profile_picture_id;
    uint16_t bio_length;
    char *bio;
}user_t;


void chtg_decode_packet_header(chtg_packet_header* header, chtg_network_buffer* buffer);
void chtg_encode_packet_header(chtg_packet_header header, chtg_network_buffer* buffer);


typedef enum chtg_ping_pong {
    CHTG_PING = 0x00,
    CHTG_PONG = 0x01,
} chtg_ping_pong;

typedef struct chtg_health_check_packet {
    chtg_ping_pong ping_pong;
} chtg_health_check_packet;

void chtg_decode_health_check_packet(chtg_health_check_packet* packet, chtg_network_buffer* buffer);
char* chtg_encode_health_check_packet(chtg_health_check_packet packet, size_t* out_length);


/* HEALTHCHECK */
int chtg_build_packet_healthcheck(packet_t *packet, uint8_t is_client, uint8_t is_ping);
/* LOGIN */
int chtg_build_packet_user_login         (packet_t *packet, char* username, char* password);
int chtg_build_packet_user_login_response(packet_t *packet, enum return_status status, char *failed_message);
/* SEND MESSAGE */
int chtg_build_packet_send_message    (packet_t *packet, char *message_text, uint8_t num_media, uint64_t *media_ids);
int chtg_build_packet_send_message_ack(packet_t *packet, enum return_status status, uint64_t message_id, char *error_message);
/* SEND MEDIA */
int chtg_build_packet_send_media    (packet_t *packet, char *filename, enum media_type type, char *media_data, size_t media_size);
int chtg_build_packet_send_media_ack(packet_t *packet, enum return_status status, uint64_t message_id, char *error_message);
/* GET CHANNELS LIST */
int chtg_build_packet_get_channels_list(packet_t *packet);
int chtg_build_packet_channels_list(packet_t *packet, enum return_status status, uint16_t num_channels, uint64_t *channel_ids, char *error_message);
/* GET CHANNELS */
int chtg_build_packet_get_channels(packet_t *packet, uint16_t num_channels, uint64_t *channel_ids);
int chtg_build_packet_channels(packet_t *packet, enum return_status status, uint16_t num_channels, channel_t *channels, char *error_message);
/* GET HISTORY */
int chtg_build_packet_get_history(packet_t *packet, uint64_t channel_id, uint64_t unix_timestamp, int8_t num_messages_back);
int chtg_build_packet_history(packet_t *packet, enum return_status status, int8_t num_messages, message_t *messages, char *error_message);
/* GET USERS */
int chtg_build_packet_get_users(packet_t *packet, uint8_t num_users, uint64_t *user_ids);
int chtg_build_packet_users(packet_t *packet, enum return_status status, uint8_t num_users, user_t *users, char *error_message);
/* GET MEDIA */
int chtg_build_packet_get_media(packet_t *packet, uint64_t media_id);
int chtg_build_packet_media(packet_t *packet, enum return_status status, enum media_type type, media_t *media, char *error_message);
/* TYPING */
int chtg_build_packet_typing(packet_t *packet, uint8_t is_typing);
int chtg_build_packet_user_typing(packet_t *packet, uint64_t user_id, uint8_t is_typing);


#endif // CHTG_PROTOCOL_H


#ifdef CHTG_PROTOCOL_IMPLEMENTATION


void chtg_netbuf_write_bytes(chtg_network_buffer* netbuf, const char* bytes, size_t count) {
    assert(count <= netbuf->length - netbuf->cursor);
    memcpy(netbuf->buffer + netbuf->cursor, bytes, count);
    netbuf->cursor += count;
}

void chtg_netbuf_write_byte(chtg_network_buffer* netbuf, char byte) {
    assert(netbuf->length - netbuf->cursor >= 1);
    *(netbuf->buffer + netbuf->cursor) = byte;
    netbuf->cursor += 1;
}

void chtg_netbuf_write_sbyte(chtg_network_buffer* netbuf, signed char sbyte) {
    assert(netbuf->length - netbuf->cursor >= 1);
    *(netbuf->buffer + netbuf->cursor) = (char)sbyte;
    netbuf->cursor += 1;
}

void chtg_netbuf_encode_int16(chtg_network_buffer* netbuf, int16_t value) {
    assert(netbuf->length - netbuf->cursor >= 2);
    *((uint16_t*)(netbuf->buffer + netbuf->cursor)) = htons((uint16_t)value);
    netbuf->cursor += 2;
}

void chtg_netbuf_encode_uint16(chtg_network_buffer* netbuf, uint16_t value) {
    assert(netbuf->length - netbuf->cursor >= 2);
    *((uint16_t*)(netbuf->buffer + netbuf->cursor)) = htons(value);
    netbuf->cursor += 2;
}

void chtg_netbuf_encode_int32(chtg_network_buffer* netbuf, int32_t value) {
    assert(netbuf->length - netbuf->cursor >= 4);
    *((uint32_t*)(netbuf->buffer + netbuf->cursor)) = htonl((uint32_t)value);
    netbuf->cursor += 4;
}

void chtg_netbuf_encode_uint32(chtg_network_buffer* netbuf, uint32_t value) {
    assert(netbuf->length - netbuf->cursor >= 4);
    *((uint32_t*)(netbuf->buffer + netbuf->cursor)) = htonl(value);
    netbuf->cursor += 4;
}

void chtg_netbuf_encode_int64(chtg_network_buffer* netbuf, int64_t value) {
    assert(netbuf->length - netbuf->cursor >= 8);
    *((uint64_t*)(netbuf->buffer + netbuf->cursor)) = htonll((uint64_t)value);
    netbuf->cursor += 8;
}

void chtg_netbuf_encode_uint64(chtg_network_buffer* netbuf, uint64_t value) {
    assert(netbuf->length - netbuf->cursor >= 8);
    *((uint64_t*)(netbuf->buffer + netbuf->cursor)) = htonll(value);
    netbuf->cursor += 8;
}


void chtg_netbuf_read_bytes(chtg_network_buffer* netbuf, char* out_bytes, size_t count) {
    assert(count <= netbuf->length - netbuf->cursor);
    memcpy(out_bytes, netbuf->buffer + netbuf->cursor, count);
    netbuf->cursor += count;
}

char chtg_netbuf_read_byte(chtg_network_buffer* netbuf) {
    assert(netbuf->length - netbuf->cursor >= 1);
    char result = *(netbuf->buffer + netbuf->cursor);
    netbuf->cursor += 1;
    return result;
}

signed char chtg_netbuf_read_sbyte(chtg_network_buffer* netbuf) {
    assert(netbuf->length - netbuf->cursor >= 1);
    signed char result = (signed char)(*(netbuf->buffer + netbuf->cursor));
    netbuf->cursor += 1;
    return result;
}

int16_t chtg_netbuf_decode_int16(chtg_network_buffer* netbuf) {
    assert(netbuf->length - netbuf->cursor >= 2);
    int16_t result = (int16_t)ntohs(*((uint16_t*)(netbuf->buffer + netbuf->cursor)));
    netbuf->cursor += 2;
    return result;
}

uint16_t chtg_netbuf_decode_uint16(chtg_network_buffer* netbuf) {
    assert(netbuf->length - netbuf->cursor >= 2);
    uint16_t result = ntohs(*((uint16_t*)(netbuf->buffer + netbuf->cursor)));
    netbuf->cursor += 2;
    return result;
}

int32_t chtg_netbuf_decode_int32(chtg_network_buffer* netbuf) {
    assert(netbuf->length - netbuf->cursor >= 4);
    int32_t result = (int32_t)ntohs(*((uint32_t*)(netbuf->buffer + netbuf->cursor)));
    netbuf->cursor += 4;
    return result;
}

uint32_t chtg_netbuf_decode_uint32(chtg_network_buffer* netbuf) {
    assert(netbuf->length - netbuf->cursor >= 4);
    uint32_t result = ntohs(*((uint32_t*)(netbuf->buffer + netbuf->cursor)));
    netbuf->cursor += 4;
    return result;
}

int64_t chtg_netbuf_decode_int64(chtg_network_buffer* netbuf) {
    assert(netbuf->length - netbuf->cursor >= 8);
    int64_t result = (int64_t)ntohs(*((uint64_t*)(netbuf->buffer + netbuf->cursor)));
    netbuf->cursor += 8;
    return result;
}

uint64_t chtg_netbuf_decode_uint64(chtg_network_buffer* netbuf) {
    assert(netbuf->length - netbuf->cursor >= 8);
    uint64_t result = ntohs(*((uint64_t*)(netbuf->buffer + netbuf->cursor)));
    netbuf->cursor += 8;
    return result;
}


void chtg_decode_packet_header(chtg_packet_header* header, chtg_network_buffer* buffer) {
    assert(header);
    assert(buffer);

    header->magic = chtg_netbuf_decode_uint32(buffer);
    header->version = chtg_netbuf_read_byte(buffer);
    header->packet_id = chtg_netbuf_read_byte(buffer);
    header->length = chtg_netbuf_decode_uint32(buffer);
}

void chtg_encode_packet_header(chtg_packet_header header, chtg_network_buffer* buffer) {
    assert(buffer);

    chtg_netbuf_encode_uint32(buffer, header.magic);
    chtg_netbuf_write_byte(buffer, header.version);
    chtg_netbuf_write_byte(buffer, header.packet_id);
    chtg_netbuf_encode_uint32(buffer, header.length);
}


/* HEALTHCHECK */


void chtg_decode_health_check_packet(chtg_health_check_packet* packet, chtg_network_buffer* buffer) {
    packet->ping_pong = (chtg_ping_pong)chtg_netbuf_read_byte(buffer);
}

char* chtg_encode_health_check_packet(chtg_health_check_packet packet, size_t* out_length) {
    size_t packet_data_length = 1;

    size_t buffer_length = packet_data_length + CHTG_PACKET_HEADER_SIZE;
    if (out_length) *out_length = buffer_length;

    chtg_network_buffer buffer = {
        .buffer = malloc(buffer_length),
        .length = buffer_length
    };

    chtg_packet_header header = {
        .magic = CHTG_MAGIC,
        .version = CHTG_VERSION,
        .packet_id = (packet.ping_pong == CHTG_PONG ? SERVER_HEALTHCHECK : CLIENT_HEALTHCHECK),
        .length = packet_data_length,
    };

    chtg_encode_packet_header(header, &buffer);
    chtg_netbuf_write_byte(&buffer, (char)packet.ping_pong);

    return buffer.buffer;
}

int chtg_build_packet_healthcheck(packet_t *packet, uint8_t is_client, uint8_t is_ping){

    size_t content_length = 1;
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = (is_client? CLIENT_HEALTHCHECK : SERVER_HEALTHCHECK),
                                        .length  = htonl(content_length) };

    packet->content[0] = (is_ping? 1 : 0);

    return 0;
}


/* LOGIN */

int chtg_build_packet_user_login(packet_t *packet, char* username, char* password){

    size_t content_length = strlen(username)+strlen(password)+1;
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = CLIENT_LOGIN,
                                        .length  = htonl(content_length) };

    strncpy(packet->content,username,content_length);
    packet->content[strlen(username)]='\0';
    size_t taken = strlen(username)+1;
    strncpy(packet->content+taken,password,content_length-taken);

    return 0;
}

int chtg_build_packet_user_login_response(packet_t *packet, enum return_status status, char *failed_message){

    size_t content_length;

    switch(status){
        case STATUS_SUCCESS:
            content_length = 1;
            break;
        case STATUS_FAILED:
            content_length = 1+strlen(failed_message);
            break;
        default:
            //TODO: log error (logka?) of unimplemented return status
            return -1;
    }
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = SERVER_USER_LOGIN_RESPONSE,
                                        .length  = htonl(content_length) };

    packet->content[0] = (uint8_t)status;
    strncpy(packet->content+1,failed_message,content_length-1);

    return 0;
}


/* SEND MESSAGE */

int chtg_build_packet_send_message(packet_t *packet, char *message_text, uint8_t num_media, uint64_t *media_ids){

    size_t content_length = 1+8*(size_t)num_media+strlen(message_text);
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = CLIENT_SEND_MESSAGE,
                                        .length  = htonl(content_length) };

    packet->content[0] = num_media;
    size_t taken = 1;
    // TODO: assert sizeof(pack_media_id)==8 before looping? 8bytes is from PROTOCOL.txt
    for(int i=0; i<num_media; i++){
        uint64_t pack_media_id = htonll(media_ids[i]);
        memcpy(packet->content+taken, &pack_media_id, sizeof(pack_media_id));
        taken += sizeof(pack_media_id);
        if(content_length < taken){
            // TODO log error (logka?) something went wrong with logic
            return -1;
        }
    }
    if(content_length!=taken){
        // TODO log error (logka?) something went wrong with logic
        return -1;
    }

    return 0;
}


int chtg_build_packet_send_message_ack(packet_t *packet, enum return_status status, uint64_t message_id, char *error_message){

    size_t content_length;

    switch(status){
        case STATUS_SUCCESS:
            content_length = 1+8;
            break;
        case STATUS_FAILED:
            content_length = 1+8+strlen(error_message);
            break;
        default:
            //TODO: log error (logka?) of unimplemented return status
            return -1;
    }
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = SERVER_SEND_MESSAGE_ACK,
                                        .length  = htonl(content_length) };

    // TODO: assert sizeof(pack_message_id)==8? 8bytes is from PROTOCOL.txt
    packet->content[0] = (uint8_t)status;
    uint64_t pack_message_id = htonll(message_id);
    memcpy(packet->content+1, &pack_message_id, sizeof(pack_message_id));
    if(status == STATUS_FAILED){
        strncpy(packet->content+1+8,error_message,content_length-1-8);
    }

    return 0;
}


/* SEND MEDIA */

int chtg_build_packet_send_media(packet_t *packet, char *filename, enum media_type type, char *media_data, size_t media_size){

    size_t content_length = 1+strlen(filename)+1+media_size;
    if(strlen(filename)>256){
        // TODO log error (logka?) filename too large
        return -1;
    }
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = CLIENT_SEND_MEDIA,
                                        .length  = htonl(content_length) };

    packet->content[0] = strlen(filename);
    size_t taken = 1;
    strncpy(packet->content+taken, filename, content_length-taken);
    taken += strlen(filename);
    packet->content[taken] = type;
    taken += 1;
    memcpy(packet->content+taken, media_data, media_size);
    if(content_length!=taken+media_size){
        // TODO log error (logka?) something went really wrong with logic
        return -1;
    }

    return 0;
}


int chtg_build_packet_send_media_ack(packet_t *packet, enum return_status status, uint64_t message_id, char *error_message){

    size_t content_length;

    switch(status){
        case STATUS_SUCCESS:
            content_length = 1+8;
            break;
        case STATUS_FAILED:
            content_length = 1+8+strlen(error_message);
            break;
        default:
            //TODO: log error (logka?) of unimplemented return status
            return -1;
    }
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = SERVER_SEND_MEDIA_ACK,
                                        .length  = htonl(content_length) };

    // TODO: assert sizeof(pack_media_id)==8? 8bytes is from PROTOCOL.txt
    packet->content[0] = (uint8_t)status;
    uint64_t pack_media_id = htonll(message_id);
    memcpy(packet->content+1, &pack_media_id, sizeof(pack_media_id));
    if(status == STATUS_FAILED){
        strncpy(packet->content+1+8,error_message,content_length-1-8);
    }

    return 0;
}


/* GET CHANNELS LIST */

int chtg_build_packet_get_channels_list(packet_t *packet){

    size_t content_length = 0;

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = CLIENT_GET_CHANNELS_LIST,
                                        .length  = htonl(content_length) };

    return 0;
}


/* TODO : THIS FUNCTION IS WHEN I STOPPED IMPLEMENTING, CONTINUE WITH IT */
int chtg_build_packet_channels_list(packet_t *packet, enum return_status status, uint16_t num_channels, uint64_t *channel_ids, char *error_message){

    size_t content_length;

    switch(status){
        case STATUS_SUCCESS:
            content_length = 1+2+8*(size_t)num_channels;
            break;
        case STATUS_FAILED:
            content_length = 1+2+8*(size_t)num_channels+strlen(error_message);
            break;
        default:
            //TODO: log error (logka?) of unimplemented return status
            return -1;
    }
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = SERVER_CHANNELS_LIST,
                                        .length  = htonl(content_length) };

    packet->content[0] = (uint8_t)status;
    size_t taken = 1;
    uint16_t pack_num_channels = htons(num_channels);
    memcpy(packet->content+taken, &pack_num_channels, sizeof(pack_num_channels));
    // TODO: is this way better? *((uint16_t*)(packet->content+taken)) = htons(num_channels);
    taken += 2; // TODO: assert sizeof(pack_num_channels)==2?
    // TODO: assert sizeof(pack_channel_id)==8 before looping? 8bytes is from PROTOCOL.txt
    for(int i=0; i<num_channels; i++){
        uint64_t pack_channel_id = htonll(channel_ids[i]);
        memcpy(packet->content+taken, &pack_channel_id, sizeof(pack_channel_id));
        taken += sizeof(pack_channel_id);
        if(content_length < taken){
            // TODO log error (logka?) something went wrong with logic
            return -1;
        }
    }
    if(status == STATUS_FAILED){
        if(content_length!=taken+strlen(error_message)){
            // TODO log error (logka?) something went wrong with logic
            return -1;
        }
        strncpy(packet->content+taken,error_message,content_length-taken);
        taken += strlen(error_message);
    }
    if(content_length!=taken){
        // TODO log error (logka?) something went wrong with logic
        return -1;
    }

    return 0;
}


/* GET CHANNELS */

int chtg_build_packet_get_channels(packet_t *packet, uint16_t num_channels, uint64_t *channel_ids){

    size_t content_length = 1+8*(size_t)num_channels;
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = CLIENT_GET_CHANNELS,
                                        .length  = htonl(content_length) };

    uint16_t pack_num_channels = htons(num_channels);
    memcpy(packet->content, &pack_num_channels, sizeof(pack_num_channels));
    size_t taken = 2;
    // TODO: is this way better? *((uint16_t*)(packet->content)) = htons(num_channels);
    // TODO: assert sizeof(pack_channel_id)==8 before looping? 8bytes is from PROTOCOL.txt
    for(int i=0; i<num_channels; i++){
        uint64_t pack_channel_id = htonll(channel_ids[i]);
        memcpy(packet->content+taken, &pack_channel_id, sizeof(pack_channel_id));
        taken += sizeof(pack_channel_id);
        if(content_length < taken){
            // TODO log error (logka?) something went wrong with logic
            return -1;
        }
    }
    if(content_length!=taken){
        // TODO log error (logka?) something went wrong with logic
        return -1;
    }

    return 0;
}

int chtg_build_packet_channels(packet_t *packet, enum return_status status, uint16_t num_channels, channel_t *channels, char *error_message){

    size_t content_length;

    switch(status){
        case STATUS_SUCCESS:
            content_length = 1+2; //to be updated later
            break;
        case STATUS_FAILED:
            content_length = 1+2+strlen(error_message); //to be updated later
            break;
        default:
            //TODO: log error (logka?) of unimplemented return status
            return -1;
    }
    if(packet->max_size < content_length){
        // TODO log error (logka?) not enough space allocated
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = SERVER_CHANNELS,
                                        .length  = 0 }; //to be updated later

    packet->content[0] = (uint8_t)status;
    size_t taken = 1;
    uint16_t pack_num_channels = htons(num_channels);
    memcpy(packet->content+taken, &pack_num_channels, sizeof(pack_num_channels));
    // TODO: is this way better? *((uint16_t*)(packet->content+taken)) = htons(num_channels);
    taken += 2; // TODO: assert sizeof(pack_num_channels)==2?
    // TODO: assert sizeof(pack_channel_id)==8 before looping? 8bytes is from PROTOCOL.txt
    for(int i=0; i<num_channels; i++){
        if(packet->max_size-taken < 8+1+strlen(channels[i].name)+1 ){
            // TODO log error (logka?) not enough space allocated
            return -1;
        }
        uint64_t pack_channel_id = htonll(channels[i].channel_id);
        memcpy(packet->content+taken, &pack_channel_id, sizeof(pack_channel_id));
        taken += sizeof(pack_channel_id);
        if(strlen(channels[i].name)>256){
            return -1; // TODO log error?
        }
        packet->content[taken] = strlen(channels[i].name);
        taken += 1;
        strncpy(packet->content+taken, channels[i].name, strlen(channels[i].name));
        uint64_t pack_icon_id = htonll(channels[i].icon_id);
        memcpy(packet->content+taken, &pack_icon_id, sizeof(pack_channel_id));
        taken += sizeof(pack_icon_id);
    }
    if(status == STATUS_FAILED){
        if(packet->max_size < taken){
            // TODO log error (logka?) not enough space allocated / something wrong (think about it)
            return -1;
        }
        strncpy(packet->content+taken,error_message,strlen(error_message));
    }

    content_length = taken;
    packet->header.length = htonl(content_length);

    return 0;

}


/* GET HISTORY */

int chtg_build_packet_get_history(packet_t *packet, uint64_t channel_id, uint64_t unix_timestamp, int8_t num_messages_back){

    size_t content_length = 8+8+1;
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = CLIENT_GET_HISTORY,
                                        .length  = htonl(content_length) };

    uint64_t pack_channel_id = htonll(channel_id);
    memcpy(packet->content, &pack_channel_id, sizeof(pack_channel_id));
    uint64_t pack_unix_timestamp = htonll(unix_timestamp);
    memcpy(packet->content+8, &pack_unix_timestamp, sizeof(pack_unix_timestamp));
    packet->content[8+8] = num_messages_back;

    return 0;
}

int chtg_build_packet_history(packet_t *packet, enum return_status status, int8_t num_messages, message_t *messages, char *error_message){

    size_t content_length;

    switch(status){
        case STATUS_SUCCESS:
            content_length = 1+1; //to be updated later
            break;
        case STATUS_FAILED:
            content_length = 1+1+strlen(error_message); //to be updated later
            break;
        default:
            //TODO: log error (logka?) of unimplemented return status
            return -1;
    }
    if(packet->max_size < content_length){
        // TODO log error (logka?) not enough space allocated
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = SERVER_HISTORY,
                                        .length  = 0 }; //to be updated later

    packet->content[0] = (uint8_t)status;
    size_t taken = 1;
    packet->content[taken] = num_messages;
    taken += 1;
    // TODO: assert sizeof(pack_message_id)==8 before looping? 8bytes is from PROTOCOL.txt
    for(int i=0; i<num_messages; i++){
        if(packet->max_size-taken < 8+8+8+8+8+2+strlen(messages[i].message_text)+1+8*messages[i].num_media ){
            // TODO log error (logka?) not enough space allocated
            return -1;
        }
        //message_id
        uint64_t pack_message_id = htonll(messages[i].message_id);
        memcpy(packet->content+taken, &pack_message_id, sizeof(pack_message_id));
        taken += sizeof(pack_message_id);
        //sent_timestamp
        uint64_t pack_sent_timestamp = htonll(messages[i].sent_timestamp);
        memcpy(packet->content+taken, &pack_sent_timestamp, sizeof(pack_sent_timestamp));
        taken += sizeof(pack_sent_timestamp);
        //user_id
        uint64_t pack_user_id = htonll(messages[i].user_id);
        memcpy(packet->content+taken, &pack_user_id, sizeof(pack_user_id));
        taken += sizeof(pack_user_id);
        //channel_id
        uint64_t pack_channel_id = htonll(messages[i].channel_id);
        memcpy(packet->content+taken, &pack_channel_id, sizeof(pack_channel_id));
        taken += sizeof(pack_channel_id);
        //reply_id
        uint64_t pack_reply_id = htonll(messages[i].reply_id);
        memcpy(packet->content+taken, &pack_reply_id, sizeof(pack_reply_id));
        taken += sizeof(pack_reply_id);
        //message_len
        if(strlen(messages[i].message_text)>UINT16_MAX){
            // TODO log error (logka?) message too long
            return -1;
        }
        uint16_t pack_message_len = htons(strlen(messages[i].message_text));
        memcpy(packet->content+taken, &pack_message_len, sizeof(pack_message_len));
        taken += sizeof(pack_message_len);
        //message
        memcpy(packet->content+taken, messages[i].message_text, strlen(messages[i].message_text));
        taken += strlen(messages[i].message_text);
        //num_media
        packet->content[taken] = messages[i].num_media;
        taken += 1;
        for(int j=0; j<messages[i].num_media; j++){
            //media_id
            uint64_t pack_media_id = htonll(messages[i].media_ids[j]);
            memcpy(packet->content+taken, &pack_media_id, sizeof(pack_media_id));
            taken += sizeof(pack_media_id);
        }
    }
    if(status == STATUS_FAILED){
        if(packet->max_size < taken){
            // TODO log error (logka?) not enough space allocated / something wrong (think about it)
            return -1;
        }
        strncpy(packet->content+taken,error_message,strlen(error_message));
    }

    content_length = taken;
    packet->header.length = htonl(content_length);

    return 0;

}


/* GET USERS */

int chtg_build_packet_get_users(packet_t *packet, uint8_t num_users, uint64_t *user_ids){

    size_t content_length = 1+8*(size_t)num_users;
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = CLIENT_GET_USERS,
                                        .length  = htonl(content_length) };

    packet->content[0] = num_users;
    size_t taken = 1;
    // TODO: assert sizeof(pack_user_id)==8 before looping? 8bytes is from PROTOCOL.txt
    for(int i=0; i<num_users; i++){
        uint64_t pack_user_id = htonll(user_ids[i]);
        memcpy(packet->content+taken, &pack_user_id, sizeof(pack_user_id));
        taken += sizeof(pack_user_id);
        if(content_length < taken){
            // TODO log error (logka?) something went wrong with logic
            return -1;
        }
    }
    if(content_length!=taken){
        // TODO log error (logka?) something went wrong with logic
        return -1;
    }

    return 0;
}

int chtg_build_packet_users(packet_t *packet, enum return_status status, uint8_t num_users, user_t *users, char *error_message){

    size_t content_length;

    switch(status){
        case STATUS_SUCCESS:
            content_length = 1+1; //to be updated later
            break;
        case STATUS_FAILED:
            content_length = 1+1+strlen(error_message); //to be updated later
            break;
        default:
            //TODO: log error (logka?) of unimplemented return status
            return -1;
    }
    if(packet->max_size < content_length){
        // TODO log error (logka?) not enough space allocated
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = SERVER_USERS,
                                        .length  = 0 }; //to be updated later

    packet->content[0] = (uint8_t)status;
    size_t taken = 1;
    packet->content[taken] = num_users;
    taken += 1;
    // TODO: assert sizeof(pack_user_id)==8 before looping? 8bytes is from PROTOCOL.txt
    for(int i=0; i<num_users; i++){
        if(packet->max_size-taken < 8+1+strlen(users[i].username)+8+2+users[i].bio_length ){
            // TODO log error (logka?) not enough space allocated
            return -1;
        }
        //user_id
        uint64_t pack_user_id = htonll(users[i].user_id);
        memcpy(packet->content+taken, &pack_user_id, sizeof(pack_user_id));
        taken += sizeof(pack_user_id);
        //username_length + username
        if(strlen(users[i].username)>256){ //should be impossible but just in case
            return -1; // TODO log error?
        }
        packet->content[taken] = strlen(users[i].username);
        taken += 1;
        strncpy(packet->content+taken, users[i].username, strlen(users[i].username));
        taken += strlen(users[i].username);
        //pfp_id
        uint64_t pack_profile_picture_id = htonll(users[i].profile_picture_id);
        memcpy(packet->content+taken, &pack_profile_picture_id, sizeof(pack_profile_picture_id));
        taken += sizeof(pack_profile_picture_id);
        //bio_lenght + bio
        uint16_t pack_bio_length = htons(users[i].bio_length);
        memcpy(packet->content+taken, &pack_bio_length, sizeof(pack_bio_length));
        taken += sizeof(pack_bio_length);
        memcpy(packet->content+taken, users[i].bio,users[i].bio_length);
        taken += users[i].bio_length;
    }
    if(status == STATUS_FAILED){
        if(packet->max_size < taken){
            // TODO log error (logka?) not enough space allocated / something wrong (think about it)
            return -1;
        }
        strncpy(packet->content+taken,error_message,strlen(error_message));
    }

    content_length = taken;
    packet->header.length = htonl(content_length);

    return 0;
}


/* GET MEDIA */

int chtg_build_packet_get_media(packet_t *packet, uint64_t media_id){

    size_t content_length = 4;
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = CLIENT_GET_MEDIA,
                                        .length  = htonl(content_length) };

    uint64_t pack_media_id = htonll(media_id);
    memcpy(packet->content, &pack_media_id, sizeof(pack_media_id));

    return 0;
}

int chtg_build_packet_media(packet_t *packet, enum return_status status, enum media_type type, media_t *media, char *error_message){

    size_t content_length;

    if(strlen(media->filename)>256){
        // TODO log error (logka?) filename too large
        return -1;
    }
    switch(status){
        case STATUS_SUCCESS:
            content_length = 1+1+strlen(media->filename)+1+4+media->size;
            break;
        case STATUS_FAILED:
            content_length = 1+1+strlen(media->filename)+1+4+media->size+strlen(error_message);
            break;
        default:
            //TODO: log error (logka?) of unimplemented return status
            return -1;
    }
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = SERVER_MEDIA,
                                        .length  = htonl(content_length) };

    packet->content[0] = (uint8_t)status;
    size_t taken = 1;
    packet->content[taken] = strlen(media->filename);
    taken += 1;
    strncpy(packet->content+taken, media->filename, content_length-taken);
    taken += strlen(media->filename);
    packet->content[taken] = type;
    taken += 1;
    uint32_t pack_media_length = htonl(media->size);
    memcpy(packet->content+taken, &pack_media_length, sizeof(pack_media_length));
    taken += sizeof(pack_media_length);
    memcpy(packet->content+taken, media->content, media->size);
    taken += media->size;
    if(content_length!=taken){
        //TODO: log error (logka?) something went wrong with logic
        return -1;
    }
    if(status == STATUS_FAILED){
        strncpy(packet->content+taken,error_message,content_length-taken);
    }

    return 0;
}


/* TYPING */

int chtg_build_packet_typing(packet_t *packet, uint8_t is_typing){

    size_t content_length = 1;
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = CLIENT_TYPING,
                                        .length  = htonl(content_length) };

    packet->content[0] = (is_typing? 1 : 0);

    return 0;
}

int chtg_build_packet_user_typing(packet_t *packet, uint64_t user_id, uint8_t is_typing){

    size_t content_length = 1+8;
    if(packet->max_size < content_length){
        return -1;
    }

    packet->header = (packet_header_t){ .magic   = htonl(chtg_magic),
                                        .version = chtg_version,
                                        .type    = SERVER_USER_TYPING,
                                        .length  = htonl(content_length) };

    packet->content[0] = (is_typing? 1 : 0);
    uint64_t pack_user_id = htonll(user_id);
    memcpy(packet->content, &pack_user_id, sizeof(pack_user_id));

    return 0;
}



#endif // CHTG_PROTOCOL_IMPLEMENTATION

