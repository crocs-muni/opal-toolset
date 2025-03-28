// SPDX-License-Identifier: MIT

#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include "bitops.h"

#define UCHR(x) (const unsigned char*)(x)

enum log_level {
    ERROR,
    INFO,
    EVERYTHING,
};
extern enum log_level current_log_level;

#define LOG(level, ...)                                                                                                \
    do {                                                                                                                  \
        if (level <= current_log_level) {                                                                              \
            fprintf(stderr, "[%i:" __FILE__ ":%s():%i] ", level, __PRETTY_FUNCTION__, __LINE__);                       \
            fprintf(stderr, __VA_ARGS__);                                                                              \
        }                                                                                                              \
    } while (0)

#define LOG_C(level, ...)                                                                                              \
    do {                                                                                                                  \
        if (level <= current_log_level) {                                                                              \
            fprintf(stderr, __VA_ARGS__);                                                                              \
        }                                                                                                              \
    } while (0)

void LOG_HEX(const void *ptr, unsigned len);

/* interrupt handling */
extern volatile int quit;
void set_int_block(int block);
void set_int_handler(int block);

struct com_packet {
    uint8_t reserved_1[4];
    uint16_t comid;
    uint16_t comid_extension;
    uint32_t outstanding_data;
    uint32_t min_transfer;
    uint32_t length;
}  __attribute__ ((packed));

struct packet {
    uint64_t session;
    uint32_t seq_number;
    uint8_t reserved_1[2];
    uint16_t ack_type;
    uint32_t ack;
    uint32_t length;
}  __attribute__ ((packed));

struct data_subpacket {
    uint8_t reserved_1[6];
    uint16_t kind;
    uint32_t length;
}  __attribute__ ((packed));

struct packet_headers {
    struct com_packet com_packet;
    struct packet packet;
    struct data_subpacket data_subpacket;
}  __attribute__ ((packed));

#define START_LIST_TOKEN 0xf0
#define END_LIST_TOKEN 0xf1
#define START_NAME_TOKEN 0xf2
#define END_NAME_TOKEN 0xf3
#define CALL_TOKEN 0xf8
#define END_OF_DATA_TOKEN 0xf9
#define END_OF_SESSION_TOKEN 0xfa
#define END_TRANSACTION_TOKEN 0xfc
#define EMPTY_ATOM_TOKEN 0xff

#define PADDING_ALIGNMENT 512

#define NVME_SECURITY_RECEIVE 0x82
#define NVME_SECURITY_SEND 0x81
#define NVME_IDENTIFY_COMMAND 0x06

#define ATA_PASS_THROUGH_12_OPERATION_CODE 0xa1
#define ATA_PASS_THROUGH_SEND 0
#define ATA_PASS_THROUGH_RECEIVE 1
#define ATA_TRUSTED_RECEIVE 0x5c
#define ATA_TRUSTED_SEND 0x5e
#define ATA_IDENTIFY_DEVICE_COMMAND 0xec
#define ATA_PROTOCOL_PIO_DATA_IN 4
#define ATA_PROTOCOL_PIO_DATA_OUT 5

// ATA Command Pass-Through
struct sg_cdb_ata_pass_through_12 {
    uint8_t operation_code;
    uint8_t reserved_1 : 1;
    uint8_t protocol : 4;
    uint8_t multiple_count : 3;
    uint8_t t_length : 2;
    uint8_t byt_blok : 1;
    uint8_t t_dir : 1;
    uint8_t reserved_2 : 1;
    uint8_t ck_cond : 1;
    uint8_t off_line : 2;
    union {
        struct {
            uint8_t features;
            uint8_t sector_count;
            uint8_t lba_low;
            uint8_t lba_mid;
            uint8_t lba_high;
            uint8_t device;
            uint8_t command;
        } __attribute__ ((packed)) original;
        // ACS-3
        struct {
            uint8_t security_protocol;
            uint16_t transfer_length;
            uint16_t sp_specific;
            uint8_t reserved_2 : 4;
            uint8_t transport_dependent : 1;
            uint8_t obsolete_1 : 1;
            uint8_t na : 1;
            uint8_t obsolete_2 : 1;
            uint8_t command;
        } __attribute__ ((packed)) trusted_receive;
    };
    uint8_t reserved_3;
    uint8_t control;
}  __attribute__ ((packed));

#define SCSI_SECURITY_PROTOCOL_IN  0xa2
#define SCSI_SECURITY_PROTOCOL_OUT 0xb5

struct scsi_security_protocol {
    uint8_t operation_code;
    uint8_t security_protocol;
    uint16_t security_protocol_specific;
    uint8_t reserved_1 : 7;
    uint8_t inc_512 : 1;
    uint8_t reserved_2;
    uint32_t allocation_length;
    uint8_t reserved_3;
    uint8_t control;
}  __attribute__ ((packed));

int hex_add(unsigned char *a, size_t a_len, size_t b);

#define VAL_UNDEFINED (-1)

enum TrustedCommandDirection {
    IF_RECV,
    IF_SEND,
};

#define TCG_PROTOCOL_ID_1 0x01
#define TCG_PROTOCOL_ID_2 0x02

#define TCG_GET_COMID 0x0000
#define TCG_LEVEL_0_DISCOVERY_COMID 0x0001

#define METHOD_PROPERTIES_UID UCHR("\x00\x00\x00\x00\x00\x00\xff\x01")
#define METHOD_START_SESSION_UID UCHR("\x00\x00\x00\x00\x00\x00\xff\x02")
#define METHOD_CLOSE_SESSION_UID UCHR("\x00\x00\x00\x00\x00\x00\xff\x06")
#define METHOD_NEXT_UID UCHR("\x00\x00\x00\x06\x00\x00\x00\x08")
#define METHOD_GENKEY_UID UCHR("\x00\x00\x00\x06\x00\x00\x00\x10")
#define METHOD_GET_UID UCHR("\x00\x00\x00\x06\x00\x00\x00\x16")
#define METHOD_GET_PARAMETER_START 3
#define METHOD_GET_PARAMETER_END 4
#define METHOD_SET_UID UCHR("\x00\x00\x00\x06\x00\x00\x00\x17")
#define METHOD_SET_PARAMETER_VALUES 1
#define METHOD_REVERT_UID UCHR("\x00\x00\x00\x06\x00\x00\x02\x02")
#define METHOD_ACTIVATE_UID UCHR("\x00\x00\x00\x06\x00\x00\x02\x03")
#define METHOD_ACTIVATE_SUM_LIST_PARAM   0x060000
#define METHOD_ACTIVATE_SUM_POLICY_PARAM 0x060001
#define METHOD_REACTIVATE_UID UCHR("\x00\x00\x00\x06\x00\x00\x08\x01")
#define METHOD_RANDOM_UID UCHR("\x00\x00\x00\x06\x00\x00\x06\x01")
#define METHOD_ERASE_UID UCHR("\x00\x00\x00\x06\x00\x00\x08\x03")

#define TABLE_TABLE_UID UCHR("\x00\x00\x00\x01\x00\x00\x00\x00")
#define TABLE_C_PIN_UID UCHR("\x00\x00\x00\x0b\x00\x00\x00\x00")
#define TABLE_C_PIN_ROW_SID_UID UCHR("\x00\x00\x00\x0b\x00\x00\x00\x01")
#define TABLE_C_PIN_ROW_MSID_UID UCHR("\x00\x00\x00\x0b\x00\x00\x84\x02")
#define TABLE_C_PIN_ROW_USER_XXXX UCHR("\x00\x00\x00\x0b\x00\x03\x00\x00")
#define TABLE_C_PIN_COLUMN_PIN 3
#define TABLE_SP_UID UCHR("\x00\x00\x02\x05\x00\x00\x00\x00")
#define TABLE_SP_COLUMN_UID 0
#define TABLE_AUTHORITY_ROW_USER_XXXX UCHR("\x00\x00\x00\x09\x00\x03\x00\x00")
#define TABLE_AUTHORITY_COLUMN_ENABLED 5
#define TABLE_ACE_ROW_LOCKING_RANGE_XXXX_SET_RD_LOCKED UCHR("\x00\x00\x00\x08\x00\x03\xe0\x00")
#define TABLE_ACE_ROW_LOCKING_RANGE_XXXX_SET_WR_LOCKED UCHR("\x00\x00\x00\x08\x00\x03\xe8\x00")
#define TABLE_ACE_LOCKING_RANGE_XXXX_GET_PARAMS UCHR("\x00\x00\x00\x08\x00\x03\xd0\x00")
#define TABLE_ACE_COLUMN_BOOLEAN_EXPR 3

#define HALF_UID_AUTHORITY_OBJECT_REF UCHR("\x00\x00\x0c\x05")
#define HALF_UID_BOOLEAN_ACE UCHR("\x00\x00\x04\x0e")
#define BOOLEAN_OR 1

#define ADMIN_BASE_ID 0x00010000 // 00 00 00 09 00 01 00 00
#define USER_BASE_ID 0x00030000 // 00 00 00 09 00 03 00 00
#define SPECIAL_BASE_ID 0x00090000
#define ANYBODY_USER_ID 0x00090001
#define SID_USER_ID 0x00090002
#define PSID_USER_ID 0x00090003

#define SMUID UCHR("\x00\x00\x00\x00\x00\x00\x00\xff")
#define THISSP UCHR("\x00\x00\x00\x00\x00\x00\x00\x01")
#define ADMIN_SP_UID UCHR("\x00\x00\x02\x05\x00\x00\x00\x01")
#define LOCKING_SP_UID UCHR("\x00\x00\x02\x05\x00\x00\x00\x02")

#define AUTHORITY_XXXX_UID UCHR("\x00\x00\x00\x09\x00\x00\x00\x00")
#define AUTHORITY_SID_UID UCHR("\x00\x00\x00\x09\x00\x00\x00\x06")
#define AUTHORITY_PSID_UID UCHR("\x00\x00\x00\x09\x00\x01\xff\x01")

#define LOCKING_TABLE_UID UCHR("\x00\x00\x08\x02\x00\x00\x00\x00")
#define LOCKING_RANGE_GLOBAL_UID UCHR("\x00\x00\x08\x02\x00\x00\x00\x01")
#define LOCKING_RANGE_NNNN_UID UCHR("\x00\x00\x08\x02\x00\x03\x00\x00")
#define LOCKING_RANGE_1_UID UCHR("\x00\x00\x08\x02\x00\x03\x00\x01")
#define LOCKING_RANGE_COLUMN_RANGE_START 3
#define LOCKING_RANGE_COLUMN_RANGE_LENGTH 4
#define LOCKING_RANGE_COLUMN_READ_LOCK_ENABLED 5
#define LOCKING_RANGE_COLUMN_WRITE_LOCK_ENABLED 6
#define LOCKING_RANGE_COLUMN_READ_LOCKED 7
#define LOCKING_RANGE_COLUMN_WRITE_LOCKED 8
#define LOCKING_RANGE_COLUMN_LOCK_ON_RESET 9
#define LOCKING_RANGE_COLUMN_LOCK_ON_RESET_POWER_CYCLE 0
#define LOCKING_RANGE_COLUMN_LOCK_ON_RESET_HARDWARE_RESET 1
#define LOCKING_RANGE_COLUMN_LOCK_ON_RESET_PROGRAMMATIC 3
#define LOCKING_RANGE_COLUMN_ACTIVE_KEY 10

#define LOCKING_INFO_UID UCHR("\x00\x00\x08\x01\x00\x00\x00\x01")
#define LOCKING_INFO_COLUMN_ALIGNMENT_REQUIRED 7
#define LOCKING_INFO_COLUMN_LOGICAL_BLOCK_SIZE 8
#define LOCKING_INFO_COLUMN_ALIGNMENT_GRANULARITY 9
#define LOCKING_INFO_COLUMN_LOWEST_ALIGNED_LBA 10

#define TPER_RESET_COMID 0x0004
#define TABLE_TPER_INFO_OBJ_UID UCHR("\x00\x00\x02\x01\x00\x03\x00\x01")
#define TABLE_TPER_INFO_COLUMN_PROGRAMMATIC_RESET_ENABLE 8
#define DATA_REMOVAL_MECHANISM_OBJ_UID UCHR("\x00\x00\x11\x01\x00\x00\x00\x01")
#define DATA_REMOVAL_COLUMN_ACTIVE_MECHANISM 1

// Table 166 Status Codes
enum MethodStatusCode {
    MSC_SUCCESS = 0x00,
    MSC_NOT_AUTHORIZED = 0x01,
    // MSC_OBSOLETE = 0x02,
    MSC_SP_BUSY = 0x03,
    MSC_SP_FAILED = 0x04,
    MSC_SP_DISABLED = 0x05,
    MSC_SP_FROZEN = 0x06,
    MSC_NO_SESSIONS_AVAILABLE = 0x07,
    MSC_UNIQUENESS_CONFLICT = 0x08,
    MSC_INSUFFICIENT_SPACE = 0x09,
    MSC_INSUFFICIENT_ROWS = 0x0A,
    MSC_INVALID_PARAMETER = 0x0C,
    // MSC_OBSOLETE = 0x0D,
    // MSC_OBSOLETE = 0x0E,
    MSC_TPER_MALFUNCTION = 0x0F,
    MSC_TRANSACTION_FAILURE = 0x10,
    MSC_RESPONSE_OVERFLOW = 0x11,
    MSC_AUTHORITY_LOCKED_OUT = 0x12,
    MSC_FAIL = 0x3F,
};
const char *error_to_string(enum MethodStatusCode msc);

struct nvme_identify_controller_data {
    uint8_t vid[2];
    uint8_t ssvid[2];
    uint8_t sn[20];
    uint8_t model_number[40];
    uint8_t firmware_revision[8];
    uint8_t _filler[184];
}  __attribute__ ((packed));

struct level_0_discovery_header {
    uint32_t length;
    uint32_t revision;
    u_int8_t reserved[8];
    u_int8_t vendor_specific[32];
}  __attribute__ ((packed));

struct level_0_discovery_feature_shared {
    uint16_t feature_code;
    uint8_t reserved_minor : 4;
    uint8_t descriptor_version : 4;
    uint8_t length;
}  __attribute__ ((packed));

struct level_0_discovery_tper_feature {
    struct level_0_discovery_feature_shared shared;
    uint8_t sync_supported : 1;
    uint8_t async_supported : 1;
    uint8_t ack_nack_supported : 1;
    uint8_t buffer_mgmt_supported : 1;
    uint8_t streaming_supported : 1;
    uint8_t reserved_2 : 1;
    uint8_t comID_mgmt_supported : 1;
    uint8_t reserved_3 : 1;
    uint8_t reserved_4[11];
}  __attribute__ ((packed));

struct level_0_discovery_geometry_feature {
    struct level_0_discovery_feature_shared shared;
    uint8_t align : 1;
    uint8_t reserved_2 : 7;
    uint8_t reserved_3[7];
    uint32_t logical_block_size;
    uint64_t alignment_granularity;
    uint64_t lowest_alignment_LBA;
}  __attribute__ ((packed));

struct level_0_discovery_lockin_feature {
    struct level_0_discovery_feature_shared shared;
    uint8_t locking_supported : 1;
    uint8_t locking_enabled : 1;
    uint8_t locked : 1;
    uint8_t media_encryption : 1;
    uint8_t MBR_enabled : 1;
    uint8_t MBR_done : 1;
    uint8_t hw_reset_for_lor_dor_supported : 1;
    uint8_t mbr_shadowing_not_supported : 1;
    uint8_t reserved_3[11];
}  __attribute__ ((packed));

struct level_0_discovery_opal_2_feature {
    struct level_0_discovery_feature_shared shared;
    uint16_t base_comID;
    uint16_t number_of_comIDs;
    uint8_t range_crossing_behaviour : 1;
    uint8_t reserved_1 : 7;
    uint16_t number_of_locking_admin_authorities_supported;
    uint16_t number_of_locking_user_authorities_supported;
    uint8_t initial_pin_indicator;
    uint8_t behavior_of_pin_upon_revert;
    uint8_t reserved_2[5];
}  __attribute__ ((packed));

struct level_0_discovery_opal_1_feature {
    struct level_0_discovery_feature_shared shared;
    uint16_t base_comID;
    uint16_t number_of_comIDs;
    uint8_t range_crossing : 1;
    uint8_t reserved_1 : 7;
    uint8_t reserved_2[11];
}  __attribute__ ((packed));

struct level_0_discovery_single_user_mode_feature {
    struct level_0_discovery_feature_shared shared;
    uint32_t number_of_locking_objects_supported;
    uint8_t any : 1;
    uint8_t all : 1;
    uint8_t policy : 1;
    uint8_t reserved_1 : 5;
    uint8_t reserved_2[7];
}  __attribute__ ((packed));

struct level_0_discovery_data_store_feature {
    struct level_0_discovery_feature_shared shared;
    uint16_t reserved_1;
    uint16_t maximum_number_of_tables;
    uint32_t maximum_total_size_of_tables;
    uint32_t table_size_alignment;
}  __attribute__ ((packed));

struct level_0_discovery_block_sid_authentication_feature {
    struct level_0_discovery_feature_shared shared;
    uint8_t sid_value_state : 1;
    uint8_t sid_authentication_blocked_state : 1;
    uint8_t locking_sp_freeze_lock_supported : 1;
    uint8_t locking_sp_freeze_lock_state : 1;
    uint8_t reserved_1 : 4;
    uint8_t hardware_reset : 1;
    uint8_t reserved_2 : 7;
    uint8_t reserved_3;
}  __attribute__ ((packed));

struct level_0_discovery_pyrite_feature {
    struct level_0_discovery_feature_shared shared;
    uint16_t base_comID;
    uint16_t number_of_comIDs;
    uint8_t reserved_1[5];
    uint8_t initial_pin_indicator;
    uint8_t behavior_of_pin_upon_revert;
    uint8_t reserved_2[5];
}  __attribute__ ((packed));

struct level_0_discovery_supported_data_removal_mechanism_feature {
    struct level_0_discovery_feature_shared shared;
    uint8_t reserved_1;
    uint8_t data_removal_operation_processing : 1;
    uint8_t reserved_2 : 7;
    uint8_t supported_data_removal_mechanism;
    uint8_t data_removal_time_format;
    uint16_t data_removal_time_for_supported_data_removal_mechanism[6];
    uint8_t reserved_3[16];
}  __attribute__ ((packed));

struct level_0_discovery_ns_locking_feature {
    struct level_0_discovery_feature_shared shared;
    uint8_t reserved_1 : 5;
    uint8_t sum_c : 1;
    uint8_t range_p : 1;
    uint8_t range_c : 1;
    uint8_t reserved_2[3];
    uint32_t maximum_key_count;
    uint32_t unused_key_count;
    uint32_t maximum_ranges_per_ns;
}  __attribute__ ((packed));

struct level_0_discovery_ns_geometry_feature {
    struct level_0_discovery_feature_shared shared;
    uint8_t align : 1;
    uint8_t reserved_2 : 7;
    uint8_t reserved_3[7];
    uint32_t logical_block_size;
    uint64_t alignment_granularity;
    uint64_t lowest_alignment_LBA;
}  __attribute__ ((packed));

/* Storage Interface Interactions Specification (SIIS) */
struct level_0_discovery_siis_feature {
    struct level_0_discovery_feature_shared shared;
    uint8_t siis_revision;
    uint8_t key_change_zone_behavior : 1;
    uint8_t identifier_usage_scope : 2;
    uint8_t reserved_1 : 5;
    uint8_t reserved_2[10];
}  __attribute__ ((packed));

#define DISK_DEVICE_UNKNOWN_FEATURE_MAX_LENGTH 1024
struct disk_device {
    int fd;
    enum disk_device_type {
        NVME,
        SATA,
        SCSI,
    } type;

    char *name;
    uint16_t base_com_id;
    uint32_t host_session_id;
    uint32_t sp_session_id;

    struct {
        uint32_t discovery0_revision;
        struct level_0_discovery_tper_feature tper;
        struct level_0_discovery_lockin_feature locking;
        struct level_0_discovery_geometry_feature geometry;
        struct level_0_discovery_opal_2_feature opal2;
        struct level_0_discovery_opal_1_feature opal1;
        struct level_0_discovery_single_user_mode_feature single_user_mode;
        struct level_0_discovery_data_store_feature data_store;
        struct level_0_discovery_block_sid_authentication_feature block_sid_authentication;
        struct level_0_discovery_pyrite_feature pyrite2;
        struct level_0_discovery_pyrite_feature pyrite1;
        struct level_0_discovery_supported_data_removal_mechanism_feature supported_data_removal_mechanism;
        struct level_0_discovery_ns_locking_feature ns_locking;
        struct level_0_discovery_ns_geometry_feature ns_geometry;
        struct level_0_discovery_siis_feature siis;
        uint8_t unknown[DISK_DEVICE_UNKNOWN_FEATURE_MAX_LENGTH];
        size_t unknown_len;
    } features;
};

#define TCG_REQUEST_CODE_NO_RESPONSE 0x00
#define TCG_REQUEST_CODE_COMID_VALID 0x01
#define TCG_REQUEST_CODE_STACK_RESET 0x02

struct get_comid_response {
    uint16_t comid;
    uint16_t ext_comid;
    uint8_t _padding[508];
} __attribute__ ((packed));

struct comid_valid_request {
    uint16_t comid;
    uint16_t ext_comid;
    uint32_t request_code;
    uint8_t _padding[504];
} __attribute__ ((packed));

struct comid_time {
    uint8_t  year[2];
    uint8_t  month;
    uint8_t  day;
    uint8_t  hour;
    uint8_t  minute;
    uint8_t  second;
    uint8_t  fraction[2];
    uint8_t  _reserved;
} __attribute__ ((packed));

struct comid_valid_response {
    uint16_t comid;
    uint16_t ext_comid;
    uint32_t request_code;
    uint8_t _reserved[2];
    uint16_t data_length; /* 0 => pending, 0x22 => see response */
    uint32_t state; /* 0 => invalid, 1 => inactive, 2 => issued, 3 => associated */
    struct comid_time time_allocation;
    struct comid_time time_expiry;
    struct comid_time time_reset;
    uint8_t _padding[466];
} __attribute__ ((packed));

struct stack_reset_request {
    uint16_t comid;
    uint16_t ext_comid;
    uint32_t request_code;
    uint8_t _padding[504];
} __attribute__ ((packed));

struct stack_reset_response {
    uint16_t comid;
    uint16_t ext_comid;
    uint32_t request_code;
    uint8_t _reserved[2];
    uint16_t data_length; /* 0 => pending, 4 => see response */
    uint32_t response; /* 0 => success, 1 => failure */
    uint8_t _padding[496];
} __attribute__ ((packed));

int disk_device_open(struct disk_device *dev, const char *file, bool use_scsi_sec);
void disk_device_close(struct disk_device *dev);

/**
 * Functions for writing tokens into buffer.
*/
void start_list(unsigned char *buffer, size_t *offset);
void end_list(unsigned char *buffer, size_t *offset);
void start_name(unsigned char *buffer, size_t *offset);
void end_name(unsigned char *buffer, size_t *offset);
void call_token(unsigned char *buffer, size_t *offset);
void end_of_data(unsigned char *buffer, size_t *offset);
void end_session_token(unsigned char *buffer, size_t *offset);
void method_status_list(unsigned char *buffer, size_t *offset);
void tiny_atom(unsigned char *buffer, size_t *offset,
               unsigned char is_signed,
               unsigned char value);
void short_atom(unsigned char *buffer, size_t *offset,
                unsigned char is_bytes, unsigned char is_signed,
                const uint8_t *value, size_t value_len);
void medium_atom(unsigned char *buffer, size_t *offset,
                unsigned char is_bytes, unsigned char is_signed,
                const uint8_t *value, size_t value_len);
void prepare_locking_range(unsigned char *buffer, size_t locking_range);

/**
 * Methods to construct headers of Opal packets.
*/
void prepare_headers(unsigned char *buffer, size_t *i, struct disk_device *dev);
void finish_headers(unsigned char *buffer, size_t *i);

/**
 * Methods to construct Opal method, ready to be send.
 * Constructs the packet headers, invokind ID, method ID, and method status list.
*/
void prepare_method(unsigned char *buffer, size_t *i, struct disk_device *dev, 
                    const unsigned char *invoking_uid, const unsigned char *method_uid);
void finish_method(unsigned char *buffer, size_t *i);


/**
 * Sends constructed method in buff_in and writes the response into buff_out.
*/
int invoke_method(struct disk_device *dev, unsigned char *buff_in, size_t buff_in_len,
                  unsigned char *buff_out, size_t buff_out_len);
int invoke_method_abort(struct disk_device *dev, unsigned char *buff_in, size_t buff_in_len,
                  unsigned char *buff_out, size_t buff_out_len);

/**
 * Invoke a IF-SEND/IF-RECV.
*/
int trusted_command(struct disk_device *dev, uint8_t *msg, size_t msg_len,
                    enum TrustedCommandDirection direction, int protocol, int comID);

/**
 * Methods to control a session.
*/
int start_session(struct disk_device *dev, const unsigned char *SPID, size_t user_id, 
                  const unsigned char *challenge, size_t challenge_len);
int close_session(struct disk_device *dev);
void wipe_session(struct disk_device *dev);

/**
 * Performs Level 0 Discovery process, storing found information in dev.
*/
int do_level_0_discovery(struct disk_device *dev);

/**
 * Parses the method response to get status code.
*/
int process_method_response(const unsigned char *buffer, size_t buffer_len, bool session_abort);

/**
 * Returns parsed tiny or small atom as unsigned integer.
*/
uint64_t parse_int(const unsigned char *buffer, size_t *offset);
/**
 * Parses byte token from src buffer.
 *  - offset allows to specify initial offset of src
 *  - dst optionally specifies buffer to write the parsed bytes into
 *  - written reports number of bytes written into dst
*/
int parse_bytes(const unsigned char *src, size_t *offset, unsigned char *dst, size_t dst_size, size_t *written);
/**
 * Skips potentially composite atom.
*/
int skip_atom(const unsigned char *buffer, size_t *offset, size_t total_length);
/**
 * Moves the offset iterator before specified parameter of method.
 *  - parameter specifies the index of mandatory (if skip_mandatory == 0)
 *    or optional parameter (otherwise)
 *  - skip_mandatory allows to specify the number of mandatory parameters
 *    to skip before parsing optional argument
*/
int skip_to_parameter(unsigned char *buffer, size_t *offset, int parameter, int skip_mandatory);

/**
 * Set object_uid row to contain atom. 
*/
int set_row(struct disk_device *dev, const unsigned char *object_uid, unsigned char column,
            unsigned char *atom, size_t atom_len);
/**
 * Acquire bytes contained in object_uid row.
*/
int get_row_bytes(struct disk_device *dev, const unsigned char *object_uid, unsigned char column,
                  unsigned char *output, size_t output_len, size_t *output_written);

int get_row_int(struct disk_device *dev, const unsigned char *object_uid, unsigned char column, uint64_t *output);


#endif // COMMON_H_
