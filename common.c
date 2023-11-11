// SPDX-License-Identifier: MIT

#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fscrypt.h>
#include <linux/nvme_ioctl.h>
#include <scsi/sg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#include "common.h"

enum log_level current_log_level = ERROR;

int hex_add(unsigned char *a, size_t a_len, size_t b)
{
    size_t i = 0;
    int extra = 0;
    while ((b > 0 || extra > 0) && i < a_len) {
        int next_extra = (a[a_len - i - 1] + (b % 256) + extra) > 255;

        a[a_len - i - 1] += (b % 256) + extra;

        b /= 256;
        i += 1;
        extra = next_extra;
    }

    return b > 0;
}

const char *error_to_string(enum MethodStatusCode msc)
{
    switch (msc) {
    case MSC_SUCCESS:
        return "MSC_SUCCESS";
    case MSC_NOT_AUTHORIZED:
        return "MSC_NOT_AUTHORIZED";
    case MSC_SP_BUSY:
        return "MSC_SP_BUSY";
    case MSC_SP_FAILED:
        return "MSC_SP_FAILED";
    case MSC_SP_DISABLED:
        return "MSC_SP_DISABLED";
    case MSC_SP_FROZEN:
        return "MSC_SP_FROZEN";
    case MSC_NO_SESSIONS_AVAILABLE:
        return "MSC_NO_SESSIONS_AVAILABLE";
    case MSC_UNIQUENESS_CONFLICT:
        return "MSC_UNIQUENESS_CONFLICT";
    case MSC_INSUFFICIENT_SPACE:
        return "MSC_INSUFFICIENT_SPACE";
    case MSC_INSUFFICIENT_ROWS:
        return "MSC_INSUFFICIENT_ROWS";
    case MSC_INVALID_PARAMETER:
        return "MSC_INVALID_PARAMETER";
    case MSC_TPER_MALFUNCTION:
        return "MSC_TPER_MALFUNCTION";
    case MSC_TRANSACTION_FAILURE:
        return "MSC_TRANSACTION_FAILURE";
    case MSC_RESPONSE_OVERFLOW:
        return "MSC_RESPONSE_OVERFLOW";
    case MSC_AUTHORITY_LOCKED_OUT:
        return "MSC_AUTHORITY_LOCKED_OUT";
    case MSC_FAIL:
        return "MSC_FAIL";
    default:
        return "UNKNOWN";
    }
}

static int tcg_discovery_0_process_feature(struct disk_device *dev, void *data, int feature_code)
{
    int err = 0;

    if (feature_code == 0x0001) {
        struct level_0_discovery_tper_feature *body = data;
        dev->features.tper = *body;
    } else if (feature_code == 0x0002) {
        struct level_0_discovery_lockin_feature *body = data;
        dev->features.locking = *body;
    } else if (feature_code == 0x0003) {
        struct level_0_discovery_geometry_feature *body = data;
        dev->features.geometry = *body;
    } else if (feature_code == 0x0203) {
        struct level_0_discovery_opal_2_feature *body = data;
        dev->features.opal2 = *body;
        dev->base_com_id = be16_to_cpu(body->base_comID);
    } else if (feature_code == 0x0200) {
        struct level_0_discovery_opal_1_feature *body = data;
        dev->features.opal1 = *body;
    } else if (feature_code == 0x0201) {
        struct level_0_discovery_single_user_mode_feature *body = data;
        dev->features.single_user_mode = *body;
    } else if (feature_code == 0x0202) {
        struct level_0_discovery_data_store_feature *body = data;
        dev->features.data_store = *body;
    } else if (feature_code == 0x0303) {
        struct level_0_discovery_pyrite_feature *body = data;
        dev->features.pyrite = *body;
        dev->base_com_id = be16_to_cpu(body->base_comID);
    } else if (feature_code == 0x0402) {
        struct level_0_discovery_block_sid_authentication_feature *body = data;
        dev->features.block_sid_authentication = *body;
    } else if (feature_code == 0x0404) {
        struct level_0_discovery_supported_data_removal_mechanism_feature *body = data;
        dev->features.supported_data_removal_mechanism = *body;
    } else {
        struct level_0_discovery_feature_shared *body = data;

        if (dev->features.unknown_len + body->length + 4 < DISK_DEVICE_UNKNOWN_FEATURE_MAX_LENGTH) {
            memcpy(dev->features.unknown + dev->features.unknown_len, data, body->length + 4);
        } else {
            LOG(ERROR, "Too many feature descriptors found, ignoring the rest.\n");
        }
        dev->features.unknown_len += body->length + 4;
    }

    return err;
}

static int tcg_discovery_0_process_response(struct disk_device *dev, void *data)
{
    int err = 0;

    struct level_0_discovery_header *header = data;
    uint32_t offset = sizeof(struct level_0_discovery_header);
    uint32_t total_length = be32_to_cpu(header->length);

    while (offset < total_length) {
        struct level_0_discovery_feature_shared *body =
                (struct level_0_discovery_feature_shared *)((unsigned char *)data + offset);
        uint16_t feature_code = be16_to_cpu(body->feature_code);

        if ((err = tcg_discovery_0_process_feature(dev, body, feature_code))) {
            return err;
        }

        offset += body->length + sizeof(struct level_0_discovery_feature_shared);
    }

    return err;
}

static void log_packet_data(const unsigned char *response)
{
    int l = 0;
    for (int x = 0; x < 254; ++x) {
        if (x == sizeof(struct packet_headers)) {
            LOG_C(EVERYTHING, "| ");
        }
        if (l == 2) {
            LOG_C(EVERYTHING, "%s ", error_to_string(response[x]));
            l = 0;
            continue;
        } else if (l > 0) {
            l++;
        }
        switch (response[x]) {
        case END_OF_DATA_TOKEN:
            LOG_C(EVERYTHING, "END_OF_DATA_TOKEN ");
            l = 1;
            break;
        case START_LIST_TOKEN:
            LOG_C(EVERYTHING, "START_LIST_TOKEN ");
            break;
        case END_LIST_TOKEN:
            LOG_C(EVERYTHING, "END_LIST_TOKEN ");
            break;
        case START_NAME_TOKEN:
            LOG_C(EVERYTHING, "START_NAME_TOKEN ");
            break;
        case END_NAME_TOKEN:
            LOG_C(EVERYTHING, "END_NAME_TOKEN ");
            break;
        case CALL_TOKEN:
            LOG_C(EVERYTHING, "CALL_TOKEN ");
            break;

        default:
            LOG_C(EVERYTHING, "%02x ", response[x]);
            break;
        }
    }
    LOG_C(EVERYTHING, "\n");
}

static int nvme_security_command(int fd, uint8_t *buffer, size_t buffer_len,
                                 enum TrustedCommandDirection direction,
                                 int protocol, int comID)
{
    int err = 0;

    struct nvme_admin_cmd cmd = { 0 };
    // The structure of IF-RECV (IF-SEND) is described in 5.25 (5.26) of NVMe Base Specification.
    // The values for SP Specific are found in TCG SIIS.
    cmd.opcode = direction == IF_RECV ? NVME_SECURITY_RECEIVE : NVME_SECURITY_SEND;

    cmd.addr = (unsigned long long)buffer;
    cmd.data_len = buffer_len;
    // Security Protocol (SECP) | SP Specific | reserved
    cmd.cdw10 = (protocol << 24) | (comID << 8);
    // Allocation Length (AL)
    cmd.cdw11 = buffer_len;

    err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);

    LOG(EVERYTHING, "Packet %s:\n", direction == IF_RECV ? "received" : "sent");
    log_packet_data(buffer);

    if (err != 0) {
        LOG(ERROR, "Problem with sending NVMe Security command: %s.\n", strerror(errno));
    }

    return err;
}

static int scsi_send_cdb(int fd, uint8_t *cdb, size_t cdb_len,
                         uint8_t *response, size_t response_len,
                         enum TrustedCommandDirection direction)
{
    int err = 0;

    uint8_t sense[32] = { 0 };
    struct sg_io_hdr sg = {
        .interface_id = 'S',
        .dxfer_direction = direction == IF_RECV ? SG_DXFER_FROM_DEV : SG_DXFER_TO_DEV,
        .cmdp = cdb,
        .cmd_len = cdb_len,
        .dxferp = response,
        .dxfer_len = response_len,
        .timeout = 60000,
        .sbp = sense,
        .mx_sb_len = sizeof(sense),
    };

    err = ioctl(fd, SG_IO, &sg);

    LOG(EVERYTHING, "Packet %s:\n", direction == IF_RECV ? "received" : "sent");
    log_packet_data(response);

    if (err != 0) {
        LOG(ERROR, "Problem with sending ATA Trusted command: %s.\n", strerror(errno));
    }

    if (sense[0] != 0 || sense[1] != 0) {
        err = -1;
        LOG(ERROR, "Received sense code: ");
        for (size_t i = 0; i < sizeof(sense); ++i) {
            LOG_C(ERROR, "%02x ", sense[i]);
        }
        LOG_C(ERROR, "\n");
    }

    return err;
}

static int ata_trusted_command(int fd, uint8_t *response, size_t response_len,
                               enum TrustedCommandDirection direction,
                               int protocol, int sp_specific)
{
    // ACS-3
    struct sg_cdb_ata_pass_through_12 cdb = {
        .operation_code = ATA_PASS_THROUGH_12_OPERATION_CODE,
        .protocol = direction == IF_RECV ? ATA_PROTOCOL_PIO_DATA_IN : ATA_PROTOCOL_PIO_DATA_OUT,
        .t_dir = direction == IF_RECV ? ATA_PASS_THROUGH_RECEIVE : ATA_PASS_THROUGH_SEND,
        .byt_blok = 1,
        .t_length = 2,
        .trusted_receive.security_protocol = protocol & 0xFF,
        .trusted_receive.transfer_length = cpu_to_le16(response_len / 512),
        .trusted_receive.sp_specific = cpu_to_le16(sp_specific),
        .trusted_receive.command = direction == IF_RECV ? ATA_TRUSTED_RECEIVE : ATA_TRUSTED_SEND,
    };

    return scsi_send_cdb(fd, (uint8_t *)&cdb, sizeof(cdb), response, response_len, direction);
}

static int scsi_security_protocol(int fd, uint8_t *response, size_t response_len,
                                  enum TrustedCommandDirection direction,
                                  int protocol, int protocol_specific)
{
    struct scsi_security_protocol cdb = {
        .operation_code = direction == IF_RECV ? SCSI_SECURITY_PROTOCOL_IN : SCSI_SECURITY_PROTOCOL_OUT,
        .security_protocol = protocol,
        .security_protocol_specific = cpu_to_be16(protocol_specific),
        .allocation_length = cpu_to_be32(response_len),
    };

    return scsi_send_cdb(fd, (uint8_t *)&cdb, sizeof(cdb), response, response_len, direction);
}

int trusted_command(struct disk_device *dev, uint8_t *msg, size_t msg_len, enum TrustedCommandDirection direction,
                    int protocol, int comID)
{
    if (dev->type == NVME)
        return nvme_security_command(dev->fd, msg, msg_len, direction, protocol, comID);
    else if (dev->type == SATA)
        return ata_trusted_command(dev->fd, msg, msg_len, direction, protocol, comID);
    else if (dev->type == SCSI)
            return scsi_security_protocol(dev->fd, msg, msg_len, direction, protocol, comID);
    else {
        LOG(ERROR, "Unsupported device interface.\n");
        return 1;
    }
}

void start_list(unsigned char *buffer, size_t *i)
{
    buffer[*i] = START_LIST_TOKEN;
    *i += 1;
}

void end_list(unsigned char *buffer, size_t *i)
{
    buffer[*i] = END_LIST_TOKEN;
    *i += 1;
}

void start_name(unsigned char *buffer, size_t *i)
{
    buffer[*i] = START_NAME_TOKEN;
    *i += 1;
}

void end_name(unsigned char *buffer, size_t *i)
{
    buffer[*i] = END_NAME_TOKEN;
    *i += 1;
}

void call_token(unsigned char *buffer, size_t *i)
{
    buffer[*i] = CALL_TOKEN;
    *i += 1;
}

void end_of_data(unsigned char *buffer, size_t *i)
{
    buffer[*i] = END_OF_DATA_TOKEN;
    *i += 1;
}

void end_session_token(unsigned char *buffer, size_t *i)
{
    buffer[*i] = END_OF_SESSION_TOKEN;
    *i += 1;
}

void method_status_list(unsigned char *buffer, size_t *i)
{
    buffer[*i] = START_LIST_TOKEN;
    *i += 1;
    for (int x = 0; x < 3; ++x) {
        buffer[*i] = 0x00;
        *i += 1;
    }
    buffer[*i] = END_LIST_TOKEN;
    *i += 1;
}

void tiny_atom(unsigned char *buffer, size_t *i, unsigned char S, unsigned char V)
{
    buffer[*i] = 0b0 << 7 | (S & 0x1) << 6 | V;
    *i += 1;
}

void short_atom(unsigned char *buffer, size_t *i, unsigned char B, unsigned char S, const uint8_t *V, size_t V_len)
{
    buffer[*i] = 0b10 << 6 | (B & 0x1) << 5 | (S & 0x1) << 4 | V_len;
    *i += 1;

    memcpy(buffer + *i, V, V_len);
    *i += V_len;
}

void medium_atom(unsigned char *buffer, size_t *i, unsigned char B, unsigned char S, const uint8_t *V, size_t V_len)
{
    buffer[*i] = 0b110 << 5 | (B & 0x1) << 4 | (S & 0x1) << 3 | V_len >> 8;
    buffer[*i + 1] = 0b11111111 & V_len;
    *i += 2;

    memcpy(buffer + *i, V, V_len);
    *i += V_len;
}

uint64_t parse_int(const unsigned char *buffer, size_t *i)
{
    uint64_t result = 0;

    if ((buffer[*i] & 0b10000000) == 0b00000000) {
        result = buffer[*i] & 0b00111111;
        *i += 1;

        return result;
    } else if ((buffer[*i] & 0b11000000) == 0b10000000) {
        size_t len = buffer[*i] & (0b00011111);
        *i += 1;

        for (size_t j = 0; j < len; ++j) {
            result |= buffer[*i] << (((len - 1) - j) * 8);
            *i += 1;
        }

        return result;
    } else {
        return UINT64_MAX;
    }
}

int process_method_response(const unsigned char *buffer, size_t buffer_len)
{
    uint8_t status_code = 0;

    const struct packet_headers *headers = (const struct packet_headers *)buffer;
    const unsigned char *data = buffer + sizeof(struct packet_headers);
    size_t data_length = be32_to_cpu(headers->data_subpacket.length);

    if (buffer_len < sizeof(struct packet_headers) + data_length) {
        LOG(ERROR, "Buffer was not large enough for the response.\n");
        return 1;
    }

    size_t i = 0;

    if (data[i] == END_OF_SESSION_TOKEN) {
        return 0;
    }

    if (data[i] == CALL_TOKEN) {
        i += 1;

        // session manager method

        if (data[i++] != 0xa8) {
            return 1;
        }
        if (memcmp(data + i, SMUID, 8) != 0) {
            LOG(ERROR, "Got SMUID method from non-SMUID invoker.\n");
            return -1;
        }
        i += 8; // invokid uid

        if (data[i++] != 0xa8) {
            return 1;
        }
        if (memcmp(data + i, METHOD_CLOSE_SESSION_UID, 8) == 0) {
            LOG(ERROR, "Probably unexpected close session.\n");
            return -1;
        }
        i += 8; // method uid
    }

    size_t backtracking_length = 8;
    if (backtracking_length > data_length - 7) {
        backtracking_length = data_length - 7;
    }
    for (size_t i = 0; i < backtracking_length; ++i) {
        const unsigned char *data_tail = data + data_length - 7 - i;

        if (data_tail[0] != END_LIST_TOKEN ||
            data_tail[1] != END_OF_DATA_TOKEN ||
            data_tail[2] != START_LIST_TOKEN ||
            data_tail[4] != 00 ||
            data_tail[5] != 00 ||
            data_tail[6] != END_LIST_TOKEN) {

            if (data_tail[6] == EMPTY_ATOM_TOKEN) {
                continue;
            } else {
                LOG(ERROR, "Received unexpected tokens.\n");
                return -1;
            }
        }

        if ((status_code = data_tail[3]) != MSC_SUCCESS) {
            LOG(ERROR, "Received non-successful status code: %s.\n", error_to_string(status_code));
        }

        return status_code;
    }

    return -1;
}

int invoke_method(struct disk_device *dev, unsigned char *buff_in, size_t buff_in_len, unsigned char *buff_out,
                  size_t buff_out_len)
{
    int err = 0;

    if ((err = trusted_command(dev, buff_in, buff_in_len, IF_SEND, 0x01, dev->base_com_id))) {
        LOG(ERROR, "Failed to send command: %i\n", err);
        return err;
    }
    if ((err = trusted_command(dev, buff_out, buff_out_len, IF_RECV, 0x01, dev->base_com_id))) {
        LOG(ERROR, "Failed to receive command: %i\n", err);
        return err;
    }
    if ((err = process_method_response(buff_out, buff_out_len))) {
        LOG(ERROR, "Received bad response.\n");
        return err;
    }

    return err;
}

void prepare_headers(unsigned char *buffer, size_t *i, struct disk_device *dev)
{
    struct packet_headers *headers = (void *)(unsigned char *)buffer;

    headers->com_packet.comid = cpu_to_be16(dev->base_com_id);
    headers->packet.session = dev->sp_session_id | (uint64_t)dev->host_session_id << 32;

    *i += sizeof(struct packet_headers);
}

void prepare_method(unsigned char *buffer, size_t *i, struct disk_device *dev, const unsigned char *invoking_uid,
                    const unsigned char *method_uid)
{
    prepare_headers(buffer, i, dev);

    call_token(buffer, i);
    short_atom(buffer, i, 1, 0, invoking_uid, 8);
    short_atom(buffer, i, 1, 0, method_uid, 8);
    start_list(buffer, i);
}

void finish_headers(unsigned char *buffer, size_t *i)
{
    struct packet_headers *headers = (void *)(((unsigned char *)buffer));

    // Data subpacket does not want aligned length.
    headers->data_subpacket.length = cpu_to_be32(*i - sizeof(struct packet_headers));

    if ((*i % 4) != 0)
        *i += 4 - (*i % 4);

    headers->com_packet.length = cpu_to_be32(*i - sizeof(struct com_packet));
    headers->packet.length = cpu_to_be32(be32_to_cpu(headers->com_packet.length) - sizeof(struct packet));

    if ((*i % PADDING_ALIGNMENT) != 0)
        *i += PADDING_ALIGNMENT - (*i % PADDING_ALIGNMENT);
}

void finish_method(unsigned char *buffer, size_t *i)
{
    end_list(buffer, i);
    end_of_data(buffer, i);
    method_status_list(buffer, i);

    finish_headers(buffer, i);
}



int do_level_0_discovery(struct disk_device *dev)
{
    int err = 0;
    uint8_t response[2048] = { 0 };

    if ((err = trusted_command(dev, response, sizeof(response), IF_RECV, TCG_LEVEL_0_DISCOVERY_PROTOCOL_ID,
                               TCG_LEVEL_0_DISCOVERY_COMID))) {
        return err;
    }

    if ((err = tcg_discovery_0_process_response(dev, response))) {
        return err;
    }

    return err;
}
static int generate_start_session_method(struct disk_device *dev, unsigned char *buffer, size_t *i, const unsigned char *spid,
                                         size_t spid_len, const unsigned char *host_challenge, size_t host_challenge_len,
                                         const unsigned char *host_signing_authority, size_t host_signing_authority_len)
{
    const int host_session_id = 1;
    const int write_session = 1;

    /*
      5.2.3.1 StartSession Method
      SMUID.StartSession [
      HostSessionID : uinteger,
      spid : uidref {SPObjectUID},
      Write : boolean,
      HostChallenge = bytes,
      HostExchangeAuthority = uidref {AuthorityObjectUID},
      HostExchangeCert = bytes,
      HostSigningAuthority = uidref {AuthorityObjectUID},
      HostSigningCert = bytes,
      SessionTimeout = uinteger,
      TransTimeout = uinteger,
      InitialCredit = uinteger,
      SignedHash = bytes ]
      =>
      SMUID.SyncSession [ see SyncSession definition in 5.2.3.2]
  */

    prepare_method(buffer, i, dev, SMUID, METHOD_START_SESSION_UID);
    {
        tiny_atom(buffer, i, 0, host_session_id);
        short_atom(buffer, i, 1, 0, spid, spid_len);
        tiny_atom(buffer, i, 0, write_session);
        if (host_challenge) {
            start_name(buffer, i);
            tiny_atom(buffer, i, 0, 0);
            medium_atom(buffer, i, 1, 0, host_challenge, host_challenge_len);
            end_name(buffer, i);
        }
        if (host_signing_authority) {
            start_name(buffer, i);
            tiny_atom(buffer, i, 0, 3);
            short_atom(buffer, i, 1, 0, host_signing_authority, host_signing_authority_len);
            end_name(buffer, i);
        }
    }
    finish_method(buffer, i);

    return 0;
}

int start_session(struct disk_device *dev, const unsigned char *SPID, size_t user_id, const unsigned char *challenge,
                  size_t challenge_len)
{
    int err = 0;

    LOG(INFO, "------- START SESSION -------\n");

    unsigned char buffer[2048] = { 0 };
    size_t i = 0;

    do_level_0_discovery(dev);
    LOG(INFO, "base_com_id=%x user_id=%lu\n", dev->base_com_id, user_id);


    if (user_id < SPECIAL_BASE_ID) {
        unsigned char signing_auth[8];
        memcpy(signing_auth, AUTHORITY_XXXX_UID, 8);
        hex_add(signing_auth, 8, user_id);
        generate_start_session_method(dev, buffer, &i, SPID, 8, 
                                      challenge, challenge_len, signing_auth, 8);
    } else if (user_id == ANYBODY_USER_ID) {
        generate_start_session_method(dev, buffer, &i, SPID, 8, 
                                      NULL, 0, NULL, 0);
    } else if (user_id == SID_USER_ID) {
        generate_start_session_method(dev, buffer, &i, SPID, 8, 
                                      challenge, challenge_len, AUTHORITY_SID_UID, 8);
    } else if (user_id == PSID_USER_ID) {
        generate_start_session_method(dev, buffer, &i, SPID, 8, 
                                      challenge, challenge_len, AUTHORITY_PSID_UID, 8);
    } else {
        LOG(ERROR, "Invalid user id.\n");
        return err;
    }

    if ((err = invoke_method(dev, buffer, i, buffer, sizeof(buffer)))) {
        LOG(ERROR, "Failed to start a session.\n");
        return err;
    }

    /*
      SMUID.SyncSession [
      HostSessionID : uinteger,
      SPSessionID : uinteger,
      SPChallenge = bytes,
      SPExchangeCert = bytes,
      SPSigningCert = bytes,
      TransTimeout = uinteger,
      InitialCredit = uinteger,
      SignedHash = bytes ]
    */
    if ((err = skip_to_parameter(buffer, &i, 0, 0))) {
        return err;
    }
    dev->host_session_id = be32_to_cpu(parse_int(buffer, &i));
    dev->sp_session_id = be32_to_cpu(parse_int(buffer, &i));
    LOG(INFO, "Created session with HostSessionID 0x%x and SPSessionID 0x%x.\n", 
        dev->host_session_id, dev->sp_session_id);

    return err;
}

int close_session(struct disk_device *dev)
{
    int err = 0;

    unsigned char buffer[512] = { 0 };
    size_t i = 0;

    if (dev->host_session_id == 0 && dev->sp_session_id == 0) {
        return 0;
    }

    prepare_headers(buffer, &i, dev);
    end_session_token(buffer, &i);
    finish_headers(buffer, &i);

    if ((err = invoke_method(dev, buffer, i, buffer, sizeof(buffer)))) {
        LOG(ERROR, "Failed to close session with HostSessionID 0x%x and SPSessionID 0x%x\n", 
            dev->host_session_id, dev->sp_session_id);
    }

    dev->sp_session_id = 0;
    dev->host_session_id = 0;

    LOG(INFO, "close_session err: %i\n", err);
    LOG(INFO, "------- CLOSE SESSION -------\n\n");

    return err;
}

int parse_bytes(const unsigned char *src, size_t *offset, unsigned char *dst, size_t dst_size, size_t *written)
{
    size_t len = 0;
    size_t i = 0;

    if (offset) {
        i = *offset;
    }

    if ((src[i] & 0b10000000) == 0b00000000) {
        // tiny atom does not have byte type
        return 1;
    } else if ((src[i] & 0b11000000) == 0b10000000) {
        // short atom
        if ((src[i] & 0b00110000) != 0b00100000) {
            // continuous or not byte type
            return 1;
        }

        len = src[i] & 0b00001111;
        i += 1;
    } else if ((src[i] & 0b11100000) == 0b11000000) {
        // medium atom
        if ((src[i] & 0b00011000) != 0b00010000) {
            // continuous or not byte type
            return 1;
        }

        len = ((src[i + 0] & 0b00000111) << 8) | ((src[i + 1]) << 0);
        i += 2;
    } else if ((src[i] & 0b11110000) == 0b11100000) {
        // long atom
        if ((src[i] & 0b00000011) != 0b00000010) {
            // continuous or not byte type
            return 1;
        }

        len = ((src[i + 0]) << 16) | ((src[i + 1]) << 8) | ((src[i + 2]) << 0);
        i += 3;
    } else {
        return 1;
    }

    if (dst) {
        if (len > dst_size) {
            return 1;
        }

        for (size_t j = 0; j < len; ++j) {
            dst[j] = src[i + j];
        }
    }
    i += len;

    if (offset) {
        *offset = i;
    }
    if (written) {
        *written = len;
    }

    return 0;
}

int skip_atom(const unsigned char *src, size_t *offset, size_t total_length)
{
    if ((src[*offset] & 0b10000000) == 0b00000000) {
        // tiny atom
        *offset += 1;
    } else if ((src[*offset] & 0b11000000) == 0b10000000) {
        // short atom
        *offset += 1 + (src[*offset] & 0b00001111);
    } else if ((src[*offset] & 0b11100000) == 0b11000000) {
        // medium atom
        *offset += 2 + (((src[*offset + 0] & 0b00000111) << 8) | ((src[*offset + 1]) << 0));
    } else if ((src[*offset] & 0b11110000) == 0b11100000) {
        // long atom
        *offset += 3 + (((src[*offset + 0]) << 16) | ((src[*offset + 1]) << 8) | ((src[*offset + 2]) << 0));
    } else if (src[*offset] == START_LIST_TOKEN) {
        *offset += 1;
        while (src[*offset] != END_LIST_TOKEN) {
            skip_atom(src, offset, total_length);
        }
        *offset += 1;
    } else if (src[*offset] == END_LIST_TOKEN) {
        *offset += 1;
    } else if (src[*offset] == START_NAME_TOKEN) {
        *offset += 1;
        skip_atom(src, offset, total_length);
        skip_atom(src, offset, total_length);
        if (src[*offset] != END_NAME_TOKEN) {
            return 1;
        }
        *offset += 1;
    } else if (src[*offset] == END_NAME_TOKEN) {
        *offset += 1;
    }

    return 0;
}

int skip_to_parameter(unsigned char *src, size_t *offset, int parameter, int skip_mandatory)
{
    struct packet_headers *headers = (struct packet_headers *)src;
    size_t len = be32_to_cpu(headers->data_subpacket.length) + sizeof(struct packet_headers);
    *offset = sizeof(struct packet_headers);
    if (src[*offset] == START_LIST_TOKEN) {
        *offset += 1;
    } else if (src[*offset] == CALL_TOKEN) {
        *offset += 20;
    } else {
        return 1;
    }

    if (!skip_mandatory) {
        // getting mandatory argument

        if (*offset >= len) {
            return 1;
        }

        // skip previous arguments
        for (int j = 0; j < parameter - 1; ++j) {
            skip_atom(src, offset, len);
        }

        return 0;
    } else {
        // getting optional argument

        // skip all mandatory arguments
        for (int j = 0; j < skip_mandatory; ++j) {
            skip_atom(src, offset, len);
        }

        while (*offset < len) {
            if (*offset >= len || src[*offset] != START_NAME_TOKEN) {
                return 1;
            }

            size_t tmp = *offset + 1;
            uint64_t parsed_index = parse_int(src, &tmp);
            if (parsed_index == (uint64_t)parameter) {
                return 0;
            }

            skip_atom(src, offset, len);
        }
    }

    return 1;
}

int set_row(struct disk_device *dev, const unsigned char *object_uid, unsigned char column, unsigned char *atom, size_t atom_len)
{
    /*
    ObjectUID.Set [
    Values = typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = <type of
    column> ... ] } ]
    =>
    [ ]
     */
    int err = 0;

    unsigned char buffer[2048] = { 0 };
    size_t i = 0;

    prepare_method(buffer, &i, dev, object_uid, METHOD_SET_UID);
    {
        start_name(buffer, &i);
        tiny_atom(buffer, &i, 0, METHOD_SET_PARAMETER_VALUES);
        start_list(buffer, &i);
        {
            start_name(buffer, &i);
            tiny_atom(buffer, &i, 0, column);
            memcpy(buffer + i, atom, atom_len);
            i += atom_len;
            end_name(buffer, &i);
        }
        end_list(buffer, &i);
        end_name(buffer, &i);
    }
    finish_method(buffer, &i);

    if ((err = invoke_method(dev, buffer, i, buffer, sizeof(buffer)))) {
        close_session(dev);
        return err;
    }

    return err;
}

int get_row_bytes(struct disk_device *dev, const unsigned char *object_uid, unsigned char column, unsigned char *output,
                  size_t output_len, size_t *output_written)
{
    /*
    TableUID.Get [
    ObjectUID.Get [
    Cellblock : cell_block ]
    =>
    [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
    */
    size_t i = 0;
    int err = 0;

    unsigned char buffer[2048] = { 0 };

    prepare_method(buffer, &i, dev, object_uid, METHOD_GET_UID);
    {
        start_list(buffer, &i);
        {
            start_name(buffer, &i);
            tiny_atom(buffer, &i, 0, METHOD_GET_PARAMETER_START);
            tiny_atom(buffer, &i, 0, column);
            end_name(buffer, &i);

            start_name(buffer, &i);
            tiny_atom(buffer, &i, 0, METHOD_GET_PARAMETER_END);
            tiny_atom(buffer, &i, 0, column);
            end_name(buffer, &i);
        }
        end_list(buffer, &i);
    }
    finish_method(buffer, &i);

    if ((err = invoke_method(dev, buffer, i, buffer, sizeof(buffer)))) {
        close_session(dev);
        return err;
    }

    size_t pos = sizeof(struct packet_headers);
    if (buffer[pos + 0] != START_LIST_TOKEN || buffer[pos + 1] != START_LIST_TOKEN ||
        buffer[pos + 2] != START_NAME_TOKEN) {
        LOG(ERROR, "Unexpected tokens received.\n");
        goto cleanup;
    }
    pos += 3;
    if (parse_int(buffer, &pos) != column) {
        LOG(ERROR, "Unexpected column received.\n");
        return err;
    }
    if ((err = parse_bytes(buffer, &pos, output, output_len, output_written))) {
        LOG(ERROR, "Failed to parse output.\n");
        return err;
    }

cleanup:
    return err;
}

int get_row_int(struct disk_device *dev, const unsigned char *object_uid, unsigned char column, uint64_t *output)
{
    /*
    TableUID.Get [
    ObjectUID.Get [
    Cellblock : cell_block ]
    =>
    [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
    */
    uint64_t tmp;
    size_t i = 0;
    int err = 0;

    unsigned char buffer[2048] = { 0 };

    prepare_method(buffer, &i, dev, object_uid, METHOD_GET_UID);
    {
        start_list(buffer, &i);
        {
            start_name(buffer, &i);
            tiny_atom(buffer, &i, 0, METHOD_GET_PARAMETER_START);
            tiny_atom(buffer, &i, 0, column);
            end_name(buffer, &i);

            start_name(buffer, &i);
            tiny_atom(buffer, &i, 0, METHOD_GET_PARAMETER_END);
            tiny_atom(buffer, &i, 0, column);
            end_name(buffer, &i);
        }
        end_list(buffer, &i);
    }
    finish_method(buffer, &i);

    if ((err = invoke_method(dev, buffer, i, buffer, sizeof(buffer)))) {
        close_session(dev);
        return err;
    }

    size_t pos = sizeof(struct packet_headers);
    LOG(EVERYTHING, "Packet headers size: %zu.\n", pos);

    if (buffer[pos + 0] != START_LIST_TOKEN || buffer[pos + 1] != START_LIST_TOKEN) {
        LOG(ERROR, "Unexpected tokens received: %02x %02x\n", buffer[pos], buffer[pos + 1]);
        goto cleanup;
    }

    if (buffer[pos + 2] == END_LIST_TOKEN && buffer[pos + 3] == END_LIST_TOKEN) {
        return 1;
    }

    if (buffer[pos + 2] != START_NAME_TOKEN) {
        LOG(ERROR, "Unexpected tokens received: %02x\n", buffer[pos + 2]);
        goto cleanup;
    }
    pos += 3;
    if (parse_int(buffer, &pos) != column) {
        LOG(ERROR, "Unexpected column received.\n");
        return err;
    }

    tmp = parse_int(buffer, &pos);
    if (tmp == UINT64_MAX) {
        LOG(ERROR, "Failed to parse integer output.\n");
        return 1;
    }

    *output = tmp;

cleanup:
    return err;
}

int disk_device_open(struct disk_device *dev, const char *file, bool use_scsi_sec)
{
    memset(dev, 0, sizeof(struct disk_device));

    if (!strncmp(file, "/dev/nvme", 9))
        dev->type = NVME;
    else if (use_scsi_sec)
        dev->type = SCSI;
    else
        dev->type = SATA;

    /* For ioctl access read-only is enough */
    if ((dev->fd = open(file, O_RDONLY)) == -1) {
        LOG(ERROR, "Cannot open file '%s': %s\n", file, strerror(errno));
        return 1;
    }

    if (dev->name)
        free(dev->name);
    if (!strncmp(file, "/dev/", 5))
        dev->name = strdup(&file[5]);
    else
        dev->name = strdup(file);

    return 0;
}

void disk_device_close(struct disk_device *dev)
{
    close(dev->fd);
    free(dev->name);
}
