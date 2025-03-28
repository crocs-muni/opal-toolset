// SPDX-License-Identifier: MIT

#include <unistd.h>
#include "common.h"
#include "utils.h"

static int generate_locking_range_set_command(struct disk_device *dev, unsigned char *buffer, size_t *i,
                                              unsigned char locking_range, uint64_t range_start, uint64_t range_length,
                                              char read_lock_enabled, char write_lock_enabled, char read_locked,
                                              char write_locked)
{
    unsigned char locking_range_uid_str[9] = { 0 };
    unsigned char tmp[8];

    prepare_locking_range(locking_range_uid_str, locking_range);
    prepare_method(buffer, i, dev, locking_range_uid_str, METHOD_SET_UID);
    {
        start_name(buffer, i);
        tiny_atom(buffer, i, 0, 1);
        start_list(buffer, i);
        {
            if (range_start != UINT64_MAX) {
                memset(tmp, 0, sizeof(tmp));
                hex_add(tmp, 8, range_start);
                LOG(INFO, "range_start = %" PRIu64 " (%02x%02x%02x%02x%02x%02x%02x%02x)\n", range_start, tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7]);

                start_name(buffer, i);
                tiny_atom(buffer, i, 0, LOCKING_RANGE_COLUMN_RANGE_START);
                short_atom(buffer, i, 0, 0, tmp, 8);
                end_name(buffer, i);
            }
            if (range_length != UINT64_MAX) {
                memset(tmp, 0, sizeof(tmp));
                hex_add(tmp, 8, range_length);
                LOG(INFO, "range_length = %" PRIu64 " (%02x%02x%02x%02x%02x%02x%02x%02x)\n", range_length, tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7]);

                start_name(buffer, i);
                tiny_atom(buffer, i, 0, LOCKING_RANGE_COLUMN_RANGE_LENGTH);
                short_atom(buffer, i, 0, 0, tmp, 8);
                end_name(buffer, i);
            }
            if (read_lock_enabled != -1) {
                LOG(INFO, "read_lock_enabled = %i\n", read_lock_enabled);

                start_name(buffer, i);
                tiny_atom(buffer, i, 0, LOCKING_RANGE_COLUMN_READ_LOCK_ENABLED);
                tiny_atom(buffer, i, 0, read_lock_enabled);
                end_name(buffer, i);
            }
            if (write_lock_enabled != -1) {
                LOG(INFO, "write_lock_enabled = %i\n", write_lock_enabled);

                start_name(buffer, i);
                tiny_atom(buffer, i, 0, LOCKING_RANGE_COLUMN_WRITE_LOCK_ENABLED);
                tiny_atom(buffer, i, 0, write_lock_enabled);
                end_name(buffer, i);
            }
            if (read_locked != -1) {
                LOG(INFO, "read_locked = %i\n", read_locked);

                start_name(buffer, i);
                tiny_atom(buffer, i, 0, LOCKING_RANGE_COLUMN_READ_LOCKED);
                tiny_atom(buffer, i, 0, read_locked);
                end_name(buffer, i);
            }
            if (write_locked != -1) {
                LOG(INFO, "write_locked = %i\n", write_locked);

                start_name(buffer, i);
                tiny_atom(buffer, i, 0, LOCKING_RANGE_COLUMN_WRITE_LOCKED);
                tiny_atom(buffer, i, 0, write_locked);
                end_name(buffer, i);
            }
        }
        end_list(buffer, i);
        end_name(buffer, i);
    }
    finish_method(buffer, i);

    return 0;
}

int unlock_range(struct disk_device *dev, unsigned char locking_range,
                 char read_locked, char write_locked,
                 unsigned char *challenge, size_t challenge_len, size_t user)
{
    int err = 0;
    unsigned char buffer[2048] = { 0 };
    size_t i = 0;
    unsigned char response[2048] = { 0 };

    if (locking_range == ALL_LOCKING_RANGES) {
        LOG(ERROR, "LR must be specified.\n");
        return -1;
    }

    if ((err = start_session(dev, LOCKING_SP_UID, user, challenge, challenge_len))) {
        LOG(ERROR, "Failed when setting starting session for setting locking range parameters.\n");
        return err;
    }
    generate_locking_range_set_command(dev, buffer, &i, locking_range, -1, -1, -1, -1, read_locked, write_locked);
    if ((err = invoke_method(dev, buffer, i, response, sizeof(response)))) {
        LOG(ERROR, "Failed when setting locking range parameters.\n");
        close_session(dev);
        return err;
    }

    return close_session(dev);
}

int setup_enable_range(struct disk_device *dev, unsigned char locking_range,
                 char read_lock_enabled, char write_lock_enabled,
                 unsigned char *challenge, size_t challenge_len, size_t user)

{
    int err = 0;
    unsigned char buffer[2048] = { 0 };
    size_t i = 0;
    unsigned char response[2048] = { 0 };

    if (locking_range == ALL_LOCKING_RANGES) {
        LOG(ERROR, "LR must be specified.\n");
        return -1;
    }

    if (read_lock_enabled < 0 && write_lock_enabled < 0) {
        LOG(ERROR, "At least one enable/disable locking value must be set.\n");
        return -1;
    }

    if ((err = start_session(dev, LOCKING_SP_UID, user, challenge, challenge_len))) {
        LOG(ERROR, "Failed when setting starting session for setting locking range parameters.\n");
        return err;
    }
    generate_locking_range_set_command(dev, buffer, &i, locking_range, UINT64_MAX, UINT64_MAX,
                                       read_lock_enabled, write_lock_enabled, -1, -1);
    if ((err = invoke_method(dev, buffer, i, response, sizeof(response)))) {
        LOG(ERROR, "Failed when setting locking range parameters.\n");
        close_session(dev);
        return err;
    }

    return close_session(dev);
}

static void add_user(unsigned char *buffer, size_t *i, size_t user, bool add_or)
{
   unsigned char user_uid[8];

   memcpy(user_uid, AUTHORITY_XXXX_UID, 8);
   hex_add(user_uid, 8, user);

   start_name(buffer, i);
   short_atom(buffer, i, 1, 0, HALF_UID_AUTHORITY_OBJECT_REF, 4);
   short_atom(buffer, i, 1, 0, user_uid, 8);
   end_name(buffer, i);

    if (add_or) {
        start_name(buffer, i);
        short_atom(buffer, i, 1, 0, HALF_UID_BOOLEAN_ACE, 4);
        tiny_atom(buffer, i, 0, BOOLEAN_OR);
        end_name(buffer, i);
    }
}

int add_user_range(struct disk_device *dev, unsigned char locking_range,
                unsigned char *challenge, size_t challenge_len,
                size_t users[], size_t users_len)
{
    int i, err = 0;
    unsigned char boolean_ace[1024] = { 0 };
    unsigned char ace_uid[8];
    size_t boolean_ace_len = 0;

    if (!challenge) {
        LOG(ERROR, "PIN not specified.\n");
        return -1;
    }

    if (!users || users_len == 0) {
        LOG(ERROR, "Users must be specified.\n");
        return -1;
    }

    err = start_session(dev, LOCKING_SP_UID, ADMIN_BASE_ID + 1, challenge, challenge_len);
    if (err) {
        LOG(ERROR, "Failed starting session for adding users.\n");
        return err;
    }

    // Create ACE with all the users
    start_list(boolean_ace, &boolean_ace_len);
    for (i = 0; i < users_len; ++i)
        add_user(boolean_ace, &boolean_ace_len, users[i], i != 0);
    end_list(boolean_ace, &boolean_ace_len);

    for (i = 0; i < 3; ++i) {
        if (i == 0)
            memcpy(ace_uid, TABLE_ACE_ROW_LOCKING_RANGE_XXXX_SET_RD_LOCKED, 8);
        else if (i == 1)
            memcpy(ace_uid, TABLE_ACE_ROW_LOCKING_RANGE_XXXX_SET_WR_LOCKED, 8);
        else
            memcpy(ace_uid, TABLE_ACE_LOCKING_RANGE_XXXX_GET_PARAMS, 8);

        hex_add(ace_uid, 8, locking_range);

        if ((err = set_row(dev, ace_uid, TABLE_ACE_COLUMN_BOOLEAN_EXPR, boolean_ace, boolean_ace_len))) {
            LOG(ERROR, "Failed to set rights for locking range (%d: %s).\n", i, i == 0 ? "reading" : "writing");
            close_session(dev);
            return err;
        }
    }

    return close_session(dev);
}

int setup_range(struct disk_device *dev, unsigned char locking_range,
                unsigned char *challenge, size_t challenge_len,
                uint64_t start, uint64_t length,
                size_t users[], size_t users_len, bool sum)
{
    int i, err = 0;
    unsigned char buffer[512] = { 0 };
    size_t buffer_len = 0;
    unsigned char response[512] = { 0 };
    unsigned char boolean_ace[1024] = { 0 };
    unsigned char ace_uid[8];
    size_t boolean_ace_len = 0;

    if (!challenge) {
        LOG(ERROR, "PIN not specified.\n");
        return -1;
    }

    if (sum && users_len != 1) {
        LOG(ERROR, "Wrong users count.\n");
        return -1;
    }

    if (sum)
        err = start_session(dev, LOCKING_SP_UID, users[0], challenge, challenge_len);
    else
        err = start_session(dev, LOCKING_SP_UID, ADMIN_BASE_ID + 1, challenge, challenge_len);

    if (err) {
        LOG(ERROR, "Failed starting session for setting range parameters.\n");
        return err;
    }

    // Configures the range and enables read and write locking by changing
    // RangeStart, RangeLength, ReadLockEnabled and WriteLockEnabled for
    // Locking_Range1

    generate_locking_range_set_command(dev, buffer, &buffer_len, locking_range, start, length, 1, 1, -1, -1);

    if ((err = invoke_method(dev, buffer, buffer_len, response, sizeof(response)))) {
        LOG(ERROR, "Failed to setup locking range.\n");
        close_session(dev);
        return err;
    }

    if (sum)
        return close_session(dev);

    // Create ACE with all the users.
    if (users_len == 0)
        LOG(ERROR, "Empty authority list may cause INVALID_PARAMETER error.\n");

    start_list(boolean_ace, &boolean_ace_len);
    for (i = 0; i < users_len; ++i)
        add_user(boolean_ace, &boolean_ace_len, users[i], i != 0);
    add_user(boolean_ace, &boolean_ace_len, ADMIN_BASE_ID + 1, true);
    end_list(boolean_ace, &boolean_ace_len);

    for (i = 0; i < 3; ++i) {
        if (i == 0)
            memcpy(ace_uid, TABLE_ACE_ROW_LOCKING_RANGE_XXXX_SET_RD_LOCKED, 8);
        else if (i == 1)
            memcpy(ace_uid, TABLE_ACE_ROW_LOCKING_RANGE_XXXX_SET_WR_LOCKED, 8);
        else
            memcpy(ace_uid, TABLE_ACE_LOCKING_RANGE_XXXX_GET_PARAMS, 8);

        hex_add(ace_uid, 8, locking_range);

        if ((err = set_row(dev, ace_uid, TABLE_ACE_COLUMN_BOOLEAN_EXPR, boolean_ace, boolean_ace_len))) {
            LOG(ERROR, "Failed to set rights for locking range (%d: %s).\n", i, i == 0 ? "reading" : "writing");
            close_session(dev);
            return err;
        }
    }

    return close_session(dev);
}

int list_range(struct disk_device *dev, unsigned char locking_range,
               unsigned char *challenge, size_t challenge_len, size_t user)
{
    int err = 0;
    unsigned char locking_range_uid_str[9] = { 0 };
    uint64_t start, length, rlocked, wlocked, rlck_enabled, wlck_enabled;

    if (locking_range == ALL_LOCKING_RANGES) {
        LOG(ERROR, "LR must be specified.\n");
        return -1;
    }

    prepare_locking_range(locking_range_uid_str, locking_range);

    // Get Locking Authority session
    if ((err = start_session(dev, LOCKING_SP_UID, user, challenge, challenge_len))) {
        LOG(ERROR, "Failed when setting starting session for getting locking range parameters.\n");
        return err;
    }
    // Get Locking Range info (TODO: Request values in a single request. This is suboptimal)
    if ((err = get_row_int(dev, locking_range_uid_str, LOCKING_RANGE_COLUMN_RANGE_START, &start))) {
        LOG(ERROR, "Failed to read Locking Range %u start.\n", locking_range);
        close_session(dev);
        return err;
    }
    if ((err = get_row_int(dev, locking_range_uid_str, LOCKING_RANGE_COLUMN_RANGE_LENGTH, &length))) {
        LOG(ERROR, "Failed to read Locking Range %u length.\n", locking_range);
        close_session(dev);
        return err;
    }
    if ((err = get_row_int(dev, locking_range_uid_str, LOCKING_RANGE_COLUMN_READ_LOCKED, &rlocked))) {
        LOG(ERROR, "Failed to read Locking Range %u read locked.\n", locking_range);
        close_session(dev);
        return err;
    }
    if ((err = get_row_int(dev, locking_range_uid_str, LOCKING_RANGE_COLUMN_WRITE_LOCKED, &wlocked))) {
        LOG(ERROR, "Failed to read Locking Range %u write locked.\n", locking_range);
        close_session(dev);
        return err;
    }
    if ((err = get_row_int(dev, locking_range_uid_str, LOCKING_RANGE_COLUMN_READ_LOCK_ENABLED, &rlck_enabled))) {
        LOG(ERROR, "Failed to read Locking Range %u read lock enabled.\n", locking_range);
        close_session(dev);
        return err;
    }
    if ((err = get_row_int(dev, locking_range_uid_str, LOCKING_RANGE_COLUMN_WRITE_LOCK_ENABLED, &wlck_enabled))) {
        LOG(ERROR, "Failed to read Locking Range %u write lock enabled.\n", locking_range);
        close_session(dev);
        return err;
    }

    err = close_session(dev);
    if (err)
        return err;

    fprintf(stdout,
            "Locking range %u: Start: %" PRIu64 ", length: %" PRIu64 ", R locked: %s, W locked: %s, R lock enabled: %s, W lock enabled: %s.\n",
            locking_range,
            start,length,
            rlocked ? "yes" : "no",
            wlocked ? "yes" : "no",
            rlck_enabled ? "yes" : "no",
            wlck_enabled ? "yes" : "no");

    return 0;
}

int setup_user(struct disk_device *dev, size_t user_uid,
               unsigned char *admin_pin, size_t admin_pin_len,
               unsigned char *user_pin, size_t user_pin_len,
               bool sum, unsigned char sum_locking_range)
{
    int err = 0;
    unsigned char user_uid_str[9] = { 0 };
    unsigned char atom_true[32] = { 0 };
    unsigned char c_pin_str[9] = { 0 };
    unsigned char atom_pin[256] = { 0 };
    unsigned char empty_str = 0;
    size_t atom_pin_len = 0;
    size_t atom_true_len = 0;

    if (!admin_pin) {
        LOG(ERROR, "Admin PIN not specified.\n");
        return -1;
    }

    if (!user_pin) {
        LOG(ERROR, "User PIN not specified.\n");
        return -1;
    }

    if (sum && sum_locking_range == ALL_LOCKING_RANGES) {
        LOG(ERROR, "LR must be specified.\n");
        return -1;
    }

    if (sum && user_uid != (sum_locking_range + USER_BASE_ID + 1)) {
        LOG(ERROR, "In SUM mode, user ID must be equal to unlocked LR number + 1.\n");
        return -1;
    }

    if ((err = start_session(dev, LOCKING_SP_UID, ADMIN_BASE_ID + 1, admin_pin, admin_pin_len))) {
        LOG(ERROR, "Failed to start ADMIN session with Locking SP.\n");
        return err;
    }

    memcpy(user_uid_str, AUTHORITY_XXXX_UID, 8);
    if (sum)
        hex_add(user_uid_str, 8, USER_BASE_ID + 1); /* Always USER1. Why? */
    else
        hex_add(user_uid_str, 8, user_uid);

    tiny_atom(atom_true, &atom_true_len, 0, 1);

    if ((err = set_row(dev, user_uid_str, TABLE_AUTHORITY_COLUMN_ENABLED, atom_true, atom_true_len))) {
        LOG(ERROR, "Failed to enable User authority.\n");
        close_session(dev);
        return err;
    }

    /*
     * For SUM we need user session now
     * Note default confusing association (sec 4.4.1 in SUM SSC doc)
     *   Global Locking Range (0) -> User1 (0x30001)
     *   Locking Range 1 -> User2 (0x30002)
     *    ...
     */
    if (sum) {
        err = close_session(dev);
        if (err)
            return err;

        if ((err = start_session(dev, LOCKING_SP_UID, user_uid, &empty_str, 0))) {
            LOG(ERROR, "Failed to start User session with Locking SP.\n");
            return err;
        }
    }

    memcpy(c_pin_str, TABLE_C_PIN_UID, 8);
    hex_add(c_pin_str, 8, user_uid);

    medium_atom(atom_pin, &atom_pin_len, 1, 0, user_pin, user_pin_len);

    if ((err = set_row(dev, c_pin_str, TABLE_C_PIN_COLUMN_PIN, atom_pin, atom_pin_len))) {
        LOG(ERROR, "Failed to set pin of User authority.\n");
        close_session(dev);
        return err;
    }

    return close_session(dev);
}

int setup_password(struct disk_device *dev, size_t users[], size_t users_len,
                   unsigned char *user0_pin, size_t user0_pin_len,
                   unsigned char *user1_pin, size_t user1_pin_len)
{
    int err = 0;
    unsigned char c_pin_str[9] = { 0 };
    unsigned char atom_pin[256] = { 0 };
    size_t atom_pin_len = 0;

    if (!users || users_len != 2) {
        LOG(ERROR, "Users not not specified.\n");
        return -1;
    }

    if (!user0_pin || !user1_pin) {
        LOG(ERROR, "User PIN not specified.\n");
        return -1;
    }

    if ((err = start_session(dev, LOCKING_SP_UID, users[0], user0_pin, user0_pin_len))) {
        LOG(ERROR, "Failed to start session with Locking SP.\n");
        return err;
    }

    memcpy(c_pin_str, TABLE_C_PIN_UID, 8);
    hex_add(c_pin_str, 8, users[1]);

    medium_atom(atom_pin, &atom_pin_len, 1, 0, user1_pin, user1_pin_len);

    if ((err = set_row(dev, c_pin_str, TABLE_C_PIN_COLUMN_PIN, atom_pin, atom_pin_len))) {
        LOG(ERROR, "Failed to set pin of the authority.\n");
        close_session(dev);
        return err;
    }

    return close_session(dev);
}

int setup_programmatic_reset(struct disk_device *dev, unsigned char locking_range,
               unsigned char *challenge, size_t challenge_len, size_t user)
{
    int err = 0;
    unsigned char atom_true[32] = { 0 };
    unsigned char locking_range_uid_str[8];
    unsigned char atom_resets[32] = { 0 };
    size_t atom_resets_len = 0;
    size_t atom_true_len = 0;

    if (!challenge) {
        LOG(ERROR, "PIN not specified.\n");
        return -1;
    }

    // Enable TPER_RESET command.
    if ((err = start_session(dev, ADMIN_SP_UID, SID_USER_ID, challenge, challenge_len))) {
        LOG(ERROR, "Failed to start Admin SP session as SID.\n");
        return err;
    }

    tiny_atom(atom_true, &atom_true_len, 0, 1);
    if ((err = set_row(dev, TABLE_TPER_INFO_OBJ_UID, TABLE_TPER_INFO_COLUMN_PROGRAMMATIC_RESET_ENABLE, 
                       atom_true, atom_true_len))) {
        LOG(ERROR, "Failed to enable programmatic reset.\n");
        close_session(dev);
        return err;
    }

    err = close_session(dev);
    if (err)
        return err;

    // Change LockOnReset for the locking range.
    if (locking_range < ALL_LOCKING_RANGES) {
        if ((err = start_session(dev, LOCKING_SP_UID, user, challenge, challenge_len))) {
            LOG(ERROR, "Failed to start Admin SP session.\n");
            return err;
        }

        prepare_locking_range(locking_range_uid_str, locking_range);

        start_list(atom_resets, &atom_resets_len);
        tiny_atom(atom_resets, &atom_resets_len, 0, LOCKING_RANGE_COLUMN_LOCK_ON_RESET_POWER_CYCLE);
        tiny_atom(atom_resets, &atom_resets_len, 0, LOCKING_RANGE_COLUMN_LOCK_ON_RESET_PROGRAMMATIC);
        end_list(atom_resets, &atom_resets_len);

        if ((err = set_row(dev, locking_range_uid_str, LOCKING_RANGE_COLUMN_LOCK_ON_RESET,
                           atom_resets, atom_resets_len))) {
            LOG(ERROR, "Failed to set LockOnReset.\n");
            close_session(dev);
            return err;
        }

        err = close_session(dev);
    }

    return err;
}

int tper_reset(struct disk_device *dev)
{
    int err = 0;
    unsigned char buffer[512] = { 0 };

    LOG(INFO, "TPer reset\n");

    if ((err = trusted_command(dev, buffer, sizeof(buffer), IF_SEND, TCG_PROTOCOL_ID_2, TPER_RESET_COMID)))
        LOG(ERROR, "Failed to send programmatic reset.\n");

    return err;
}

int get_comid(struct disk_device *dev, int *comid)
{
    int err;
    struct get_comid_response resp = {};

    if ((err = trusted_command(dev, (uint8_t*)&resp, sizeof(resp), IF_RECV, TCG_PROTOCOL_ID_2, TCG_GET_COMID)))
        LOG(ERROR, "Failed to Get ComID.\n");
    else {
        *comid = be16_to_cpu(resp.comid);
        LOG(ERROR, "Get ComID 0x%04x\n", *comid);
    }

    return err;
}

int comid_valid(struct disk_device *dev, int comid)
{
    int err;
    struct comid_valid_request rq = {
        .request_code = cpu_to_be32(TCG_REQUEST_CODE_COMID_VALID)
    };
    struct comid_valid_response resp = { 0 };

    if ((err = do_level_0_discovery(dev))) {
        LOG(ERROR, "Failed to get ComID from Discovery0.\n");
        return err;
    }

    LOG(INFO, "Commid valid, Base ComID 0x%04x (Ext ComID 0x%04x)\n", dev->base_com_id, comid);

    rq.comid = cpu_to_be16(dev->base_com_id);

    if ((err = trusted_command(dev, (uint8_t*)&rq, sizeof(rq), IF_SEND, TCG_PROTOCOL_ID_2, dev->base_com_id))) {
        LOG(ERROR, "Failed to send stack reset.\n");
        return err;
    }

    if ((err = trusted_command(dev, (uint8_t*)&resp, sizeof(resp), IF_RECV, TCG_PROTOCOL_ID_2, dev->base_com_id))) {
        LOG(ERROR, "Failed to receive command: %i\n", err);
        return err;
    }

    LOG(INFO, "ComID valid response: ComID 0x%04x, Code 0x%x, Length 0x%x, State 0x%x\n",
        be16_to_cpu(resp.comid), be32_to_cpu(resp.request_code),
        be16_to_cpu(resp.data_length), be32_to_cpu(resp.state));
    LOG_HEX(&resp, 48);

    return 0;
}

int stack_reset(struct disk_device *dev)
{
    int err = 0, i = 0;
    struct stack_reset_request rq = {
        .request_code = cpu_to_be32(TCG_REQUEST_CODE_STACK_RESET)
    };
    struct stack_reset_response resp = { 0 };

    if ((err = do_level_0_discovery(dev))) {
        LOG(ERROR, "Failed to get ComID from Discovery0.\n");
        return err;
    }

    LOG(INFO, "Stack reset, Base ComID 0x%04x\n", dev->base_com_id);

    rq.comid = cpu_to_be16(dev->base_com_id);

    if ((err = trusted_command(dev, (uint8_t*)&rq, sizeof(rq), IF_SEND, TCG_PROTOCOL_ID_2, dev->base_com_id))) {
        LOG(ERROR, "Failed to send stack reset.\n");
        return err;
    }

    do {
        if ((err = trusted_command(dev, (uint8_t*)&resp, sizeof(resp), IF_RECV, TCG_PROTOCOL_ID_2, dev->base_com_id))) {
            LOG(ERROR, "Failed to receive command: %i\n", err);
            return err;
        }

        LOG(INFO, "Stack reset #%i response: ComID 0x%04x, Code 0x%x, Length 0x%x, Response 0x%x\n", i,
            be16_to_cpu(resp.comid), be32_to_cpu(resp.request_code),
            be16_to_cpu(resp.data_length), be32_to_cpu(resp.response));

        if (resp.data_length == 0)
            sleep(1);

    } while (resp.data_length == 0 && ++i < 3);

    return 0;
}

static void generate_activate_ranges(struct disk_device *dev, unsigned char *buffer, size_t *i,
                                    unsigned char locking_range)
{
    unsigned char uid[9] = { 0 };
    size_t j, max_lr;

    max_lr = be32_to_cpu(dev->features.single_user_mode.number_of_locking_objects_supported);

    if (locking_range == ALL_LOCKING_RANGES) {
        LOG(INFO, "Activate LOCKING_TABLE\n");
        memcpy(uid, LOCKING_TABLE_UID, 8);
        short_atom(buffer, i, 1, 0, uid, 8);
    } else if (locking_range >= max_lr) {
        LOG(INFO, "Activate LRs list 1..%zu\n", max_lr);
        start_list(buffer, i);
        //memcpy(uid, LOCKING_RANGE_GLOBAL_UID, 8);
        //short_atom(buffer, &i, 1, 0, uid, 8);
        for (j = 1; j < max_lr; j++) {
            prepare_locking_range(uid, j);
            short_atom(buffer, i, 1, 0, uid, 8);
        }
        end_list(buffer, i);
    } else {
        LOG(INFO, "Activate LR %d\n", locking_range);
        start_list(buffer, i);
        prepare_locking_range(uid, locking_range);
        short_atom(buffer, i, 1, 0, uid, 8);
        end_list(buffer, i);
    }
}

int setup_reactivate(struct disk_device *dev, unsigned char locking_range,
                     bool sum, bool sum_policy,
                     const unsigned char *challenge, size_t challenge_len)
{
    int err = 0;
    unsigned char param[3];
    unsigned char buffer[512] = { 0 };
    unsigned char response[512] = { 0 };
    size_t i = 0;

    if (!challenge) {
        LOG(ERROR, "PIN not specified.\n");
        return -1;
    }

    if ((err = start_session(dev, LOCKING_SP_UID, ADMIN_BASE_ID + 1, challenge, challenge_len))) {
        LOG(ERROR, "Failed to start Admin SP session.\n");
        return err;
    }

    // We have Discovery0 features now
    if (!dev->features.single_user_mode.shared.feature_code) {
        LOG(ERROR, "SUM not supported.\n");
        close_session(dev);
        return -1;
    }

    /*
     SP.Reactivate [
       SingleUserModeSelectionList = typeOr { EntireLockingTable : LockingTableUID,
         SelectedLockingObjects : list [ LockingObjectUIDs ] },
          RangeStartRangeLengthPolicy = enum{ 0 => User only, 1 => Admins only },
          Admin1PIN = bytes
      ]
      =>
      [ ]
      NOTE: is sum is not set, sent empty parameters => restore SP to factory default
    */

    prepare_method(buffer, &i, dev, THISSP, METHOD_REACTIVATE_UID);

    if (sum) {
        start_name(buffer, &i);

        memset(param, 0, sizeof(param));
        hex_add(param, 3, METHOD_ACTIVATE_SUM_LIST_PARAM);
        short_atom(buffer, &i, 0, 0, param, 3);

        generate_activate_ranges(dev, buffer, &i, locking_range);

        end_name(buffer, &i);

        /* RangeStartRangeLengthPolicy */
        start_name(buffer, &i);
        memset(param, 0, sizeof(param));
        hex_add(param, 3, METHOD_ACTIVATE_SUM_POLICY_PARAM);
        short_atom(buffer, &i, 0, 0, param, 3);

        tiny_atom(buffer, &i, 0, sum_policy ? 1 : 0);

        end_name(buffer, &i);
    }

    finish_method(buffer, &i);

    if ((err = invoke_method_abort(dev, buffer, i, response, sizeof(response)))) {
        LOG(ERROR, "Failed to activate Locking SP.\n");
        close_session(dev);
        return err;
    }

    // The session is aborted automatically.
    LOG(INFO, "------- ABORT SESSION -------\n\n");
    wipe_session(dev);

    return 0;
}

int setup_tper(struct disk_device *dev, const unsigned char *sid_pwd, size_t sid_pwd_len,
               bool sum, unsigned char sum_locking_range, bool sum_policy)
{
    int err = 0;
    unsigned char msid[2048] = { 0 }, param[3];
    unsigned char atom[1024] = { 0 };
    unsigned char buffer[512] = { 0 };
    unsigned char response[512] = { 0 };
    size_t atom_len = 0;
    size_t msid_len = 0;
    size_t i = 0;

    if (!sid_pwd) {
        LOG(ERROR, "PIN not specified.\n");
        return -1;
    }

    // Get MSID.
    if ((err = start_session(dev, ADMIN_SP_UID, ANYBODY_USER_ID, NULL, 0))) {
        LOG(ERROR, "Failed to start Admin SP session as Anybody.\n");
        return err;
    }
    if ((err = get_row_bytes(dev, TABLE_C_PIN_ROW_MSID_UID, TABLE_C_PIN_COLUMN_PIN, msid, sizeof(msid), &msid_len))) {
        LOG(ERROR, "Failed to read MSID.\n");
        close_session(dev);
        return err;
    }

    err = close_session(dev);
    if (err)
        return err;

    // We have Discovery0 features now
    if (sum && !dev->features.single_user_mode.shared.feature_code) {
        LOG(ERROR, "SUM not supported.\n");
        return -1;
    }

    // Update SID password.
    if ((err = start_session(dev, ADMIN_SP_UID, SID_USER_ID, msid, msid_len))) {
        LOG(ERROR, "Failed to start Admin SP session as SID with MSID.\n");
        return err;
    }

    medium_atom(atom, &atom_len, 1, 0, sid_pwd, sid_pwd_len);
    if ((err = set_row(dev, TABLE_C_PIN_ROW_SID_UID, TABLE_C_PIN_COLUMN_PIN, atom, atom_len))) {
        LOG(ERROR, "Failed to update SID password.\n");
        close_session(dev);
        return err;
    }
    err = close_session(dev);
    if (err)
        return err;

    // Activate locking SP.
    if ((err = start_session(dev, ADMIN_SP_UID, SID_USER_ID, sid_pwd, sid_pwd_len))) {
        LOG(ERROR, "Failed to start Admin SP session as SID with updated password.\n");
        return err;
    }
    /*
    SPObjectUID.Activate[ ]
    =>
    [ ]
    */
    prepare_method(buffer, &i, dev, LOCKING_SP_UID, METHOD_ACTIVATE_UID);

    if (sum) {
        start_name(buffer, &i);

        memset(param, 0, sizeof(param));
        hex_add(param, 3, METHOD_ACTIVATE_SUM_LIST_PARAM);
        short_atom(buffer, &i, 0, 0, param, 3);

        generate_activate_ranges(dev, buffer, &i, sum_locking_range);

        end_name(buffer, &i);

        /* RangeStartRangeLengthPolicy */
        start_name(buffer, &i);
        memset(param, 0, sizeof(param));
        hex_add(param, 3, METHOD_ACTIVATE_SUM_POLICY_PARAM);
        short_atom(buffer, &i, 0, 0, param, 3);

        tiny_atom(buffer, &i, 0, sum_policy ? 1 : 0);

        end_name(buffer, &i);
    }

    finish_method(buffer, &i);
    if ((err = invoke_method(dev, buffer, i, response, sizeof(response)))) {
        LOG(ERROR, "Failed to activate Locking SP.\n");
        close_session(dev);
        return err;
    }

    return close_session(dev);
}

int psid_revert(struct disk_device *dev, const unsigned char *psid, size_t psid_len)
{
    int err = 0;

    unsigned char buffer[1024] = { 0 };
    size_t buffer_used = 0;
    unsigned char response[1024] = { 0 };

    LOG(INFO, "PSID revert\n");

    if (!psid) {
        LOG(ERROR, "PSID not specified.\n");
        return -1;
    }

    if ((err = start_session(dev, ADMIN_SP_UID, PSID_USER_ID, psid, psid_len))) {
        LOG(ERROR, "Cannot initialise session.\n");
        return err;
    }

    /*
    SPObjectUID.Revert[ ]
    =>
    [ ]
    */
    prepare_method(buffer, &buffer_used, dev, ADMIN_SP_UID, METHOD_REVERT_UID);
    finish_method(buffer, &buffer_used);

    if ((err = invoke_method(dev, buffer, buffer_used, response, sizeof(response)))) {
        LOG(ERROR, "Failed to revert the TPer.\n");
    }

    // The session is aborted automatically.
    LOG(INFO, "------- ABORT SESSION -------\n\n");
    wipe_session(dev);

    return err;
}

#define RANDOM_REQUEST_SIZE 32 // Opal says that the minimal supported maximum is 32 bytes
int get_random(struct disk_device *dev, unsigned char *output, size_t output_len)
{
    int err = 0;
    unsigned char command[512] = { 0 };
    unsigned char response[512] = { 0 };
    unsigned char rng_buffer[RANDOM_REQUEST_SIZE] = { 0 };
    size_t done, offset, len, remaining, command_len = 0;

    LOG(INFO, "Getting Random numbers:\n");

    if ((err = start_session(dev, ADMIN_SP_UID, ANYBODY_USER_ID, NULL, 0))) {
        LOG(ERROR, "Failed to initialise session.\n");
        goto cleanup;
    }

    /*
    ThisSP.Random[
    Count : uinteger,
    BufferOut = cell_block ]
    =>
    [ Result : bytes ]
    */
    prepare_method(command, &command_len, dev, THISSP, METHOD_RANDOM_UID);
    tiny_atom(command, &command_len, 0, RANDOM_REQUEST_SIZE); // Count
    finish_method(command, &command_len);

    for (done = 0; done < output_len && !quit; done += RANDOM_REQUEST_SIZE) {

        if ((err = invoke_method(dev, command, command_len, response, sizeof(response)))) {
            LOG(ERROR, "Failed to get random data from the device.\n");
            goto cleanup;
        }

        offset = 0;
        if ((err = skip_to_parameter(response, &offset, 0, 0))) {
            LOG(ERROR, "Received unexpected token.\n");
            goto cleanup;
        }

        len = 0;
        if ((err = parse_bytes(response, &offset, rng_buffer, sizeof(rng_buffer), &len))) {
            LOG(ERROR, "Received unexpected token.\n");
            goto cleanup;
        }

        remaining = output_len - done;
        memcpy(output, rng_buffer, remaining > RANDOM_REQUEST_SIZE ? RANDOM_REQUEST_SIZE : remaining);
        output += RANDOM_REQUEST_SIZE;
    }

cleanup:
    if (quit && !err) {
        err = -1;
        LOG(ERROR, "Interrupted by a signal.\n");
    }

    close_session(dev);
    return err;
}

int get_random_session(struct disk_device *dev, unsigned char *output, size_t output_len)
{
    int err;
    unsigned char rng_buffer[RANDOM_REQUEST_SIZE] = { 0 };
    unsigned char response[512] = { 0 };
    unsigned char command[512] = { 0 };
    size_t command_len = 0, done, offset, len, remaining;

    /*
    ThisSP.Random[
    Count : uinteger,
    BufferOut = cell_block ]
    =>
    [ Result : bytes ]
    */
    prepare_method(command, &command_len, dev, THISSP, METHOD_RANDOM_UID);
    tiny_atom(command, &command_len, 0, RANDOM_REQUEST_SIZE); // Count
    finish_method(command, &command_len);

    for (done = 0; done < output_len && !quit; done += RANDOM_REQUEST_SIZE) {

        if ((err = invoke_method(dev, command, command_len, response, sizeof(response)))) {
            LOG(ERROR, "Failed to get random data from the device.\n");
            return -1;
        }

        if ((err = skip_to_parameter(response, &offset, 0, 0))) {
            LOG(ERROR, "Received unexpected token.\n");
            return -1;
        }

        if ((err = parse_bytes(response, &offset, rng_buffer, sizeof(rng_buffer), &len))) {
            LOG(ERROR, "Received unexpected token.\n");
            return -1;
        }

        remaining = output_len - done;
        memcpy(output, rng_buffer, remaining > RANDOM_REQUEST_SIZE ? RANDOM_REQUEST_SIZE : remaining);
        output += RANDOM_REQUEST_SIZE;
    }

    if (quit) {
        LOG(ERROR, "Interrupted by a signal.\n");
        return -1;
    }

    return 0;
}

int regenerate_range(struct disk_device *dev, unsigned char locking_range,
                     unsigned char *challenge, size_t challenge_len, size_t user)

{
    int err = 0;
    unsigned char locking_range_uid_str[8] = { 0 };
    unsigned char active_key_uid[128];
    unsigned char command[512] = { 0 };
    size_t command_len = 0;

    if (locking_range == ALL_LOCKING_RANGES) {
        LOG(ERROR, "LR must be specified.\n");
        return -1;
    }

    prepare_locking_range(locking_range_uid_str, locking_range);

    if ((err = start_session(dev, LOCKING_SP_UID, user, challenge, challenge_len))) {
        LOG(ERROR, "Failed to initialise session.\n");
        close_session(dev);
        return err;
    }

    if ((err = get_row_bytes(dev, locking_range_uid_str, LOCKING_RANGE_COLUMN_ACTIVE_KEY, active_key_uid,
                             sizeof(active_key_uid), NULL))) {
        LOG(ERROR, "Failed to get key type used in the locking range.\n");
        close_session(dev);
        return err;
    }

    /*
    CredentialObjectUID.GenKey [
    PublicExponent = uinteger,
    PinLength = uinteger ]
    =>
    [ ]
    */
    prepare_method(command, &command_len, dev, active_key_uid, METHOD_GENKEY_UID);
    finish_method(command, &command_len);

    if ((err = invoke_method(dev, command, command_len, command, sizeof(command)))) {
        LOG(ERROR, "Failed to re-generate the key.\n");
        close_session(dev);
        return err;
    }

    return close_session(dev);
}

int erase_range(struct disk_device *dev, unsigned char locking_range,
                     unsigned char *challenge, size_t challenge_len, size_t user)

{
    int err = 0;
    unsigned char locking_range_uid_str[8] = { 0 };
    unsigned char command[512] = { 0 };
    size_t command_len = 0;

    if (locking_range == ALL_LOCKING_RANGES) {
        LOG(ERROR, "LR must be specified.\n");
        return -1;
    }

    prepare_locking_range(locking_range_uid_str, locking_range);

    if ((err = start_session(dev, LOCKING_SP_UID, user, challenge, challenge_len))) {
        LOG(ERROR, "Failed to initialise session.\n");
        close_session(dev);
        return err;
    }

    if (!dev->features.single_user_mode.shared.feature_code) {
        LOG(ERROR, "SUM not supported.\n");
        close_session(dev);
        return -1;
    }

    /*
     LockingObjectUID.Erase [ ]
     =>
     [ ]
     NOTE: this method works only on a SUM object and will set user PIN to "" !
    */
    prepare_method(command, &command_len, dev, locking_range_uid_str, METHOD_ERASE_UID);
    finish_method(command, &command_len);

    if ((err = invoke_method(dev, command, command_len, command, sizeof(command)))) {
        LOG(ERROR, "Failed to erase locking range.\n");
        close_session(dev);
        return err;
    }

    return close_session(dev);
}
