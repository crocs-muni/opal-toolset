// SPDX-License-Identifier: MIT

#ifndef UTILS_H_
#define UTILS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct disk_device;

#define ALL_LOCKING_RANGES 0xff

int unlock_range(struct disk_device *dev, unsigned char locking_range,
                 char read_locked, char write_locked, 
                 unsigned char *challenge, size_t challenge_len, size_t user);

int setup_range(struct disk_device *dev, unsigned char locking_range,
                unsigned char *challenge, size_t challenge_len,
                uint64_t start, uint64_t length,
                size_t users[], size_t users_len, bool sum);

int list_range(struct disk_device *dev, unsigned char locking_range,
               unsigned char *challenge, size_t challenge_len, size_t user);

int regenerate_range(struct disk_device *dev, unsigned char locking_range,
                     unsigned char *challenge, size_t challenge_len, size_t user);

int erase_range(struct disk_device *dev, unsigned char locking_range,
                     unsigned char *challenge, size_t challenge_len, size_t user);

int setup_enable_range(struct disk_device *dev, unsigned char locking_range,
                 char read_lock_enabled, char write_lock_enabled,
                 unsigned char *challenge, size_t challenge_len, size_t user);

int setup_user(struct disk_device *dev, size_t user_uid,
               unsigned char *admin_pin, size_t admin_pin_len,
               unsigned char *user_pin, size_t user_pin_len,
               bool sum, unsigned char sum_locking_range);

int add_user_range(struct disk_device *dev, unsigned char locking_range,
                unsigned char *challenge, size_t challenge_len,
                size_t users[], size_t users_len);

int setup_password(struct disk_device *dev, size_t users[], size_t users_len,
                   unsigned char *user0_pin, size_t user0_pin_len,
                   unsigned char *user1_pin, size_t user1_pin_len);

int setup_reactivate(struct disk_device *dev, unsigned char locking_range,
                     bool sum, bool sum_policy,
                     const unsigned char *challenge, size_t challenge_len);

int setup_programmatic_reset(struct disk_device *dev, unsigned char locking_range,
               unsigned char *challenge, size_t challenge_len, size_t user);

int tper_reset(struct disk_device *dev);
int stack_reset(struct disk_device *dev);

int get_comid(struct disk_device *dev, int *comid);
int comid_valid(struct disk_device *dev, int comid);

int setup_tper(struct disk_device *dev, const unsigned char *sid_pwd, size_t sid_pwd_len,
               bool sum, unsigned char sum_locking_range, bool sum_policy);

int psid_revert(struct disk_device *dev, const unsigned char *psid, size_t psid_len);

int get_random(struct disk_device *dev, unsigned char *output, size_t output_len);

int get_random_session(struct disk_device *dev, unsigned char *output, size_t output_len);

#endif // UTILS_H_
