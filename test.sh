set -e

failed=0

# NOTE: avoiding reading the first block as USB connected drives have some issue here
function unreadable() {
  sleep 0.15
  if dd if="${DEV}" of=/dev/null bs=4096 count=1 skip=1 iflag=direct &>>"${LOG_FILE}"; then
    echo " bad" | tee -a "${LOG_FILE}"
    failed="$((failed + 1))"
  else
    echo " good" | tee -a "${LOG_FILE}"
  fi
}

function readable() {
  sleep 0.15
  if dd if="${DEV}" of=/dev/null bs=4096 count=1 skip=1 iflag=direct &>>"${LOG_FILE}"; then
    echo " good" | tee -a "${LOG_FILE}"
  else
    echo " bad" | tee -a "${LOG_FILE}"
    failed="$((failed + 1))"
  fi
}

OPAL_UTIL="./control"
DEV="${1}"
PSID="${2}"

echo "Warning: All data on the disk will be deleted!"

if [ "$#" -ne 2 ]; then
    echo "Usage: ${0} device_file psid"
    exit 1
fi

ADMIN_PIN="0000"
USER_1_PIN="1111"
USER_2_PIN="2222"
USER_3_PIN="3333"
USER_4_PIN="4444"
LOG_FILE="./test_log"


echo "test_start" | tee "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "DEV:        ${DEV}" | tee -a "${LOG_FILE}"
echo "ADMIN_PIN:  ${ADMIN_PIN}" | tee -a "${LOG_FILE}"
echo "USER_1_PIN: ${USER_1_PIN}" | tee -a "${LOG_FILE}"
echo "USER_2_PIN: ${USER_2_PIN}" | tee -a "${LOG_FILE}"
echo "USER_3_PIN: ${USER_3_PIN}" | tee -a "${LOG_FILE}"
echo "USER_4_PIN: ${USER_4_PIN}" | tee -a "${LOG_FILE}"
echo "PSID:       ${PSID}" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"

"${OPAL_UTIL}" psid_revert "${DEV}" --verify-pin "${PSID}" &>>"${LOG_FILE}"

"${OPAL_UTIL}" setup_tper "${DEV}" --assign-pin "${ADMIN_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" setup_reset "${DEV}" --locking-range 1 --verify-pin "${ADMIN_PIN}" &>>"${LOG_FILE}"

"${OPAL_UTIL}" setup_user "${DEV}" --user 1 --verify-pin "${ADMIN_PIN}" --assign-pin "${USER_1_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" setup_user "${DEV}" --user 2 --verify-pin "${ADMIN_PIN}" --assign-pin "${USER_2_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" setup_user "${DEV}" --user 3 --verify-pin "${ADMIN_PIN}" --assign-pin "${USER_3_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" setup_user "${DEV}" --user 4 --verify-pin "${ADMIN_PIN}" --assign-pin "${USER_4_PIN}" &>>"${LOG_FILE}"

readable "${DEV}"

echo "locking range does not affect data outside of the range" | tee -a "${LOG_FILE}"
"${OPAL_UTIL}" -V setup_range "${DEV}" --locking-range 1 --locking-range-start 512 --locking-range-length 512 --user 1 --user 2 --user 4 --verify-pin "${ADMIN_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" -V unlock "${DEV}" --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 1 &>>"${LOG_FILE}"
"${OPAL_UTIL}" list_range $DEV --locking-range 1 --user 1 --verify-pin "${USER_1_PIN}" &>>"${LOG_FILE}"
readable "${DEV}"

"${OPAL_UTIL}" -V unlock "${DEV}" --user 2 --verify-pin "${USER_2_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
"${OPAL_UTIL}" list_range $DEV --locking-range 1 --user 2 --verify-pin "${USER_2_PIN}" &>>"${LOG_FILE}"
readable "${DEV}"

echo "locking range does affect data inside the range" | tee -a "${LOG_FILE}"
"${OPAL_UTIL}" -V setup_range "${DEV}" --locking-range 1 --locking-range-start 0 --locking-range-length 512 --user 1 --user 2 --user 4 --verify-pin "${ADMIN_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" -V unlock "${DEV}" --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 1 --write-locked 1 &>>"${LOG_FILE}"
"${OPAL_UTIL}" -V unlock "${DEV}" --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 1 &>>"${LOG_FILE}"
"${OPAL_UTIL}" list_range $DEV --locking-range 1 --user 1 --verify-pin "${USER_1_PIN}" &>>"${LOG_FILE}"
unreadable "${DEV}"

echo "programmatic reset"
"${OPAL_UTIL}" -VV unlock "${DEV}" --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
readable "${DEV}"
"${OPAL_UTIL}" reset "${DEV}"
unreadable "${DEV}"
"${OPAL_UTIL}" -VV unlock "${DEV}" --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 1 &>>"${LOG_FILE}"
unreadable "${DEV}"
"${OPAL_UTIL}" reset "${DEV}"
unreadable "${DEV}"


echo "can't unlock with wrong password" | tee -a "${LOG_FILE}"
! "${OPAL_UTIL}" unlock "${DEV}" --user 2 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
unreadable "${DEV}"
echo "or wrong user" | tee -a "${LOG_FILE}"
! "${OPAL_UTIL}" unlock "${DEV}" --user 3 --verify-pin "${USER_3_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
unreadable "${DEV}"
"${OPAL_UTIL}" unlock "${DEV}" --user 4 --verify-pin "${USER_4_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
readable "${DEV}"

echo "locking range does affect data inside the range (admin)" | tee -a "${LOG_FILE}"
"${OPAL_UTIL}" setup_range "${DEV}" --locking-range 1 --locking-range-start 0 --locking-range-length 512 --admin 1 --verify-pin "${ADMIN_PIN}" &>>"${LOG_FILE}"
echo "${OPAL_UTIL}" unlock "${DEV}" --admin 1 --verify-pin "${ADMIN_PIN}" --locking-range 1 --read-locked 1
"${OPAL_UTIL}" unlock "${DEV}" --admin 1 --verify-pin "${ADMIN_PIN}" --locking-range 1 --read-locked 1 &>>"${LOG_FILE}"
unreadable "${DEV}"
"${OPAL_UTIL}" unlock "${DEV}" --admin 1 --verify-pin "${ADMIN_PIN}" --locking-range 1 --read-locked 0 &>>"${LOG_FILE}"
readable "${DEV}"

echo "can we write to readlocked range?"
"${OPAL_UTIL}" setup_range "${DEV}" --locking-range 1 --locking-range-start 0 --locking-range-length 512 --user 1 --user 2 --user 4 --verify-pin "${ADMIN_PIN}" &>>"${LOG_FILE}"
"${OPAL_UTIL}" unlock "${DEV}" --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 0 --write-locked 0 &>>"${LOG_FILE}"
readable "${DEV}"
printf "  before writing:                    "
head "${DEV}" -c 16 | hexdump | head -n 1 || true
dd if=/dev/urandom of="${DEV}" bs=100K count=1 oflag=direct &>/dev/null || true
printf "  after writing while read-unlocked: "
head "${DEV}" -c 16 | hexdump | head -n 1 || true
"${OPAL_UTIL}" unlock "${DEV}" --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 1 --write-locked 0 &>>"${LOG_FILE}"
unreadable "${DEV}"
dd if=/dev/urandom of="${DEV}" bs=100K count=1 oflag=direct &>/dev/null || true
"${OPAL_UTIL}" unlock "${DEV}" --user 1 --verify-pin "${USER_1_PIN}" --locking-range 1 --read-locked 0 --write-locked 0 &>>"${LOG_FILE}"
readable "${DEV}"
printf "  after writing while read-locked:   "
head "${DEV}" -c 16 | hexdump | head -n 1 || true

"${OPAL_UTIL}" psid_revert "${DEV}" --verify-pin "${PSID}" &>>"${LOG_FILE}"

echo ""
echo "results:"
if [[ "${failed}" -eq 0 ]]; then
  echo "ok"
  exit 0
else
  echo "failed ${failed} tests"
  exit 1
fi
