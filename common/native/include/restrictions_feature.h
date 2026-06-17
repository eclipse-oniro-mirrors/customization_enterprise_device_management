/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMMON_NATIVE_INCLUDE_RESTRICTION_FEATURE_H
#define COMMON_NATIVE_INCLUDE_RESTRICTION_FEATURE_H

namespace OHOS {
namespace EDM {
enum class RestrictionsFeature : int32_t {
    WIFI_P2P = 0,
    LOCAL_INPUT = 2,
    SUDO = 4,
    TRAFFIC_REDIRECTION = 5,
    CORE_DUMP = 6,
    RS232 = 7,
    SECURE_ERASE = 8,
    BLUETOOTH = 9,
    MODIFY_DATETIME = 10,
    PRINTER = 11,
    HDC = 12,
    MICROPHONE = 13,
    FINGERPRINT = 14,
    USB = 15,
    WIFI = 16,
    TETHERING = 17,
    INACTIVE_USER_FREEZE = 18,
    CAMERA = 19,
    MTP_CLIENT = 20,
    MTP_SERVER = 21,
    SAMBA_CLIENT = 22,
    SAMBA_SERVER = 23,
    BACKUP_AND_RESTORE = 24,
    MAINTENANCE_MODE = 25,
    MMS = 26,
    SMS = 27,
    MOBILE_DATA = 28,
    AIRPLANE_MODE = 29,
    VPN = 30,
    NOTIFICATION = 31,
    NFC = 32,
    PRIVATE_SPACE = 33,
    TELEPHONY_CALL = 34,
    APP_CLONE = 35,
    EXTERNAL_STORAGE_CARD = 36,
    RANDOM_MAC = 37,
    UNMUTE_DEVICE = 38,
    HDC_REMOTE = 39,
    VIRTUAL_SERVICE = 40,
    USB_SERIAL = 41,
    SCREENSHOT = 42,
    SCREEN_RECORD = 43,
    DISK_RECOVERY_KEY = 44,
    NEAR_LINK = 45,
    DEVELOPER_MODE = 46,
    RESET_FACTORY = 47,
    REMOTE_DESK = 48,
    REMOTE_DIAGNOSIS = 49,
    OTA_UPDATE = 50,
};

enum class RestrictionsFeatureForAccount : int32_t {
    MULTI_WINDOW = 0,
    DISTRIBUTED_TRANSMISSION = 1,
    SUPER_HUB = 2,
    FINGERPRINT = 3,
    PRINT = 4,
    MTP_CLIENT = 5,
    USB_STORAGE_DEVICE_WRITE = 6,
    DISK_RECOVERY_KEY = 7,
    SUDO = 8,
    DISTRIBUTED_TRANSMISSION_OUTGOING = 9,
    OPEN_FILE_BOOST = 10,
};

enum class UserRestrictionForDevice : int32_t {
    SET_APN = 0,
    POWER_LONG_PRESS = 1,
    SET_ETHERNET_IP = 2,
    SET_DEVICE_NAME = 3,
    SET_BIOMETRICS_AND_SCREENLOCK = 4,
};

enum class UserRestrictionForAccount : int32_t {
    MODIFY_WALLPAPER = 0,
};
} // namespace EDM
} // namespace OHOS

#endif // COMMON_NATIVE_INCLUDE_RESTRICTION_FEATURE_H