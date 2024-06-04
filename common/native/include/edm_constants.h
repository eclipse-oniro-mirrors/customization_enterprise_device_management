/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef COMMON_NATIVE_INCLUDE_EDM_CONSTANTS_H
#define COMMON_NATIVE_INCLUDE_EDM_CONSTANTS_H

#include <iostream>

namespace OHOS {
namespace EDM {
namespace EdmConstants {
    static constexpr int32_t DECIMAL = 10;
    static constexpr int32_t APPID_MAX_SIZE = 200;
    static constexpr int32_t DEFAULT_USER_ID = 100;
    static constexpr int32_t ALLOWED_USB_DEVICES_MAX_SIZE = 1000;
    static constexpr int32_t STORAGE_USB_POLICY_READ_WRITE = 0;
    static constexpr int32_t STORAGE_USB_POLICY_READ_ONLY = 1;
    static constexpr int32_t STORAGE_USB_POLICY_DISABLED = 2;
    static constexpr int32_t AUTO_START_APPS_MAX_SIZE = 10;
    static constexpr int32_t SET_POLICIES_TYPE = 1;
    static constexpr int32_t SET_POLICY_TYPE = 2;
    static constexpr int32_t BLUETOOTH_WHITELIST_MAX_SIZE = 1000;

    static const std::string PERMISSION_TAG_VERSION_11 = "version_11";
    static const std::string PERMISSION_TAG_VERSION_12 = "version_12";

    namespace DeviceInfo {
        static const std::string DEVICE_NAME = "deviceName";
        static const std::string DEVICE_SERIAL = "deviceSerial";
        static const std::string SIM_INFO = "simInfo";
        static const std::string SIM_SLOT_ID = "slotId";
        static const std::string SIM_MEID = "MEID";
        static const std::string SIM_IMSI = "IMSI";
        static const std::string SIM_ICCID = "ICCID";
        static const std::string SIM_IMEI = "IMEI";
        static constexpr int32_t SIM_SLOT_ID_0 = 0;
        static constexpr int32_t SIM_SLOT_ID_1 = 1;
    } // namespace DeviceInfo

    namespace Restrictions {
        const std::string LABEL_DISALLOWED_POLICY_BLUETOOTH = "bluetooth";
        const std::string LABEL_DISALLOWED_POLICY_MODIFY_DATETIME = "modifyDateTime";
        const std::string LABEL_DISALLOWED_POLICY_PRINTER = "printer";
        const std::string LABEL_DISALLOWED_POLICY_HDC = "hdc";
        const std::string LABEL_DISALLOWED_POLICY_MIC = "microphone";
        const std::string LABEL_DISALLOWED_POLICY_FINGER_PRINT = "fingerprint";
        const std::string LABEL_DISALLOWED_POLICY_SCREENSHOT = "screenshot";
        const std::string LABEL_DISALLOWED_POLICY_SCREEN_RECORD = "screenRecord";
        const std::string LABEL_DISALLOWED_POLICY_USB = "usb";
        const std::string LABEL_DISALLOWED_POLICY_WIFI = "wifi";
        const std::string LABEL_DISALLOWED_POLICY_DISK_RECOVERY_KEY = "diskRecoveryKey";
        const std::string LABEL_DISALLOWED_POLICY_NEAR_LINK = "nearLink";
    } // namespace Restrictions

    namespace SecurityManager {
        static const std::string PATCH = "patch";
        static const std::string ENCRYPTION = "encryption";
        static const std::string ROOT = "root";
    } // namespace SecurityManager

    namespace DeviceSettings {
        const std::string SCREEN_OFF = "screenOff";
        const std::string POWER_POLICY = "powerPolicy";
        const std::string DATE_TIME = "dateTime";
    } // namespace DeviceSettings

    namespace DeviceControl {
        static const std::string RESET_FACTORY = "resetFactory";
        static const std::string REBOOT = "reboot";
        static const std::string SHUT_DOWN = "shutDown";
        static const std::string LOCK_SCREEN = "lockScreen";
    } // namespace DeviceControl
} // namespace EdmConstants
} // namespace EDM
} // namespace OHOS

#endif // COMMON_NATIVE_INCLUDE_EDM_CONSTANTS_H
