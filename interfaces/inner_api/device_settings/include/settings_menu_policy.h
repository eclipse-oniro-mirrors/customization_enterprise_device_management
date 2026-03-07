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

#ifndef INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_SETTINGS_MENU_POLICY_H
#define INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_SETTINGS_MENU_POLICY_H

#include <iostream>
#include <vector>
#include <unordered_map>
#include <string>

namespace OHOS {
namespace EDM {
enum class SettingsMenu : uint32_t {
    ACCOUNT_ID = 0,
    WIFI = 1,
    WIFI_PROXY_SETTINGS = 2,
    WIFI_IP_SETTINGS = 3,
    BLUETOOTH = 4,
    NETWORK = 5,
    SUPER_DEVICE = 6,
    MORE_CONNECTIVITY_OPTIONS = 7,
    HOME_SCREEN_STYLE = 8,
    DISPLAY_BRIGHTNESS = 9,
    SOUND_VIBRATION = 10,
    NOTIFICATIONS = 11,
    BIOMETRICS_PASSWORD = 12,
    APPS_AND_SERVICES = 13,
    BATTERY = 14,
    STORAGE = 15,
    PRIVACY_AND_SECURITY = 16,
    DIGITAL_BALANCE = 17,
    SMART_ASSISTANT = 18,
    ACCESSIBILITY = 19,
    SYSTEM = 20,
    ABOUT_DEVICE = 21,
    SYSTEM_NAVIGATION = 22,
    LANGUAGE_REGION = 23,
    INPUT_METHODS = 24,
    DATE_TIME = 25,
    DATA_CLONE = 26,
    BACKUP_SETTINGS = 27,
    RESET = 28,
    SUPERHUB = 29,
    USER_EXPERIENCE = 30,
    SCREEN_CAST = 31,
    PRINTERS_SCANNERS = 32,
    MOBILE_DATA = 33,
    PERSONAL_HOTSPOT = 34,
    SIM_MANAGEMENT = 35,
    AIRPLANE_MODE = 36,
    MANAGE_DATA_USAGE = 37,
    VPN_SETTINGS = 38,
    TEXT_DISPLAY_SIZE = 39,
    APP_DUPLICATOR = 40,
    SEARCH = 41
};

constexpr int32_t MAX_SETTINGS_MENU_ID = 41;

class SettingsConverter {
public:
    static std::vector<std::string> getHiddenMenuNames(const std::vector<int32_t>& hiddenIds)
    {
        static const std::unordered_map<SettingsMenu, std::string> menuNameMap = {
            {SettingsMenu::ACCOUNT_ID,                "ACCOUNT_ID"},
            {SettingsMenu::WIFI,                      "WIFI"},
            {SettingsMenu::WIFI_PROXY_SETTINGS,       "WIFI_PROXY_SETTINGS"},
            {SettingsMenu::WIFI_IP_SETTINGS,          "WIFI_IP_SETTINGS"},
            {SettingsMenu::BLUETOOTH,                 "BLUETOOTH"},
            {SettingsMenu::NETWORK,                   "NETWORK"},
            {SettingsMenu::SUPER_DEVICE,              "SUPER_DEVICE"},
            {SettingsMenu::MORE_CONNECTIVITY_OPTIONS, "MORE_CONNECTIVITY_OPTIONS"},
            {SettingsMenu::HOME_SCREEN_STYLE,         "HOME_SCREEN_STYLE"},
            {SettingsMenu::DISPLAY_BRIGHTNESS,        "DISPLAY_BRIGHTNESS"},
            {SettingsMenu::SOUND_VIBRATION,           "SOUND_VIBRATION"},
            {SettingsMenu::NOTIFICATIONS,             "NOTIFICATIONS"},
            {SettingsMenu::BIOMETRICS_PASSWORD,       "BIOMETRICS_PASSWORD"},
            {SettingsMenu::APPS_AND_SERVICES,         "APPS_AND_SERVICES"},
            {SettingsMenu::BATTERY,                   "BATTERY"},
            {SettingsMenu::STORAGE,                   "STORAGE"},
            {SettingsMenu::PRIVACY_AND_SECURITY,      "PRIVACY_AND_SECURITY"},
            {SettingsMenu::DIGITAL_BALANCE,           "DIGITAL_BALANCE"},
            {SettingsMenu::SMART_ASSISTANT,           "SMART_ASSISTANT"},
            {SettingsMenu::ACCESSIBILITY,             "ACCESSIBILITY"},
            {SettingsMenu::SYSTEM,                    "SYSTEM"},
            {SettingsMenu::ABOUT_DEVICE,              "ABOUT_DEVICE"},
            {SettingsMenu::SYSTEM_NAVIGATION,         "SYSTEM_NAVIGATION"},
            {SettingsMenu::LANGUAGE_REGION,           "LANGUAGE_REGION"},
            {SettingsMenu::INPUT_METHODS,             "INPUT_METHODS"},
            {SettingsMenu::DATE_TIME,                 "DATE_TIME"},
            {SettingsMenu::DATA_CLONE,                "DATA_CLONE"},
            {SettingsMenu::BACKUP_SETTINGS,           "BACKUP_SETTINGS"},
            {SettingsMenu::RESET,                     "RESET"},
            {SettingsMenu::SUPERHUB,                  "SUPERHUB"},
            {SettingsMenu::USER_EXPERIENCE,           "USER_EXPERIENCE"},
            {SettingsMenu::SCREEN_CAST,               "SCREEN_CAST"},
            {SettingsMenu::PRINTERS_SCANNERS,         "PRINTERS_SCANNERS"},
            {SettingsMenu::MOBILE_DATA,               "MOBILE_DATA"},
            {SettingsMenu::PERSONAL_HOTSPOT,          "PERSONAL_HOTSPOT"},
            {SettingsMenu::SIM_MANAGEMENT,            "SIM_MANAGEMENT"},
            {SettingsMenu::AIRPLANE_MODE,             "AIRPLANE_MODE"},
            {SettingsMenu::MANAGE_DATA_USAGE,         "MANAGE_DATA_USAGE"},
            {SettingsMenu::VPN_SETTINGS,              "VPN_SETTINGS"},
            {SettingsMenu::TEXT_DISPLAY_SIZE,         "TEXT_DISPLAY_SIZE"},
            {SettingsMenu::APP_DUPLICATOR,            "APP_DUPLICATOR"},
            {SettingsMenu::SEARCH,                    "SEARCH"},
        };
        std::vector<std::string> result;
        result.reserve(hiddenIds.size());
        for (int32_t id : hiddenIds) {
            SettingsMenu menu = static_cast<SettingsMenu>(id);
            auto it = menuNameMap.find(menu);
            if (it != menuNameMap.end()) {
                result.push_back(it->second);
            } else {
                result.push_back("UNKNOWN_ID_" + std::to_string(id));
            }
        }
        return result;
    }
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_SETTINGS_MENU_POLICY_H
