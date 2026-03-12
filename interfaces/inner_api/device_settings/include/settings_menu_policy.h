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

#include <array>
#include <cstdint>
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
    MOBILE_NETWORK = 6,
    SUPER_DEVICE = 7,
    MORE_CONNECTIVITY_OPTIONS = 8,
    HOME_SCREEN_STYLE = 9,
    DISPLAY_BRIGHTNESS = 10,
    SOUND_VIBRATION = 11,
    NOTIFICATIONS = 12,
    BIOMETRICS_PASSWORD = 13,
    APPS_AND_SERVICES = 14,
    BATTERY = 15,
    STORAGE = 16,
    PRIVACY_AND_SECURITY = 17,
    DIGITAL_BALANCE = 18,
    SMART_ASSISTANT = 19,
    ACCESSIBILITY = 20,
    SYSTEM = 21,
    ABOUT_DEVICE = 22,
    SYSTEM_NAVIGATION = 23,
    LANGUAGE_REGION = 24,
    INPUT_METHODS = 25,
    DATE_TIME = 26,
    DATA_CLONE = 27,
    BACKUP_SETTINGS = 28,
    RESET = 29,
    SUPERHUB = 30,
    USER_EXPERIENCE = 31,
    SCREEN_CAST = 32,
    PRINTERS_SCANNERS = 33,
    MOBILE_DATA = 34,
    PERSONAL_HOTSPOT = 35,
    SIM_MANAGEMENT = 36,
    AIRPLANE_MODE = 37,
    MANAGE_DATA_USAGE = 38,
    VPN_SETTINGS = 39,
    TEXT_DISPLAY_SIZE = 40,
    APP_DUPLICATOR = 41,
    SEARCH = 42
};

constexpr int32_t MAX_SETTINGS_MENU_ID = 42;

class SettingsConverter {
public:
    static std::vector<std::string> getHiddenMenuNames(const std::vector<int32_t>& hiddenIds)
    {
        const auto& nameMap = getNameMap();
        std::vector<std::string> result;
        result.reserve(hiddenIds.size());
        for (int32_t id : hiddenIds) {
            if (id < 0 || id > MAX_SETTINGS_MENU_ID) {
                continue;
            }
            auto it = nameMap.find(static_cast<SettingsMenu>(id));
            result.push_back(it != nameMap.end() ? it->second : "UNKNOWN_ID_" + std::to_string(id));
        }
        return result;
    }
    static std::vector<int32_t> getHiddenMenuIds(const std::vector<std::string>& hiddenNames)
    {
        const auto& idMap = getIdMap();
        std::vector<int32_t> result;
        result.reserve(hiddenNames.size());
        for (const std::string& name : hiddenNames) {
            auto it = idMap.find(name);
            if (it == idMap.end()) {
                continue;
            }
            int32_t id = static_cast<int32_t>(it->second);
            if (id < 0 || id > MAX_SETTINGS_MENU_ID) {
                continue;
            }
            result.push_back(id);
        }
        return result;
    }

private:
    struct MenuItem {
        SettingsMenu id;
        const char*  name;
    };
    static constexpr std::array<MenuItem, 43> MENU_ITEMS = {{
        {SettingsMenu::ACCOUNT_ID,                "ACCOUNT_ID"},
        {SettingsMenu::WIFI,                      "WIFI"},
        {SettingsMenu::WIFI_PROXY_SETTINGS,       "WIFI_PROXY_SETTINGS"},
        {SettingsMenu::WIFI_IP_SETTINGS,          "WIFI_IP_SETTINGS"},
        {SettingsMenu::BLUETOOTH,                 "BLUETOOTH"},
        {SettingsMenu::NETWORK,                   "NETWORK"},
        {SettingsMenu::MOBILE_NETWORK,            "MOBILE_NETWORK"},
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
    }};
    static const std::unordered_map<SettingsMenu, std::string>& getNameMap()
    {
        static const auto map = []() {
            std::unordered_map<SettingsMenu, std::string> m;
            for (const auto& item : MENU_ITEMS) {
                m.emplace(item.id, item.name);
            }
            return m;
        }();
        return map;
    }
    static const std::unordered_map<std::string, SettingsMenu>& getIdMap()
    {
        static const auto map = []() {
            std::unordered_map<std::string, SettingsMenu> m;
            for (const auto& item : MENU_ITEMS) {
                m.emplace(item.name, item.id);
            }
            return m;
        }();
        return map;
    }
};

} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_DEVICE_SETTINGS_INCLUDE_SETTINGS_MENU_POLICY_H