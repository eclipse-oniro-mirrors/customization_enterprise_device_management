/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "set_device_name_plugin.h"

#include <regex>

#include "battery_utils.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl.h"
#include "iplugin_manager.h"
#include "string_serializer.h"

#ifdef WIFI_EDM_ENABLE
#include "inner_api/wifi_hotspot.h"
#include "wifi_device.h"
#endif

#ifdef TELEPHONY_EDM_ENABLE
#include "call_manager_client.h"
#endif

namespace OHOS {
namespace EDM {
const std::string KEY_USER_DEFINED_DEVICE_NAME = "settings.general.user_defined_device_name";
const std::string KEY_DISPLAY_DEVICE_NAME = "settings.general.display_device_name";
const std::string KEY_DISPLAY_DEVICE_NAME_STATE = "settings.general.display_device_name_state";
const std::string USER_DEFINED_DEVICE_NAME = "user_defined_device_name";
const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_";
const std::string SETTINGS_DATA_PREFIX = "?Proxy=true";
const int32_t DEVICE_NAME_MAX_LENGTH = 100;
#if defined(TELEPHONY_EDM_ENABLE) && defined(WIFI_EDM_ENABLE)
const int32_t MAIN_USER_ID = 100;
const int32_t HOTSPOT_NAME_MAX_LENGTH = 30;
const std::string HOTSPOT_NAME_ELLIPSIS = "...";
#endif

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetDeviceNamePlugin::GetPlugin());

void SetDeviceNamePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetDeviceNamePlugin, std::string>> ptr)
{
    EDMLOGD("SetDeviceNamePlugin::InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions,
        IPlugin::ApiType::PUBLIC);

    ptr->InitAttribute(EdmInterfaceCode::SET_DEVICE_NAME, PolicyName::POLICY_SET_DEVICE_NAME, config, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetDeviceNamePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetDeviceNamePlugin::OnSetPolicy(std::string &data, std::string &currentData, std::string &mergeData,
    int32_t userId)
{
    EDMLOGI("SetDeviceNamePlugin start set set deviceName data = %{public}s.", data.c_str());
    if (data.empty()) {
        EDMLOGE("OnSetPolicy deviceName is empty.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (data.length() > DEVICE_NAME_MAX_LENGTH) {
        EDMLOGE("OnSetPolicy deviceName length exceeds the limit.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t currentUserId = externalManagerFactory_->CreateOsAccountManager()->GetCurrentUserId();
    if (currentUserId < 0) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (userId != currentUserId) {
        EDMLOGE("SetDeviceNamePlugin::OnSetPolicy userId isn't current userId.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    std::string uri = SETTINGS_DATA_BASE_URI + std::to_string(userId) + SETTINGS_DATA_PREFIX;
    ErrCode code1 = EdmDataAbilityUtils::UpdateSettingsData(uri, KEY_USER_DEFINED_DEVICE_NAME, data);
    ErrCode code2 = EdmDataAbilityUtils::UpdateSettingsData(uri, KEY_DISPLAY_DEVICE_NAME, data);
    ErrCode code3 = EdmDataAbilityUtils::UpdateSettingsData(uri, KEY_DISPLAY_DEVICE_NAME_STATE,
        USER_DEFINED_DEVICE_NAME);
    if (FAILED(code1) || FAILED(code2) || FAILED(code3)) {
        EDMLOGE("SetDeviceNamePlugin::set deviceName failed, code1: %{public}d, code2: %{public}d, code3: %{public}d.",
            code1, code2, code3);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
#if defined(TELEPHONY_EDM_ENABLE) && defined(WIFI_EDM_ENABLE)
    UpdateHotspotNameIfNeed(data, userId);
#endif
    return ERR_OK;
}

ErrCode SetDeviceNamePlugin::OnGetPolicy(std::string &value, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGD("SetDeviceNamePlugin::OnGetPolicy");
    int32_t currentUserId = externalManagerFactory_->CreateOsAccountManager()->GetCurrentUserId();
    if (currentUserId < 0) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (userId != currentUserId) {
        EDMLOGE("SetDeviceNamePlugin::OnGetPolicy userId isn't current userId.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::string result;
    std::string uri = SETTINGS_DATA_BASE_URI + std::to_string(userId) + SETTINGS_DATA_PREFIX;
    ErrCode code = EdmDataAbilityUtils::GetStringFromSettingsDataShare(uri, KEY_DISPLAY_DEVICE_NAME, result);
    if (code != ERR_OK) {
        EDMLOGE("SetDeviceNamePlugin::get data from database failed : %{public}d.", code);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    reply.WriteInt32(ERR_OK);
    reply.WriteString(result);
    return ERR_OK;
}

#if defined(TELEPHONY_EDM_ENABLE) && defined(WIFI_EDM_ENABLE)
ErrCode SetDeviceNamePlugin::UpdateHotspotNameIfNeed(const std::string &value, int32_t userId)
{
    if (userId != MAIN_USER_ID) {
        EDMLOGI("SetDeviceNamePlugin current user isn't mainUser, No need to modify the hotspot.");
        return ERR_OK;
    }
    auto callManagerClient = DelayedSingleton<Telephony::CallManagerClient>::GetInstance();
    callManagerClient->Init(TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID);
    bool hasVoiceCapability = callManagerClient->HasVoiceCapability();
    callManagerClient->UnInit();
    if (!hasVoiceCapability) {
        EDMLOGI("SetDeviceNamePlugin does not has voice capability, No need to modify the hotspot.");
        return ERR_OK;
    }

    // 当前连接的wifi名称和要设置的热点名不重名
    bool isWifiActive = false;
    auto wifiDevice = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (wifiDevice == nullptr) {
        EDMLOGE("SetDeviceNamePlugin wifiDevice GetInstance null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = wifiDevice->IsWifiActive(isWifiActive);
    if (ret != ERR_OK) {
        EDMLOGE("SetDeviceNamePlugin wifiDevice IsWifiActive error.%{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (isWifiActive) {
        Wifi::WifiLinkedInfo wifiLinkedInfo;
        ret = wifiDevice->GetLinkedInfo(wifiLinkedInfo);
        if (ret != ERR_OK) {
            EDMLOGE("SetDeviceNamePlugin wifiDevice GetLinkedInfo error.%{public}d", ret);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        if (isWifiActive && wifiLinkedInfo.ssid == value) {
            EDMLOGI("SetDeviceNamePlugin wifi ssid is equal device name, can't modify the hotspot.");
            return ERR_OK;
        }
    }
    return UpdateHotspotName(value);
}

ErrCode SetDeviceNamePlugin::PrepareHotspotConfig(const std::string &value,
    Wifi::HotspotConfig &hotspotConfig, bool &needUpdate)
{
    needUpdate = false;
    std::string ssid = hotspotConfig.GetSsid();
    std::regex regex(R"(.*(CloudClone|SpaceClone|SubClone)$)");
    if (std::regex_match(ssid, regex)) {
        EDMLOGI("SetDeviceNamePlugin now is cloning.");
        return ERR_OK;
    }
    std::string newSsid = value;
    if (value.length() > HOTSPOT_NAME_MAX_LENGTH) {
        newSsid = GetSubstringByBytes(value, HOTSPOT_NAME_MAX_LENGTH - HOTSPOT_NAME_ELLIPSIS.length())
            + HOTSPOT_NAME_ELLIPSIS;
    }
    if (newSsid == ssid) {
        EDMLOGI("SetDeviceNamePlugin ssid has not changed.");
        return ERR_OK;
    }
    hotspotConfig.SetSsid(newSsid);
    needUpdate = true;
    return ERR_OK;
}

ErrCode SetDeviceNamePlugin::ApplyHotspotConfig(Wifi::WifiHotspot *hotspot,
    const Wifi::HotspotConfig &hotspotConfig)
{
    bool isHotspotActive = false;
    int32_t ret = hotspot->IsHotspotActive(isHotspotActive);
    if (ret != ERR_OK) {
        EDMLOGE("SetDeviceNamePlugin::ApplyHotspotConfig IsHotspotActive error.%{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (isHotspotActive) {
        ret = hotspot->DisableHotspot();
        if (ret != ERR_OK) {
            EDMLOGE("SetDeviceNamePlugin::ApplyHotspotConfig DisableHotspot error.%{public}d", ret);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        ret = hotspot->SetHotspotConfig(hotspotConfig);
        if (ret != ERR_OK) {
            EDMLOGE("SetDeviceNamePlugin::ApplyHotspotConfig SetHotspotConfig error.%{public}d", ret);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        ret = hotspot->EnableHotspot();
        if (ret != ERR_OK) {
            EDMLOGE("SetDeviceNamePlugin::ApplyHotspotConfig EnableHotspot error.%{public}d", ret);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    } else {
        ret = hotspot->SetHotspotConfig(hotspotConfig);
        if (ret != ERR_OK) {
            EDMLOGE("SetDeviceNamePlugin::ApplyHotspotConfig SetHotspotConfig error.%{public}d", ret);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode SetDeviceNamePlugin::UpdateHotspotName(const std::string &value)
{
    EDMLOGI("SetDeviceNamePlugin::UpdateHotspotName");
    auto hotspot = Wifi::WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
    if (hotspot == nullptr) {
        EDMLOGE("SetDeviceNamePlugin::UpdateHotspotName WifiHotspot nullptr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    Wifi::HotspotConfig hotspotConfig;
    int32_t ret = hotspot->GetHotspotConfig(hotspotConfig);
    if (ret != ERR_OK) {
        EDMLOGE("SetDeviceNamePlugin::UpdateHotspotName GetHotspotConfig error.%{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool needUpdate = false;
    ErrCode errCode = PrepareHotspotConfig(value, hotspotConfig, needUpdate);
    if (errCode != ERR_OK || !needUpdate) {
        return errCode;
    }
    return ApplyHotspotConfig(hotspot.get(), hotspotConfig);
}

std::string SetDeviceNamePlugin::GetSubstringByBytes(const std::string &value, size_t size)
{
    if (value.empty() || value.length() <= size) {
        return value;
    }
    std::string result;
    result.reserve(size);
    size_t current_bytes = 0;
    size_t i = 0;
    while (i < value.length()) {
        unsigned char c = value[i];
        size_t char_len = 1;
        // 根据UTF-8编码规则，通过首字节的高位判断字符占用多少字节
        if ((c & 0x80) == 0) {
            char_len = 1;    // 0xxxxxxx 1字节 (ASCII)
        } else if ((c & 0xE0) == 0xC0) {
            char_len = 2;    // 110xxxxx 2字节
        } else if ((c & 0xF0) == 0xE0) {
            char_len = 3;    // 1110xxxx 3字节
        } else if ((c & 0xF8) == 0xF0) {
            char_len = 4;    // 11110xxx 4字节
        } else {
            char_len = 1;    // 处理非首字节或非法UTF-8序列的容错
        }
        // 如果加入当前字符会超出限制，立刻停止截取
        if (current_bytes + char_len > size) {
            break;
        }
        // 防止输入的字符串格式不正确导致越界
        if (i + char_len > value.length()) {
            break;
        }
        // 追加完整的字符并更新索引
        result.append(value, i, char_len);
        current_bytes += char_len;
        i += char_len;
    }
    return result;
}
#endif
} // namespace EDM
} // namespace OHOS
