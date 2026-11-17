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

#include "disallow_install_device_certificate_plugin.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "cert_manager_api.h"
#include "cm_config_type.h"
#include "cm_type.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "securec.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowInstallDeviceCertificatePlugin>());

namespace {
constexpr uint32_t MAX_CONFIG_ITEM_COUNT = 3;
constexpr size_t DEFAULT_CONFIG_ITEM_INDEX = 0;
constexpr size_t ENABLE_USER_LIST_ITEM_INDEX = 1;
constexpr size_t DISABLE_USER_LIST_ITEM_INDEX = 2;
constexpr char DEFAULT_CONFIG_KEY[] = "installGlobalUserCA_defaultConfig";
constexpr char ENABLE_USER_LIST_KEY[] = "enableInstallGlobalUserCA_userList";
constexpr char DISABLE_USER_LIST_KEY[] = "disableInstallGlobalUserCA_userList";
constexpr char DEFAULT_CONFIG_ENABLE[] = "enable";
constexpr char DEFAULT_CONFIG_DISABLE[] = "disable";
constexpr char USER_LIST_SEPARATOR = '|';

bool IsUserIdInList(const std::string &list, int32_t userId)
{
    std::string userIdStr = std::to_string(userId);
    size_t start = 0;
    while (start <= list.size()) {
        size_t end = list.find(USER_LIST_SEPARATOR, start);
        if (end == std::string::npos) {
            end = list.size();
        }
        if (end > start && list.substr(start, end - start) == userIdStr) {
            return true;
        }
        start = end + 1;
    }
    return false;
}

void AppendUserListToken(const std::string &token, const std::string &excludedUserId, std::string &result)
{
    if (token.empty() || token == excludedUserId) {
        return;
    }
    if (!result.empty()) {
        result.push_back(USER_LIST_SEPARATOR);
    }
    result.append(token);
}

void RemoveUserIdFromList(const std::string &list, int32_t userId, std::string &result)
{
    std::string userIdStr = std::to_string(userId);
    result.clear();
    size_t start = 0;
    while (start <= list.size()) {
        size_t end = list.find(USER_LIST_SEPARATOR, start);
        if (end == std::string::npos) {
            end = list.size();
        }
        AppendUserListToken(list.substr(start, end - start), userIdStr, result);
        start = end + 1;
    }
}
} // namespace

DisallowInstallDeviceCertificatePlugin::DisallowInstallDeviceCertificatePlugin()
{
    EDMLOGI("DisallowInstallDeviceCertificatePlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::INSTALL_DEVICE_CERTIFICATE;
    policyName_ = PolicyName::POLICY_DISALLOW_INSTALL_DEVICE_CERTIFICATE;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode DisallowInstallDeviceCertificatePlugin::SetOtherModulePolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisallowInstallDeviceCertificatePlugin::SetOtherModulePolicy, policy: %{public}d, userId: %{public}d",
        policy, userId);
    if (userId < 0) {
        EDMLOGE("DisallowInstallDeviceCertificatePlugin::SetOtherModulePolicy invalid userId");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    struct CertManagerConfig config = { 0, nullptr };
    int32_t ret = CmGetCertManagerConfig(nullptr, &config);
    if (FAILED(ret)) {
        EDMLOGE("DisallowInstallDeviceCertificatePlugin::SetOtherModulePolicy get config failed: %{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }

    std::string defaultConfig = DEFAULT_CONFIG_ENABLE;
    std::string enableUserList;
    std::string disableUserList;
    for (uint32_t i = 0; i < config.count; i++) {
        std::string key(config.configItems[i].key);
        std::string value(config.configItems[i].value);
        if (key == DEFAULT_CONFIG_KEY) {
            defaultConfig = value;
        } else if (key == ENABLE_USER_LIST_KEY) {
            enableUserList = value;
        } else if (key == DISABLE_USER_LIST_KEY) {
            disableUserList = value;
        }
    }
    CmFreeCertManagerConfig(&config);

    std::string newEnableUserList = enableUserList;
    std::string newDisableUserList = disableUserList;
    if (policy) {
        RemoveUserIdFromList(enableUserList, userId, newEnableUserList);
        if (!IsUserIdInList(disableUserList, userId)) {
            if (!newDisableUserList.empty()) {
                newDisableUserList.push_back(USER_LIST_SEPARATOR);
            }
            newDisableUserList.append(std::to_string(userId));
        }
    } else {
        RemoveUserIdFromList(disableUserList, userId, newDisableUserList);
        if (defaultConfig == DEFAULT_CONFIG_DISABLE && !IsUserIdInList(enableUserList, userId)) {
            if (!newEnableUserList.empty()) {
                newEnableUserList.push_back(USER_LIST_SEPARATOR);
            }
            newEnableUserList.append(std::to_string(userId));
        }
    }

    return UpdateCertManagerConfig(defaultConfig, newEnableUserList, newDisableUserList);
}

ErrCode DisallowInstallDeviceCertificatePlugin::UpdateCertManagerConfig(const std::string &defaultConfig,
    const std::string &enableUserList, const std::string &disableUserList)
{
    std::vector<struct CmConfigItem> items(MAX_CONFIG_ITEM_COUNT);
    for (auto &item : items) {
        item.key[0] = '\0';
        item.value[0] = '\0';
    }
    if (strncpy_s(items[DEFAULT_CONFIG_ITEM_INDEX].key, sizeof(items[DEFAULT_CONFIG_ITEM_INDEX].key),
            DEFAULT_CONFIG_KEY, sizeof(items[DEFAULT_CONFIG_ITEM_INDEX].key) - 1) != EOK ||
        strncpy_s(items[DEFAULT_CONFIG_ITEM_INDEX].value, sizeof(items[DEFAULT_CONFIG_ITEM_INDEX].value),
            defaultConfig.c_str(), sizeof(items[DEFAULT_CONFIG_ITEM_INDEX].value) - 1) != EOK ||
        strncpy_s(items[ENABLE_USER_LIST_ITEM_INDEX].key, sizeof(items[ENABLE_USER_LIST_ITEM_INDEX].key),
            ENABLE_USER_LIST_KEY, sizeof(items[ENABLE_USER_LIST_ITEM_INDEX].key) - 1) != EOK ||
        strncpy_s(items[ENABLE_USER_LIST_ITEM_INDEX].value, sizeof(items[ENABLE_USER_LIST_ITEM_INDEX].value),
            enableUserList.c_str(), sizeof(items[ENABLE_USER_LIST_ITEM_INDEX].value) - 1) != EOK ||
        strncpy_s(items[DISABLE_USER_LIST_ITEM_INDEX].key, sizeof(items[DISABLE_USER_LIST_ITEM_INDEX].key),
            DISABLE_USER_LIST_KEY, sizeof(items[DISABLE_USER_LIST_ITEM_INDEX].key) - 1) != EOK ||
        strncpy_s(items[DISABLE_USER_LIST_ITEM_INDEX].value, sizeof(items[DISABLE_USER_LIST_ITEM_INDEX].value),
            disableUserList.c_str(), sizeof(items[DISABLE_USER_LIST_ITEM_INDEX].value) - 1) != EOK) {
        EDMLOGE("DisallowInstallDeviceCertificatePlugin::UpdateCertManagerConfig copy config item failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }

    struct CertManagerConfig config = { 0, nullptr };
    config.count = MAX_CONFIG_ITEM_COUNT;
    config.configItems = items.data();

    int32_t ret = CmSetCertManagerConfig(&config);
    if (FAILED(ret)) {
        EDMLOGE("DisallowInstallDeviceCertificatePlugin::UpdateCertManagerConfig failed: %{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    EDMLOGI("DisallowInstallDeviceCertificatePlugin::UpdateCertManagerConfig success");
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
