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

#include "install_local_enterprise_app_policy_utils.h"

#include <algorithm>

#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "edm_log.h"
#include "ipolicy_manager.h"
#include "os_account_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {

// 从edm数据库获取离线安装器策略
int32_t InstallLocalEnterpriseAppPolicyUtils::GetPolicyValueFromRdb(const std::string &policyValue)
{
    if (policyValue.empty()) {
        return POLICY_NO_CONTROLL;
    }
    if (policyValue == EdmConstants::CONST_TRUE) {
        return POLICY_FORCE_ENABLE;
    }
    return POLICY_FORCE_DISABLE;
}

// 将策略写入Settings设备级数据库
ErrCode InstallLocalEnterpriseAppPolicyUtils::WriteDeviceSettingsData(int32_t policyValue)
{
    EDMLOGI("WriteDeviceSettingsPolicy value = %{public}d", policyValue);
    ErrCode ret = EdmDataAbilityUtils::UpdateSettingsData(
        EdmConstants::SETTINGS_DATA_BASE_URI, EdmConstants::KEY_INSTALL_LOCAL_APP_POLICY, std::to_string(policyValue));
    if (FAILED(ret)) {
        EDMLOGE("WriteDeviceSettingsPolicy failed, ret = %{public}d", ret);
    }
    return ret;
}

// 将策略写入Settings用户级数据库
ErrCode InstallLocalEnterpriseAppPolicyUtils::WriteUserSettingsData(int32_t policyValue, int32_t userId)
{
    EDMLOGI("WriteUserSettingsPolicy userId = %{public}d, value = %{public}d", userId, policyValue);
    std::string uri = std::string(EdmConstants::SETTINGS_DATA_SECURE_URI_PREFIX)
        + std::to_string(userId) + EdmConstants::SETTINGS_DATA_URI_SUFFIX;
    ErrCode ret = EdmDataAbilityUtils::UpdateSettingsData(
        uri, EdmConstants::KEY_INSTALL_LOCAL_APP_USER_POLICY, std::to_string(policyValue));
    if (FAILED(ret)) {
        EDMLOGE("WriteUserSettingsPolicy failed, userId = %{public}d, ret = %{public}d", userId, ret);
    }
    return ret;
}

// 离线安装器设备级策略实际值
bool InstallLocalEnterpriseAppPolicyUtils::GetDeviceActualPolicyValue()
{
    std::string value = system::GetParameter(PERSIST_LOCAL_INSTALL_ENABLE, "false");
    return value == "true";
}

// 离线安装器用户级策略实际值
bool InstallLocalEnterpriseAppPolicyUtils::GetUserActualPolicyValue(int32_t userId)
{
    std::vector<std::string> constraints;
    bool isEnable = false;
    AccountSA::OsAccountManager::IsOsAccountConstraintEnable(userId, CONSTRAINT_LOCAL_INSTALL, isEnable);
    if (isEnable) { 
        std::vector<AccountSA::ConstraintSourceTypeInfo> constraintTypes;
        AccountSA::OsAccountManager::QueryOsAccountConstraintSourceTypes(userId,
            CONSTRAINT_LOCAL_INSTALL, constraintTypes);
        isEnable = std::any_of(constraintTypes.begin(), constraintTypes.end(),
            [](const AccountSA::ConstraintSourceTypeInfo &info) {
                return info.typeInfo == AccountSA::ConstraintSourceType::CONSTRAINT_TYPE_DEVICE_OWNER;
            });
    }   
    return isEnable;
}

// 更新用户手动打开/关闭离线安装器策略
ErrCode InstallLocalEnterpriseAppPolicyUtils::UpdateOsAccountConstraint(bool value, int32_t userId)
{
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_LOCAL_INSTALL);
    ErrCode ret = AccountSA::OsAccountManager::SetOsAccountConstraints(
        userId, constraints, value);
    if (FAILED(ret)) {
        EDMLOGE("UpdateOsAccountConstraint failed, userId = %{public}d, value = %{public}d", userId, value);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

// 更新settings数据库
ErrCode InstallLocalEnterpriseAppPolicyUtils::UpdateSettingsPolicy(std::optional<int32_t> userId)
{
    EDMLOGI("UpdateSettingsPolicy");
    std::string policyValue;
    bool isDevice = !userId.has_value();
    int32_t updateUserId = isDevice ? EdmConstants::DEFAULT_USER_ID : userId.value();

    IPolicyManager::GetInstance()->GetPolicy(
        "", isDevice ? PolicyName::POLICY_SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED :
        PolicyName::POLICY_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT,
        policyValue, updateUserId);
    int32_t policy = GetPolicyValueFromRdb(policyValue);
    ErrCode ret = isDevice ? WriteDeviceSettingsData(policy) :
        WriteUserSettingsData(policy, updateUserId);
    if (FAILED(ret)) {
        return ret;
    }
    return ERR_OK;
}

// 同步用户手动设置的离线安装器参数
ErrCode InstallLocalEnterpriseAppPolicyUtils::UpdatePolicyByUser(std::optional<int32_t> userId)
{
    bool isDevice = !userId.has_value();
    bool deviceActual = GetDeviceActualPolicyValue();
    if (isDevice) {
        std::vector<int32_t> userIds;
        IPolicyManager::GetInstance()->GetPolicyUserIds(userIds);
        ErrCode ret = ERR_OK;
        for (int32_t id : userIds) {
            bool userActual = GetUserActualPolicyValue(id);
            bool finalValue = deviceActual || userActual;
            ret = UpdateOsAccountConstraint(finalValue, id);
        }
        return ret;
    } else {
        bool userActual = GetUserActualPolicyValue(userId.value());
        bool finalValue = deviceActual || userActual;
        return UpdateOsAccountConstraint(finalValue, userId.value());
    }
}
} // namespace EDM
} // namespace OHOS
