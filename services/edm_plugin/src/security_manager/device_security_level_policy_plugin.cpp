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

#include "device_security_level_policy_plugin.h"

#include <string>

#include "cJSON.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code.h"
#include "iextra_policy_notification.h"
#include "iplugin_manager.h"
#include "managed_policy.h"
#include "override_interface_name.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<DeviceSecurityLevelPolicyPlugin>());

DeviceSecurityLevelPolicyPlugin::DeviceSecurityLevelPolicyPlugin()
{
    policyCode_ = EdmInterfaceCode::DEVICE_SECURITY_LEVEL_POLICY;
    policyName_ = PolicyName::POLICY_DEVICE_SECURITY_LEVEL_POLICY;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode DeviceSecurityLevelPolicyPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("DeviceSecurityLevelPolicyPlugin OnHandlePolicy");
    auto operateType = static_cast<FuncOperateType>(FUNC_TO_OPERATE(funcCode));
    if (operateType != FuncOperateType::SET) {
        EDMLOGW("DeviceSecurityLevelPolicyPlugin unsupported operate type: %{public}d.",
            static_cast<int32_t>(operateType));
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t policyValue = 0;
    if (!data.ReadInt32(policyValue)) {
        EDMLOGE("DeviceSecurityLevelPolicyPlugin read data failed.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    ErrCode result = OnSetPolicy(policyValue);
    if (result != ERR_OK) {
        return result;
    }
    return ERR_OK;
}

ErrCode DeviceSecurityLevelPolicyPlugin::OnSetPolicy(int32_t policyValue)
{
    EDMLOGI("DeviceSecurityLevelPolicyPlugin set policy value = %{public}d.", policyValue);
    if (policyValue < static_cast<int32_t>(DeviceSecurityLevelPolicy::DEFAULT_ENFORCED) ||
        policyValue > static_cast<int32_t>(DeviceSecurityLevelPolicy::ALLOW_FLEXIBLE)) {
        EDMLOGE("DeviceSecurityLevelPolicyPlugin policy illegal. Value = %{public}d.", policyValue);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (!system::SetParameter(EdmConstants::SecurityManager::PARAM_EDM_DEVICE_SECURITY_LEVEL_POLICY,
        std::to_string(policyValue))) {
        EDMLOGE("DeviceSecurityLevelPolicyPlugin SetParameter failed.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    cJSON* json = cJSON_CreateObject();
    if (json == nullptr) {
        EDMLOGE("DeviceSecurityLevelPolicyPlugin cJSON_CreateObject failed.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (cJSON_AddNumberToObject(json, "level", policyValue) == nullptr) {
        EDMLOGE("DeviceSecurityLevelPolicyPlugin cJSON_AddNumberToObject failed.");
        cJSON_Delete(json);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    char* jsonStr = cJSON_PrintUnformatted(json);
    if (jsonStr == nullptr) {
        EDMLOGE("DeviceSecurityLevelPolicyPlugin cJSON_PrintUnformatted failed.");
        cJSON_Delete(json);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    auto notification = IExtraPolicyNotification::GetInstance();
    if (notification != nullptr) {
        notification->NotifyPolicyChanged(
            OverrideInterfaceName::SecurityManager::SET_DEVICE_SECURITY_LEVEL_POLICY, std::string(jsonStr));
    }
    cJSON_free(jsonStr);
    cJSON_Delete(json);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
