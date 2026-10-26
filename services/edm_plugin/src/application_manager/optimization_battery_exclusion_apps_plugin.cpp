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

#include "optimization_battery_exclusion_apps_plugin.h"

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<OptimizationBatteryExclusionAppsPlugin>());

OptimizationBatteryExclusionAppsPlugin::OptimizationBatteryExclusionAppsPlugin()
{
    policyCode_ = EdmInterfaceCode::OPTIMIZATION_BATTERY_EXCLUSION_APPS;
    policyName_ = PolicyName::POLICY_OPTIMIZATION_BATTERY_EXCLUSION_APPS;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    overMaxReturnErrCode_ = EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
    needSave_ = true;
}

ErrCode OptimizationBatteryExclusionAppsPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    std::vector<std::string> inputData;
    if (!ArrayStringSerializer::GetInstance()->GetPolicy(data, inputData)) {
        EDMLOGE("OnHandlePolicy: deserialize input data failed");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    auto serializer = ArrayStringSerializer::GetInstance();
    serializer->Deserialize(policyData.policyData, currentData);
    serializer->Deserialize(policyData.mergePolicyData, mergeData);

    FuncOperateType operateType = FuncCodeUtils::GetOperateType(funcCode);
    ErrCode ret;
    if (operateType == FuncOperateType::SET) {
        ret = OnBasicSetPolicy(inputData, currentData, mergeData, userId);
    } else if (operateType == FuncOperateType::REMOVE) {
        ret = OnBasicRemovePolicy(inputData, currentData, mergeData, userId);
    } else {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (ret == ERR_OK) {
        serializer->Serialize(currentData, policyData.policyData);
        serializer->Serialize(mergeData, policyData.mergePolicyData);
        policyData.isChanged = true;
    }
    return ret;
}

ErrCode OptimizationBatteryExclusionAppsPlugin::OnGetPolicy(std::string &policyDataStr, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    std::vector<std::string> result;
    ArrayStringSerializer::GetInstance()->Deserialize(policyDataStr, result);
    ArrayStringSerializer::GetInstance()->WritePolicy(reply, result);
    return ERR_OK;
}

ErrCode OptimizationBatteryExclusionAppsPlugin::OnAdminRemove(const std::string &adminName,
    const std::string &policyDataStr, const std::string &mergeJsonData, int32_t userId)
{
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    auto serializer = ArrayStringSerializer::GetInstance();
    serializer->Deserialize(policyDataStr, currentData);
    serializer->Deserialize(mergeJsonData, mergeData);
    ErrCode ret = OnBasicAdminRemove(currentData, mergeData, userId);
    if (ret == ERR_OK) {
        currentData.clear();
        serializer->Serialize(currentData, const_cast<std::string &>(policyDataStr));
        serializer->Serialize(mergeData, const_cast<std::string &>(mergeJsonData));
    }
    return ret;
}
} // namespace EDM
} // namespace OHOS
