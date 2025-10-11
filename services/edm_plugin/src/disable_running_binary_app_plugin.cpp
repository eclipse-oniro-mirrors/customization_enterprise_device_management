/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "disable_running_binary_app_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "managed_policy.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableRunningBinaryAppPlugin::GetPlugin());
const std::string DEFAULT = 0;
const std::string DISALLOW = 0;
const std::string FORCE_OPEN = 0;
const std::string PARAM_EDM_RUNNING_BINARY_APP_POLICY = "persist.edm.running_binary_app_disable";

void DisableRunningBinaryAppPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableRunningBinaryAppPlugin,
    int32_t>> ptr)
{
    EDMLOGI("DisableRunningBinaryAppPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_RUNNING_BINARY_APP, PolicyName::POLICY_DISABLE_RUNNING_BINARY_APP,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableRunningBinaryAppPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableRunningBinaryAppPlugin::OnAdminRemove);
}

ErrCode DisableRunningBinaryAppPlugin::OnSetPolicy(int32_t &data, int32_t &currentData, int32_t &mergeData,
    int32_t userId)
{
    EDMLOGD("DisableRunningBinaryAppPlugin set policy value = %{public}d.", data);
    if (mergeData != static_cast<int32_t>(ManagedPolicy::DEFAULT)) {
        EDMLOGE("DisableRunningBinaryAppPlugin set failed, anaother admin has already set policy.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    switch (data) {
        case static_cast<int32_t>(ManagedPolicy::DEFAULT):
            system::SetParameter(PARAM_EDM_RUNNING_BINARY_APP_POLICY, DEFAULT);
            break;
        case static_cast<int32_t>(ManagedPolicy::DISALLOW):
            system::SetParameter(PARAM_EDM_RUNNING_BINARY_APP_POLICY, DISALLOW);
            break;
        case static_cast<int32_t>(ManagedPolicy::FORCE):
            system::SetParameter(PARAM_EDM_RUNNING_BINARY_APP_POLICY, FORCE_OPEN);
            break;
        default:
            EDMLOGD("DisableRunningBinaryAppPlugin policy illegal. Value = %{public}d.", data);
            return EdmReturnErrCode::PARAM_ERROR;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}

ErrCode DisableRunningBinaryAppPlugin::OnAdminRemove(const std::string &adminName, int32_t &policyData,
    int32_t &mergeData, int32_t userId)
{
    if (policyData == static_cast<int32_t>(ManagedPolicy::DEFAULT)) {
        return ERR_OK;
    }
    system::SetParameter(PARAM_EDM_RUNNING_BINARY_APP_POLICY, DEFAULT);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
