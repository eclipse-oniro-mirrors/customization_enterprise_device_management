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

#include "disallow_distributed_transmission_plugin.h"

#include <ipc_skeleton.h>
#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "os_account_manager.h"


namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    DisallowDistributedTransmissionPlugin::GetPlugin());
const std::string CONSTRAINT_DISTRIBUTED_TRANSMISSION = "constraint.distributed.transmission.outgoing";

void DisallowDistributedTransmissionPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowDistributedTransmissionPlugin, bool>> ptr)
{
    EDMLOGI("DisallowDistributedTransmissionPlugin InitPlugin...");
    ptr->InitAttribute(
        EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION,
        PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowDistributedTransmissionPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowDistributedTransmissionPlugin::OnAdminRemove);
}

ErrCode DisallowDistributedTransmissionPlugin::OnSetPolicy(
    bool &data, bool &currentData, bool &mergeData, int32_t userId)
{
    EDMLOGI("DisallowDistributedTransmissionPlugin::OnSetPolicy, data: %{public}d, currentData: %{public}d, "
            "mergeData: %{public}d,userId: %{public}d", data, currentData, mergeData, userId);
    if (mergeData) {
        currentData = data;
        return ERR_OK;
    }
    ErrCode ret = SetDistributedTransmissionPolicy(data, userId);
    if (FAILED(ret)) {
        EDMLOGE("DisallowDistributedTransmissionPlugin::OnSetPolicy Failed, ret: %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}

ErrCode DisallowDistributedTransmissionPlugin::OnAdminRemove(
    const std::string &adminName, bool &data, bool &mergeData, int32_t userId)
{
    EDMLOGI("DisallowDistributedTransmissionPlugin::OnAdminRemove, adminName: %{public}s, data: %{public}d, "
            "mergeData: %{public}d, userId: %{public}d", adminName.c_str(), data, mergeData, userId);
    if (mergeData) {
        return ERR_OK;
    }
    if (data) {
        ErrCode ret = SetDistributedTransmissionPolicy(false, userId);
        if (FAILED(ret)) {
            EDMLOGE("DisallowDistributedTransmissionPlugin::OnAdminRemove Failed, ret: %{public}d", ret);
        }
    }
    return ERR_OK;
}

ErrCode DisallowDistributedTransmissionPlugin::SetDistributedTransmissionPolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisallowDistributedTransmissionPlugin::SetDistributedTransmissionPolicy, "
            "userId: %{public}d, policy: %{public}d", userId, policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_DISTRIBUTED_TRANSMISSION);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(
        constraints, policy, userId, EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("DisallowDistributedTransmissionPlugin SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}
} // namespace EDM
} // namespace OHOS
