/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "location_policy_plugin.h"
#include "edm_ipc_interface_code.h"
#include "locator_impl.h"
#include "parameters.h"
#include "int_serializer.h"
#include "iplugin_manager.h"
#include "location_policy.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(LocationPolicyPlugin::GetPlugin());
const std::string PARAM_EDM_LOCATION_POLICY = "persist.edm.location_policy";
void LocationPolicyPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<LocationPolicyPlugin, int32_t>> ptr)
{
    EDMLOGI("LocationPolicyPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::LOCATION_POLICY, "location_policy",
        "ohos.permission.ENTERPRISE_MANAGE_LOCATION", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&LocationPolicyPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&LocationPolicyPlugin::OnAdminRemove);
}

ErrCode LocationPolicyPlugin::OnSetPolicy(int32_t &data, int32_t &currentData, int32_t &mergeData, int32_t userId)
{
    EDMLOGD("LocationPolicyPlugin set location policy value = %{public}d.", data);
    if (mergeData != static_cast<int32_t>(LocationPolicy::DEFAULT_LOCATION_SERVICE)) {
        EDMLOGE("LocationPolicyPlugin set location failed, anaother admin has already set location policy.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    switch (data) {
        case static_cast<int32_t>(LocationPolicy::DEFAULT_LOCATION_SERVICE):
            SetDefaultLocationPolicy();
            break;
        case static_cast<int32_t>(LocationPolicy::DISALLOW_LOCATION_SERVICE):
            system::SetParameter(PARAM_EDM_LOCATION_POLICY, "disallow");
            Location::LocatorImpl::GetInstance()->EnableAbility(false);
            break;
        case static_cast<int32_t>(LocationPolicy::FORCE_OPEN_LOCATION_SERVICE):
            system::SetParameter(PARAM_EDM_LOCATION_POLICY, "force_open");
            Location::LocatorImpl::GetInstance()->EnableAbility(true);
            break;
        default:
            EDMLOGD("LocationPolicyPlugin location policy illegal. Value = %{public}d.", data);
            return EdmReturnErrCode::PARAM_ERROR;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}

void LocationPolicyPlugin::SetDefaultLocationPolicy()
{
    std::string currentState = system::GetParameter(PARAM_EDM_LOCATION_POLICY, "");
    system::SetParameter(PARAM_EDM_LOCATION_POLICY, "none");
    if (currentState == "force_open") {
        Location::LocatorImpl::GetInstance()->EnableAbility(false);
    }
}

ErrCode LocationPolicyPlugin::OnAdminRemove(const std::string &adminName, int32_t &policyData, int32_t &mergeData,
    int32_t userId)
{
    if (policyData == static_cast<int32_t>(LocationPolicy::DEFAULT_LOCATION_SERVICE)) {
        return ERR_OK;
    }
    SetDefaultLocationPolicy();
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
