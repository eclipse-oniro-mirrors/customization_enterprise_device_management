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

#include "allowed_running_bundles_plugin.h"

#include "algorithm"
#include "array_string_serializer.h"
#include "bms_utils.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(AllowedRunningBundlesPlugin::GetPlugin());

void AllowedRunningBundlesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<AllowedRunningBundlesPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("AllowedRunningBundlesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ALLOW_RUNNING_BUNDLES, PolicyName::POLICY_ALLOW_RUNNING_BUNDLES,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AllowedRunningBundlesPlugin::OnBasicSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&AllowedRunningBundlesPlugin::OnBasicRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&AllowedRunningBundlesPlugin::OnBasicAdminRemove);
    maxListSize_ = EdmConstants::APPID_MAX_SIZE;
    overMaxReturnErrCode_ = EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
}

ErrCode AllowedRunningBundlesPlugin::SetOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
    std::vector<std::string> &failedData)
{
    EDMLOGI("AllowedRunningBundlesPlugin SetOtherModulePolicy");
    if (HasConflictPolicy(userId)) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    return BmsUtils::DealAppRunningRules(data, userId, true, true);
}

ErrCode AllowedRunningBundlesPlugin::RemoveOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
    std::vector<std::string> &failedData)
{
    EDMLOGD("AllowedRunningBundlesPlugin OnRemovePolicy");
    return BmsUtils::DealAppRunningRules(data, userId, true, false);
}

bool AllowedRunningBundlesPlugin::HasConflictPolicy(int32_t userId)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string policyValue;
    policyManager->GetPolicy("", PolicyName::POLICY_DISALLOW_RUNNING_BUNDLES, policyValue, userId);
    if (!policyValue.empty()) {
        EDMLOGE("AllowedRunningBundlesPlugin policy conflict!");
        return true;
    }
    return false;
}
} // namespace EDM
} // namespace OHOS
