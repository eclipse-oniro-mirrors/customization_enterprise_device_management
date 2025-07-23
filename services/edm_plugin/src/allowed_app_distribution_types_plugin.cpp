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

#include "allowed_app_distribution_types_plugin.h"

#include <algorithm>

#include <system_ability_definition.h>

#include "allowed_app_distribution_types_utils.h"
#include "app_distribution_type.h"
#include "array_int_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "edm_utils.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(AllowedAppDistributionTypesPlugin::GetPlugin());

void AllowedAppDistributionTypesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<AllowedAppDistributionTypesPlugin, std::vector<int32_t>>> ptr)
{
    EDMLOGI("AllowedAppDistributionTypesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE, PolicyName::POLICY_ALLOWED_INSTALL_APP_TYPE,
        EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayIntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AllowedAppDistributionTypesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&AllowedAppDistributionTypesPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&AllowedAppDistributionTypesPlugin::OnAdminRemove);
}

ErrCode AllowedAppDistributionTypesPlugin::OnSetPolicy(std::vector<int32_t> &data,
    std::vector<int32_t> &currentData, std::vector<int32_t> &mergeData, int32_t userId)
{
    EDMLOGD("AllowedAppDistributionTypesPlugin OnSetPolicy");
    if (data.empty()) {
        EDMLOGW("AllowedAppDistributionTypesPlugin OnSetPolicy data is empty");
        return ERR_OK;
    }
    for (const auto &item : data) {
        if (item < static_cast<int32_t>(AppDistributionType::APP_GALLERY) ||
            item > static_cast<int32_t>(AppDistributionType::CROWDTESTING)) {
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        }
    }
    std::vector<int32_t> needAddData =
        ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(currentData, data);
    std::vector<int32_t> afterHandle =
        ArrayIntSerializer::GetInstance()->SetUnionPolicyData(currentData, needAddData);
    std::vector<int32_t> afterMerge =
        ArrayIntSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    ErrCode errCode = AllowedAppDistributionTypesUtils::SetAppDistributionTypes(afterMerge);
    if (errCode != ERR_OK) {
        return errCode;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode AllowedAppDistributionTypesPlugin::OnRemovePolicy(std::vector<int32_t> &data, std::vector<int32_t> &currentData,
    std::vector<int32_t> &mergeData, int32_t userId)
{
    EDMLOGD("AllowedAppDistributionTypesPlugin OnRemovePolicy");
    if (data.empty()) {
        EDMLOGW("AllowedAppDistributionTypesPlugin OnRemovePolicy data is empty:");
        return ERR_OK;
    }
    for (const auto &item : data) {
        if (item < static_cast<int32_t>(AppDistributionType::APP_GALLERY) ||
            item > static_cast<int32_t>(AppDistributionType::CROWDTESTING)) {
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        }
    }
    std::vector<int32_t> afterHandle =
        ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(data, currentData);
    std::vector<int32_t> afterMerge =
        ArrayIntSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    ErrCode errCode = AllowedAppDistributionTypesUtils::SetAppDistributionTypes(afterMerge);
    if (errCode != ERR_OK) {
        return errCode;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode AllowedAppDistributionTypesPlugin::OnAdminRemove(const std::string &adminName, std::vector<int32_t> &data,
    std::vector<int32_t> &mergeData, int32_t userId)
{
    EDMLOGD("AllowedAppDistributionTypesPlugin OnAdminRemove");
    return AllowedAppDistributionTypesUtils::SetAppDistributionTypes(mergeData);
}
} // namespace EDM
} // namespace OHOS