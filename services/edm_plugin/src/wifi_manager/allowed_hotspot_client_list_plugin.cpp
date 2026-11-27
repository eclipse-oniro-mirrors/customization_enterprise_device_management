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

#include "allowed_hotspot_client_list_plugin.h"

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "wifi_policy_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(AllowedHotspotClientListPlugin::GetPlugin());

void AllowedHotspotClientListPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<AllowedHotspotClientListPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("AllowedHotspotClientListPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ALLOWED_HOTSPOT_CLIENT_LIST,
        PolicyName::POLICY_ALLOWED_HOTSPOT_CLIENT_LIST,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AllowedHotspotClientListPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&AllowedHotspotClientListPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&AllowedHotspotClientListPlugin::OnAdminRemove);
}

ErrCode AllowedHotspotClientListPlugin::OnSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    EDMLOGI("AllowedHotspotClientListPlugin OnSetPolicy");
    if (data.empty()) {
        EDMLOGW("AllowedHotspotClientListPlugin OnSetPolicy data is empty");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (data.size() > EdmConstants::ALLOWED_HOTSPOT_CLIENT_LIST_MAX_SIZE) {
        EDMLOGE("AllowedHotspotClientListPlugin OnSetPolicy data size=[%{public}zu] is too large", data.size());
        return EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
    }
    if (data.size() + currentData.size() > EdmConstants::ALLOWED_HOTSPOT_CLIENT_LIST_MAX_SIZE) {
        EDMLOGE("AllowedHotspotClientListPlugin OnSetPolicy total size=[%{public}zu] exceeds limit",
            data.size() + currentData.size());
        return EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
    }

    std::vector<std::string> afterHandle =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(currentData, data);
    std::vector<std::string> afterMerge =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);

    currentData = afterHandle;
    mergeData = afterMerge;
    ErrCode ret = WifiPolicyUtils::SetHotspotClientListToWifi(mergeData);
    if (ret != ERR_OK) {
        EDMLOGE("AllowedHotspotClientListPlugin OnSetPolicy SetHotspotClientListToWifi failed ret=%{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AllowedHotspotClientListPlugin::OnRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    EDMLOGI("AllowedHotspotClientListPlugin OnRemovePolicy");
    if (data.empty()) {
        EDMLOGW("AllowedHotspotClientListPlugin OnRemovePolicy data is empty");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (data.size() > EdmConstants::ALLOWED_HOTSPOT_CLIENT_LIST_MAX_SIZE) {
        EDMLOGE("AllowedHotspotClientListPlugin OnRemovePolicy data size=[%{public}zu] is too large", data.size());
        return EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
    }

    std::vector<std::string> afterHandle =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(data, currentData);
    std::vector<std::string> afterMerge =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);

    currentData = afterHandle;
    mergeData = afterMerge;
    ErrCode ret = WifiPolicyUtils::SetHotspotClientListToWifi(mergeData);
    if (ret != ERR_OK) {
        EDMLOGE("AllowedHotspotClientListPlugin OnRemovePolicy SetHotspotClientListToWifi failed ret=%{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode AllowedHotspotClientListPlugin::OnAdminRemove(const std::string &adminName,
    std::vector<std::string> &data, std::vector<std::string> &mergeData, int32_t userId)
{
    EDMLOGI("AllowedHotspotClientListPlugin OnAdminRemove");
    ErrCode ret = WifiPolicyUtils::SetHotspotClientListToWifi(mergeData);
    if (ret != ERR_OK) {
        EDMLOGE("AllowedHotspotClientListPlugin OnAdminRemove SetHotspotClientListToWifi failed ret=%{public}d", ret);
        return ret;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
