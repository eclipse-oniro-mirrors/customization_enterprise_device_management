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

#include "set_allowed_kiosk_apps_plugin.h"

#include "ability_manager_client.h"
#include "array_string_serializer.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "session_manager_lite.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetAllowedKioskAppsPlugin::GetPlugin());

void SetAllowedKioskAppsPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<SetAllowedKioskAppsPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("SetAllowedKioskAppsPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ALLOWED_KIOSK_APPS, PolicyName::POLICY_ALLOWED_KIOSK_APPS,
        EdmPermission::PERMISSION_ENTERPRISE_SET_KIOSK, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetAllowedKioskAppsPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&SetAllowedKioskAppsPlugin::OnAdminRemove);
    ptr->SetOtherServiceStartListener(&SetAllowedKioskAppsPlugin::OnOtherServiceStart);
}

ErrCode SetAllowedKioskAppsPlugin::OnSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    std::vector<std::string> needAddData =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(currentData, data);
    std::vector<std::string> afterHandle =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(currentData, needAddData);
    std::vector<std::string> afterMerge =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    if (afterMerge.size() > EdmConstants::POLICIES_MAX_SIZE) {
        EDMLOGE("SetAllowedKioskAppsPlugin OnSetPolicy merge data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    ErrCode ret = SetKioskAppsToAms(afterMerge);
    if (FAILED(ret)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ret = SetKioskAppsToWms(afterMerge);
    if (FAILED(ret)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode SetAllowedKioskAppsPlugin::OnGetPolicy(
    std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    std::vector<std::string> bundleNames;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData, bundleNames);
    reply.WriteInt32(ERR_OK);
    reply.WriteStringVector(bundleNames);
    return ERR_OK;
}

ErrCode SetAllowedKioskAppsPlugin::OnAdminRemove(
    const std::string &adminName, std::vector<std::string> &data, std::vector<std::string> &mergeData, int32_t userId)
{
    std::vector<std::string> emptyBundleNames;
    SetKioskAppsToAms(emptyBundleNames);
    SetKioskAppsToWms(emptyBundleNames);
    return ERR_OK;
}

void SetAllowedKioskAppsPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("SetAllowedKioskAppsPlugin OnOtherServiceStart %{public}d", systemAbilityId);
    std::string policyData;
    IPolicyManager::GetInstance()->GetPolicy(
        "", PolicyName::POLICY_ALLOWED_KIOSK_APPS, policyData, EdmConstants::DEFAULT_USER_ID);
    std::vector<std::string> bundleNames;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData, bundleNames);
    if (systemAbilityId == ABILITY_MGR_SERVICE_ID) {
        SetKioskAppsToAms(bundleNames);
    } else if (systemAbilityId == WINDOW_MANAGER_SERVICE_ID) {
        SetKioskAppsToWms(bundleNames);
    }
}

int32_t SetAllowedKioskAppsPlugin::SetKioskAppsToAms(const std::vector<std::string> &bundleNames)
{
    EDMLOGI("SetAllowedKioskAppsPlugin SetKioskAppsToAms");
    return ERR_OK;
}

int32_t SetAllowedKioskAppsPlugin::SetKioskAppsToWms(const std::vector<std::string> &bundleNames)
{
    EDMLOGI("SetAllowedKioskAppsPlugin SetKioskAppsToWms");
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
