/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "control_panel_quick_toggle_list_plugin.h"

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {

namespace {
const std::string QUICK_TOGGLE_LIST_KEY = "control_panel_quick_toggle_list";
constexpr uint32_t TOGGLE_LIST_MAX_SIZE = 1000;
}

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    ControlPanelQuickToggleListPlugin::GetPlugin());

void ControlPanelQuickToggleListPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<ControlPanelQuickToggleListPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("ControlPanelQuickToggleListPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::CONTROL_PANEL_QUICK_TOGGLE_LIST,
        PolicyName::POLICY_CONTROL_PANEL_QUICK_TOGGLE_LIST,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ControlPanelQuickToggleListPlugin::OnBasicSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&ControlPanelQuickToggleListPlugin::OnBasicRemovePolicy,
        FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&ControlPanelQuickToggleListPlugin::OnBasicAdminRemove);
    maxListSize_ = TOGGLE_LIST_MAX_SIZE;
    overMaxReturnErrCode_ = EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
}

ErrCode ControlPanelQuickToggleListPlugin::OnBasicSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    ErrCode ret = BasicArrayStringPlugin::OnBasicSetPolicy(data, currentData, mergeData, userId);
    if (FAILED(ret)) {
        return ret;
    }
    return WriteMergeToSettingsData(mergeData, userId);
}

ErrCode ControlPanelQuickToggleListPlugin::OnBasicRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    ErrCode ret = BasicArrayStringPlugin::OnBasicRemovePolicy(data, currentData, mergeData, userId);
    if (FAILED(ret)) {
        return ret;
    }
    return WriteMergeToSettingsData(mergeData, userId);
}

ErrCode ControlPanelQuickToggleListPlugin::OnBasicAdminRemove(const std::string &adminName,
    std::vector<std::string> &data, std::vector<std::string> &mergeData, int32_t userId)
{
    ErrCode ret = BasicArrayStringPlugin::OnBasicAdminRemove(adminName, data, mergeData, userId);
    if (FAILED(ret)) {
        return ret;
    }
    std::vector<std::string> newMerge =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(mergeData, data);
    return WriteMergeToSettingsData(newMerge, userId);
}

ErrCode ControlPanelQuickToggleListPlugin::WriteMergeToSettingsData(
    const std::vector<std::string> &mergeData, int32_t userId)
{
    EDMLOGI("ControlPanelQuickToggleListPlugin WriteMergeToSettingsData userId=%{public}d size=%{public}zu",
        userId, mergeData.size());
    std::string jsonStr;
    if (!ArrayStringSerializer::GetInstance()->Serialize(mergeData, jsonStr)) {
        EDMLOGE("ControlPanelQuickToggleListPlugin Serialize failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    std::string baseUri = std::string(EdmConstants::SETTINGS_DATA_SECURE_URI_PREFIX) +
        std::to_string(userId) + EdmConstants::SETTINGS_DATA_URI_SUFFIX;
    ErrCode ret = EdmDataAbilityUtils::UpdateSettingsData(baseUri, QUICK_TOGGLE_LIST_KEY, jsonStr);
    if (FAILED(ret)) {
        EDMLOGE("ControlPanelQuickToggleListPlugin UpdateSettingsData failed ret=%{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
