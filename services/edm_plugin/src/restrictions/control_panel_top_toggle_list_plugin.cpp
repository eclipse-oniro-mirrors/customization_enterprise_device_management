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

#include "control_panel_top_toggle_list_plugin.h"

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
const std::string TOP_TOGGLE_LIST_KEY = "control_panel_top_toggle_list";
const std::string SETTINGS_DATA_USER_URI_PREFIX =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_";
const std::string SETTINGS_DATA_URI_SUFFIX = "?Proxy=true";
constexpr uint32_t TOGGLE_LIST_MAX_SIZE = 1000;
}

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    ControlPanelTopToggleListPlugin::GetPlugin());

void ControlPanelTopToggleListPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<ControlPanelTopToggleListPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("ControlPanelTopToggleListPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::CONTROL_PANEL_TOP_TOGGLE_LIST,
        PolicyName::POLICY_CONTROL_PANEL_TOP_TOGGLE_LIST,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ControlPanelTopToggleListPlugin::OnBasicSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&ControlPanelTopToggleListPlugin::OnBasicRemovePolicy,
        FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&ControlPanelTopToggleListPlugin::OnBasicAdminRemove);
    maxListSize_ = TOGGLE_LIST_MAX_SIZE;
    overMaxReturnErrCode_ = EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
}

ErrCode ControlPanelTopToggleListPlugin::OnBasicSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    ErrCode ret = BasicArrayStringPlugin::OnBasicSetPolicy(data, currentData, mergeData, userId);
    if (FAILED(ret)) {
        return ret;
    }
    return WriteMergeToSettingsData(mergeData, userId);
}

ErrCode ControlPanelTopToggleListPlugin::OnBasicRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    ErrCode ret = BasicArrayStringPlugin::OnBasicRemovePolicy(data, currentData, mergeData, userId);
    if (FAILED(ret)) {
        return ret;
    }
    return WriteMergeToSettingsData(mergeData, userId);
}

ErrCode ControlPanelTopToggleListPlugin::OnBasicAdminRemove(const std::string &adminName,
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

ErrCode ControlPanelTopToggleListPlugin::WriteMergeToSettingsData(
    const std::vector<std::string> &mergeData, int32_t userId)
{
    EDMLOGI("ControlPanelTopToggleListPlugin WriteMergeToSettingsData userId=%{public}d size=%{public}zu",
        userId, mergeData.size());
    std::string jsonStr;
    if (!ArrayStringSerializer::GetInstance()->Serialize(mergeData, jsonStr)) {
        EDMLOGE("ControlPanelTopToggleListPlugin Serialize failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    std::string baseUri = SETTINGS_DATA_USER_URI_PREFIX + std::to_string(userId) + SETTINGS_DATA_URI_SUFFIX;
    ErrCode ret = EdmDataAbilityUtils::UpdateSettingsData(baseUri, TOP_TOGGLE_LIST_KEY, jsonStr);
    if (FAILED(ret)) {
        EDMLOGE("ControlPanelTopToggleListPlugin UpdateSettingsData failed ret=%{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
