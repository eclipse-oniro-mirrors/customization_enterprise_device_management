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
#include "edm_json_builder.h"
#include "edm_log.h"
#include "edm_utils.h"
#include "iextra_policy_notification.h"
#include "iplugin_manager.h"
#include "override_interface_name.h"

namespace OHOS {
namespace EDM {

namespace {
const std::string QUICK_TOGGLE_LIST_KEY = "settings.control.cust_quick_toggle_data";
constexpr uint32_t TOGGLE_LIST_MAX_SIZE = 1000;
}

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    ControlPanelQuickToggleListPlugin::GetPlugin());

void ControlPanelQuickToggleListPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<ControlPanelQuickToggleListPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("ControlPanelQuickToggleListPlugin InitPlugin...");
    // needSave=false: 白名单仅存 settingsdata，不落 EDM RDB（覆盖策略，无合并/清理需求）
    ptr->InitAttribute(EdmInterfaceCode::CONTROL_PANEL_QUICK_TOGGLE_LIST,
        PolicyName::POLICY_CONTROL_PANEL_QUICK_TOGGLE_LIST,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ControlPanelQuickToggleListPlugin::OnBasicSetPolicy, FuncOperateType::SET);
    maxListSize_ = TOGGLE_LIST_MAX_SIZE;
    overMaxReturnErrCode_ = EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
}

ErrCode ControlPanelQuickToggleListPlugin::OnBasicSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    EDMLOGI("ControlPanelQuickToggleListPlugin OnBasicSetPolicy accountId=%{public}d size=%{public}zu",
        userId, data.size());
    if (data.size() > maxListSize_) {
        EDMLOGE("ControlPanelQuickToggleListPlugin input data is too large.");
        return overMaxReturnErrCode_;
    }
    // 覆盖语义：当前 admin 值与全局生效值均直接等于本次下发（空数组合法，表示该区域全部隐藏）
    currentData = data;
    mergeData = data;
    ErrCode ret = WriteToggleListToSettingsData(data, userId);
    if (FAILED(ret)) {
        return ret;
    }
    std::string params = EdmJsonBuilder().Add("accountId", userId).Build();
    IExtraPolicyNotification::GetInstance()->NotifyPolicyChanged(
        OverrideInterfaceName::DeviceSettings::SET_CONTROL_PANEL_QUICK_TOGGLE_LIST, params);
    return ERR_OK;
}

ErrCode ControlPanelQuickToggleListPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("ControlPanelQuickToggleListPlugin OnGetPolicy accountId=%{public}d", userId);
    std::string baseUri = std::string(EdmConstants::SETTINGS_DATA_SECURE_URI_PREFIX) +
        std::to_string(userId) + EdmConstants::SETTINGS_DATA_URI_SUFFIX;
    std::string toggleData;
    std::vector<std::string> result;
    ErrCode ret = EdmDataAbilityUtils::GetStringFromSettingsDataShare(baseUri, QUICK_TOGGLE_LIST_KEY, toggleData);
    if (FAILED(ret)) {
        EDMLOGE("ControlPanelQuickToggleListPlugin GetStringFromSettingsDataShare failed ret=%{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    if (!toggleData.empty()) {
        result = EdmUtils::SplitString(toggleData, ",");
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteStringVector(result);
    return ERR_OK;
}

ErrCode ControlPanelQuickToggleListPlugin::WriteToggleListToSettingsData(
    const std::vector<std::string> &toggleList, int32_t accountId)
{
    std::string toggleData = EdmUtils::JoinString(toggleList, ",");
    std::string baseUri = std::string(EdmConstants::SETTINGS_DATA_SECURE_URI_PREFIX) +
        std::to_string(accountId) + EdmConstants::SETTINGS_DATA_URI_SUFFIX;
    ErrCode ret = EdmDataAbilityUtils::UpdateSettingsData(baseUri, QUICK_TOGGLE_LIST_KEY, toggleData);
    if (FAILED(ret)) {
        EDMLOGE("ControlPanelQuickToggleListPlugin UpdateSettingsData failed ret=%{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS