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

#include "control_panel_restricted_plugin.h"

#include "parameters.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iextra_policy_notification.h"
#include "iplugin_manager.h"
#include "override_interface_name.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<ControlPanelRestrictedPlugin>());

ControlPanelRestrictedPlugin::ControlPanelRestrictedPlugin()
{
    EDMLOGI("ControlPanelRestrictedPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::CONTROL_PANEL_RESTRICTED;
    policyName_ = PolicyName::POLICY_CONTROL_PANEL_RESTRICTED;
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    persistParam_ = EdmConstants::PARAM_EDM_CONTROL_PANEL_RESTRICTED;
}

ErrCode ControlPanelRestrictedPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    bool newValue = data.ReadBool();
    bool oldAdminValue = policyData.policyData == EdmConstants::CONST_TRUE;
    bool oldGlobalValue = system::GetParameter(persistParam_, EdmConstants::CONST_FALSE) ==
        EdmConstants::CONST_TRUE;
    if (!system::SetParameter(persistParam_,
        newValue ? EdmConstants::CONST_TRUE : EdmConstants::CONST_FALSE)) {
        EDMLOGE("ControlPanelRestrictedPlugin set persist param failed.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    // Last-write-wins: the latest admin value is the effective device value.
    policyData.policyData = newValue ? EdmConstants::CONST_TRUE : "";
    policyData.mergePolicyData = newValue ? EdmConstants::CONST_TRUE : "";
    bool globalChanged = (oldGlobalValue != newValue);
    policyData.isChanged = (oldAdminValue != newValue) || globalChanged;
    if (globalChanged) {
        IExtraPolicyNotification::GetInstance()->NotifyPolicyChanged(
            OverrideInterfaceName::Restrictions::SET_CONTROL_PANEL_RESTRICTED, "");
    }
    // Notify the control panel on every successful set, even if the value is unchanged.
    IExtraPolicyNotification::GetInstance()->NotifyControlPanelRestrictedChanged();
    return ERR_OK;
}

ErrCode ControlPanelRestrictedPlugin::GetRestrictedValue(bool &restricted)
{
    std::string value = system::GetParameter(persistParam_, EdmConstants::CONST_FALSE);
    if (value == EdmConstants::CONST_TRUE) {
        restricted = true;
        return ERR_OK;
    }
    if (value == EdmConstants::CONST_FALSE) {
        restricted = false;
        return ERR_OK;
    }
    EDMLOGE("ControlPanelRestrictedPlugin get persist param invalid: %{public}s", value.c_str());
    return EdmReturnErrCode::EXECUTE_TIME_OUT;
}

ErrCode ControlPanelRestrictedPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    // Device-level flag: always return the effective persist value so that an
    // admin who has never set this policy also sees the current device state.
    bool restricted = false;
    ErrCode ret = GetRestrictedValue(restricted);
    if (FAILED(ret)) {
        return ret;
    }
    // Build the whole success reply in a temporary parcel first. If writing the
    // bool fails, leave reply empty so that the stub's error code becomes the
    // first int32 and the proxy can return 9200016 instead of reading it as true.
    MessageParcel temp;
    if (!temp.WriteInt32(ERR_OK)) {
        EDMLOGE("ControlPanelRestrictedPlugin write reply status failed.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    if (!temp.WriteBool(restricted)) {
        EDMLOGE("ControlPanelRestrictedPlugin write reply bool failed.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    if (!reply.Append(temp)) {
        EDMLOGE("ControlPanelRestrictedPlugin append reply failed.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}

ErrCode ControlPanelRestrictedPlugin::OnAdminRemove(const std::string &adminName, const std::string &policyData,
    const std::string &mergeData, int32_t userId)
{
    // Removal can only clear the flag, never re-enable it.
    bool oldGlobalValue = system::GetParameter(persistParam_, EdmConstants::CONST_FALSE) ==
        EdmConstants::CONST_TRUE;
    bool remainingHasTrue = mergeData == EdmConstants::CONST_TRUE;
    bool newGlobalValue = oldGlobalValue && remainingHasTrue;
    if (newGlobalValue) {
        // newGlobalValue can only be true when oldGlobalValue is true and a
        // remaining admin still holds true, so the effective value is unchanged.
        return ERR_OK;
    }
    // Always clear the flag when the recomputed value is false. If reading the
    // old value failed, it is treated as false; writing false here prevents a
    // stale "true" from being left behind and never re-enables the flag.
    if (!system::SetParameter(persistParam_, EdmConstants::CONST_FALSE)) {
        EDMLOGE("ControlPanelRestrictedPlugin reset persist param failed.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    IExtraPolicyNotification::GetInstance()->NotifyPolicyChanged(
        OverrideInterfaceName::Restrictions::SET_CONTROL_PANEL_RESTRICTED, "");
    IExtraPolicyNotification::GetInstance()->NotifyControlPanelRestrictedChanged();
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS