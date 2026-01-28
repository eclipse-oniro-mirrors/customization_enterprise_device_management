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

#include "hidden_settings_menu_plugin.h"

#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "array_int_serializer.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "edm_errors.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<HiddenSettingsMenuPlugin>());

HiddenSettingsMenuPlugin::HiddenSettingsMenuPlugin()
{
    policyCode_ = EdmInterfaceCode::HIDDEN_SETTINGS_MENU;
    policyName_ = PolicyName::POLICY_HIDDEN_SETTINGS_MENU;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    maxListSize_ = EdmConstants::MENUS_TO_HIDDEN_LIST_MAX_SIZE;
    needSave_ = true;
}

ErrCode HiddenSettingsMenuPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode HiddenSettingsMenuPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode HiddenSettingsMenuPlugin::SetOtherModulePolicy(const std::vector<int32_t> &data, int32_t userId,
    std::vector<int32_t> &failedData)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode HiddenSettingsMenuPlugin::RemoveOtherModulePolicy(const std::vector<int32_t> &data, int32_t userId,
    std::vector<int32_t> &failedData)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode HiddenSettingsMenuPlugin::GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
    std::string &othersMergePolicyData)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode HiddenSettingsMenuPlugin::OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
    const std::string &mergeJsonData, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS