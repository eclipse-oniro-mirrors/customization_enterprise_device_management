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

#include "set_key_code_plugin.h"

#include <algorithm>
#include <system_ability_definition.h>

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "element_name.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "func_code_utils.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<SetKeyCodePlugin>());

SetKeyCodePlugin::SetKeyCodePlugin()
{
    policyCode_ = EdmInterfaceCode::SET_KEY_CODE_POLICYS;
    policyName_ = PolicyName::POLICY_SET_KEY_CODE;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode SetKeyCodePlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode SetKeyCodePlugin::OnSetPolicy(std::vector<KeyCustomization> &keyCustomizations,
    std::vector<KeyCustomization> &currentData, std::vector<KeyCustomization> &mergeData)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode SetKeyCodePlugin::SetOtherModulePolicy(std::vector<KeyCustomization> &keyCustomization)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode SetKeyCodePlugin::OnRemovePolicy(std::vector<int> &keyCodes,
    std::vector<KeyCustomization> &currentData, std::vector<KeyCustomization> &mergeData)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode SetKeyCodePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode SetKeyCodePlugin::OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
    const std::string &mergeJsonData, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

void SetKeyCodePlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("SetKeyCodePlugin::OnOtherServiceStart...");
}

} // namespace EDM
} // namespace OHOS