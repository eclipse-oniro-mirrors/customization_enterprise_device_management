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
 
#include "set_switch_status_plugin.h"
 
#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
 
namespace OHOS {
namespace EDM {
 
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetSwitchStatusPlugin::GetPlugin());
 
void SetSwitchStatusPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetSwitchStatusPlugin, SwitchParam>> ptr)
{
    ptr->InitAttribute(EdmInterfaceCode::SET_SWITCH_STATUS, PolicyName::POLICY_SET_SWITCH_STATUS,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(SwitchParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetSwitchStatusPlugin::OnSetPolicy, FuncOperateType::SET);
}
 
ErrCode SetSwitchStatusPlugin::OnSetPolicy(SwitchParam &param)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS