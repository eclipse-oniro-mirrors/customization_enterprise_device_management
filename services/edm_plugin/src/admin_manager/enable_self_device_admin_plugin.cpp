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

#include "enable_self_device_admin_plugin.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "enable_self_device_admin_param_serializer.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(EnableSelfDeviceAdminPlugin::GetPlugin());

void EnableSelfDeviceAdminPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<EnableSelfDeviceAdminPlugin,
    EnableSelfDeviceAdminParam>> ptr)
{
    EDMLOGI("EnableSelfDeviceAdminPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ENABLE_SELF_DEVICE_ADMIN, PolicyName::POLICY_ENABLE_SELF_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_ACTIVATE_DEVICE_ADMIN, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(EnableSelfDeviceAdminParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&EnableSelfDeviceAdminPlugin::OnSetPolicy, FuncOperateType::SET);
    this->pluginInstance_->SetPluginUnloadFlag(false); // 此处是为了避免dlclose对应so出现的稳定性问题，如果dlclose无问题可以删除。
}

ErrCode EnableSelfDeviceAdminPlugin::OnSetPolicy()
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS
