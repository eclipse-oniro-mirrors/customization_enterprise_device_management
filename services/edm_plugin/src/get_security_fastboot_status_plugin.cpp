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

#include "get_security_fastboot_status_plugin.h"

#include "battery_utils.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "string_serializer.h"


namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(GetSecurityFastbootStatusPlugin::GetPlugin());

void GetSecurityFastbootStatusPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetSecurityFastbootStatusPlugin,
    std::string>> ptr)
{
    EDMLOGD("GetSecurityFastbootStatusPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::GET_SECURITY_FASTBOOT_STATUS, PolicyName::POLICY_GET_DEVICE_FASTBOOT_STATUS,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}

ErrCode GetSecurityFastbootStatusPlugin::OnGetPolicy(std::string &value,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    EDMLOGD("GetSecurityFastbootStatusPlugin OnGetPolicy.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS