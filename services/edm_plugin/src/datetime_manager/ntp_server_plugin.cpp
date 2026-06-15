/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "ntp_server_plugin.h"

#include "parameters.h"

#include "edm_ipc_interface_code.h"
#include "edm_json_builder.h"
#include "iextra_policy_notification.h"
#include "ipolicy_manager.h"
#include "iplugin_manager.h"
#include "override_interface_name.h"

namespace OHOS {
namespace EDM {
const std::string KEY_NTP_SERVER = "persist.time.ntpserver_specific";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<NTPServerPlugin>());

NTPServerPlugin::NTPServerPlugin()
{
    policyCode_ = EdmInterfaceCode::NTP_SERVER;
    policyName_ = PolicyName::POLICY_NTP_SERVER;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    needSave_ = true;
}

ErrCode NTPServerPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    std::string handleData = data.ReadString();
    EDMLOGI("NTPServerPlugin OnHandlePolicy");
    if (system::SetParameter(KEY_NTP_SERVER, handleData)) {
        std::string params = EdmJsonBuilder()
            .Add("server", handleData)
            .Build();
        IExtraPolicyNotification::GetInstance()->NotifyPolicyChanged(
            OverrideInterfaceName::SystemManager::SET_NTP_SERVER, params);
        return ERR_OK;
    }
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}
} // namespace EDM
} // namespace OHOS
