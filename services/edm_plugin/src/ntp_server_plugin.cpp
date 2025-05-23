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

#include "edm_ipc_interface_code.h"
#include "string_serializer.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const std::string KEY_NTP_SERVER = "persist.time.ntpserver_specific";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(NTPServerPlugin::GetPlugin());

void NTPServerPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<NTPServerPlugin, std::string>> ptr)
{
    EDMLOGI("NTPServerPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::NTP_SERVER, PolicyName::POLICY_NTP_SERVER,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM, IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ptr->SetSerializer(StringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&NTPServerPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode NTPServerPlugin::OnSetPolicy(std::string &value)
{
    EDMLOGI("NTPServerPlugin OnSetPolicy");
    return system::SetParameter(KEY_NTP_SERVER, value) ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}
} // namespace EDM
} // namespace OHOS
