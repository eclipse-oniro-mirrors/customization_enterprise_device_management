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

#include "hang_up_calling_plugin.h"

#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "call_manager_client.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<HangupCallingPlugin>());

HangupCallingPlugin::HangupCallingPlugin()
{
    policyCode_ = EdmInterfaceCode::HANG_UP_CALLING;
    policyName_ = PolicyName::POLICY_HANG_UP_CALLING;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode HangupCallingPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    auto callManagerClient = DelayedSingleton<Telephony::CallManagerClient>::GetInstance();
    callManagerClient->Init(TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID);
    int32_t ret = 0;
    ret = callManagerClient->HangUpCall(0);
    EDMLOGI("HangupCallingPlugin HangUpCall result = %{public}d", ret);
    ret = callManagerClient->RejectCall(0, false, u"MDM Management");
    EDMLOGI("HangupCallingPlugin RejectCall result = %{public}d", ret);
    callManagerClient->UnInit();
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
