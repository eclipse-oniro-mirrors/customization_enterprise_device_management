/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <shutdown_plugin.h>
#include "power_mgr_client.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<ShutdownPlugin>());

ShutdownPlugin::ShutdownPlugin()
{
    EDMLOGI("ShutdownPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::SHUTDOWN;
    policyName_ = PolicyName::POLICY_SHUTDOWN_DEVICE;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_REBOOT,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode ShutdownPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    auto& powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
    PowerMgr::PowerErrors ret = powerMgrClient.ShutDownDevice("edm_Shutdown");
    if (ret != PowerMgr::PowerErrors::ERR_OK) {
        EDMLOGE("ShutdownPlugin:OnSetPolicy send request fail. %{public}d", int32_t(ret));
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
