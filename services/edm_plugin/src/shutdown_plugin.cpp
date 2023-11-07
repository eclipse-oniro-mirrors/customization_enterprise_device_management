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
#include "screenlock_manager.h"
#include "power_mgr_client.h"
#include "edm_ipc_interface_code.h"
#include "int_serializer.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(ShutdownPlugin::GetPlugin());

void ShutdownPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<ShutdownPlugin, int32_t>> ptr)
{
    EDMLOGD("ShutdownPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::SHUTDOWN, "shutdown_device", "ohos.permission.ENTERPRISE_RESET_DEVICE",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ShutdownPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode ShutdownPlugin::OnSetPolicy()
{
    auto& powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
    PowerMgr::PowerErrors& ret = powerMgrClient.ShutDownDevice("edm_Shutdown");
    if (ret != PowerMgr::PowerErrors::ERR_OK) {
        EDMLOGE("ShutdownPlugin:OnSetPolicy send request fail. %{public}d", int32_t(ret));
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
