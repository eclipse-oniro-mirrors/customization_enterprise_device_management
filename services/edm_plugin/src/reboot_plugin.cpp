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
#include "power_mgr_client.h"
#include "reboot_plugin.h"

#include "edm_ipc_interface_code.h"
#include "int_serializer.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(RebootPlugin::GetPlugin());

void RebootPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<RebootPlugin, int32_t>> ptr)
{
    EDMLOGI("RebootPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::REBOOT, "reboot", "ohos.permission.ENTERPRISE_REBOOT",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&RebootPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode RebootPlugin::OnSetPolicy()
{
    auto& powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
    PowerMgr::PowerErrors ret = powerMgrClient.RebootDevice("edm_Reboot");
    if (ret != PowerMgr::PowerErrors::ERR_OK) {
        EDMLOGE("RebootPlugin:OnSetPolicy send request fail. %{public}d", int32_t(ret));
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
