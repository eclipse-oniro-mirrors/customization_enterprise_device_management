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

#include "reset_factory_plugin.h"
#include "edm_ipc_interface_code.h"
#include "update_service_kits.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(ResetFactoryPlugin::GetPlugin());

void ResetFactoryPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<ResetFactoryPlugin, std::string>> ptr)
{
    EDMLOGI("ResetFactoryPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::RESET_FACTORY, "reset_factory", "ohos.permission.ENTERPRISE_RESET_DEVICE",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ResetFactoryPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode ResetFactoryPlugin::OnSetPolicy()
{
    UpdateEngine::BusinessError businessError;
    int32_t ret = UpdateEngine::UpdateServiceKits::GetInstance().FactoryReset(businessError);
    if (FAILED(ret)) {
        EDMLOGE("ResetFactoryPlugin:OnSetPolicy send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS