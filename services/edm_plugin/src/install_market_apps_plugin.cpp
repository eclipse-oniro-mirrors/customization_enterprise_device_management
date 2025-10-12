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

#include "install_market_apps_plugin.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "install_market_apps_serializer.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(InstallMarketAppsPlugin::GetPlugin());

void InstallMarketAppsPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<InstallMarketAppsPlugin,
    InstallMarketAppsInfo>> ptr)
{
    EDMLOGI("InstallMarketAppsPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::INSTALL_MARKET_APPS, "INSTALL_MARKET_APPS",
        EdmPermission::PERMISSION_ENTERPRISE_INSTALL_BUNDLE, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(InstallMarketAppsSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&InstallMarketAppsPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode InstallMarketAppsPlugin::OnSetPolicy(InstallMarketAppsInfo &info)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode InstallMarketAppsPlugin::OnGetPolicy(std::string &value, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    reply.WriteInt32(EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS
