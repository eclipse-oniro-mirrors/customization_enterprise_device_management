/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "notify_upgrade_packages_plugin.h"

#include "edm_ipc_interface_code.h"
#include "plugin_manager.h"
#include "upgrade_package_info_serializer.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(NotifyUpgradePackagesPlugin::GetPlugin());

void NotifyUpgradePackagesPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<NotifyUpgradePackagesPlugin,
    UpgradePackageInfo>> ptr)
{
    EDMLOGI("NotifyUpgradePackagesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES, "notify_upgrade_packages",
        "ohos.permission.ENTERPRISE_MANAGE_SYSTEM", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(UpgradePackageInfoSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&NotifyUpgradePackagesPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode NotifyUpgradePackagesPlugin::OnSetPolicy(UpgradePackageInfo &policy)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode NotifyUpgradePackagesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS
