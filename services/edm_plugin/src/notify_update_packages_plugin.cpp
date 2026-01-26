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

#include "notify_update_packages_plugin.h"

#include "securec.h"

#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "upgrade_package_info_serializer.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(NotifyUpdatePackagesPlugin::GetPlugin());

void NotifyUpdatePackagesPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<NotifyUpdatePackagesPlugin,
    UpgradePackageInfo>> ptr)
{
    EDMLOGI("NotifyUpdatePackagesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES, PolicyName::POLICY_NOTIFY_UPGRADE_PACKAGES,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(UpgradePackageInfoSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&NotifyUpdatePackagesPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode NotifyUpdatePackagesPlugin::OnSetPolicy(UpgradePackageInfo &policy)
{
    UpdatePolicyUtils::ClosePackagesFileHandle(policy.packages);
    if (policy.authInfoSize > EdmConstants::AUTH_INFO_MAX_SIZE) {
        EDMLOGE("NotifyUpdatePackagesPlugin::OnSetPolicy authInfoSize error.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (memset_s(policy.authInfo, policy.authInfoSize, 0, policy.authInfoSize) != EOK) {
        EDMLOGE("NotifyUpdatePackagesPlugin::OnSetPolicy memset_s fail.");
    }
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode NotifyUpdatePackagesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS
