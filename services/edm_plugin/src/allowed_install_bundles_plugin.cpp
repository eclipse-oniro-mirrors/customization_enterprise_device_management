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

#include "allowed_install_bundles_plugin.h"
#include "array_string_serializer.h"
#include "policy_info.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(AllowedInstallBundlesPlugin::GetPlugin());

void AllowedInstallBundlesPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<AllowedInstallBundlesPlugin,
    std::vector<std::string>>> ptr)
{
    EDMLOGD("AllowedInstallBundlesPlugin InitPlugin...");
    std::string policyName;
    POLICY_CODE_TO_NAME(ALLOWED_INSTALL_BUNDLES, policyName);
    ptr->InitAttribute(ALLOWED_INSTALL_BUNDLES, policyName, "ohos.permission.ENTERPRISE_SET_BUNDLE_INSTALL_POLICY",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AllowedInstallBundlesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&AllowedInstallBundlesPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveDoneListener(&AllowedInstallBundlesPlugin::OnAdminRemoveDone);
    SetAppInstallControlRuleType(AppExecFwk::AppInstallControlRuleType::ALLOWED_INSTALL);
}

ErrCode AllowedInstallBundlesPlugin::OnSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
    int32_t userId)
{
    EDMLOGI("AllowedInstallBundlesPlugin OnSetPolicy userId = %{public}d", userId);
    return BundleSetPolicy(data, currentData, userId);
}

ErrCode AllowedInstallBundlesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("AllowedInstallBundlesPlugin OnGetPolicy policyData : %{public}s, userId : %{public}d",
        policyData.c_str(), userId);
    std::vector<std::string> bundles;
    pluginInstance_->serializer_->Deserialize(policyData, bundles);
    return BundleGetPolicy(bundles, reply);
}

ErrCode AllowedInstallBundlesPlugin::OnRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, int32_t userId)
{
    EDMLOGD("AllowedInstallBundlesPlugin OnRemovePolicy userId : %{public}d", userId);
    return BundleRemovePolicy(data, currentData, userId);
}

void AllowedInstallBundlesPlugin::OnAdminRemoveDone(const std::string &adminName, std::vector<std::string> &data,
    int32_t userId)
{
    EDMLOGI("AllowedInstallBundlesPlugin OnAdminRemoveDone adminName : %{public}s userId : %{public}d",
        adminName.c_str(), userId);
    BundleAdminRemoveDone(adminName, data, userId);
}
} // namespace EDM
} // namespace OHOS
