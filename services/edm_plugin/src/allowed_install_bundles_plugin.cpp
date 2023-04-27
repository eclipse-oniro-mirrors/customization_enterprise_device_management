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
#include <ipc_skeleton.h>
#include <system_ability_definition.h>

#include "app_control/app_control_proxy.h"
#include "array_string_serializer.h"
#include "edm_sys_manager.h"
#include "policy_info.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(AllowedInstallBundlesPlugin::GetPlugin());

constexpr int32_t MAX_SIZE = 200;

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
}

ErrCode AllowedInstallBundlesPlugin::OnSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
    int32_t userId)
{
    EDMLOGI("AllowedInstallBundlesPlugin OnSetPolicy userId = %{public}d", userId);
    if (data.empty()) {
        EDMLOGW("AllowedInstallBundlesPlugin OnSetPolicy data is empty:");
        return ERR_OK;
    }

    std::vector<std::string> mergeData = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(data, currentData);

    if (mergeData.size() > MAX_SIZE) {
        EDMLOGE("AllowedInstallBundlesPlugin OnSetPolicy data is too large:");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    ErrCode res = GetAppControlProxy()->
        AddAppInstallControlRule(data, AppExecFwk::AppInstallControlRuleType::ALLOWED_INSTALL, userId);
    if (res != ERR_OK) {
        EDMLOGE("AllowedInstallBundlesPlugin OnSetPolicyDone Faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = mergeData;
    return ERR_OK;
}

ErrCode AllowedInstallBundlesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("AllowedInstallBundlesPlugin OnGetPolicy policyData : %{public}s, userId : %{public}d",
        policyData.c_str(), userId);
    std::vector<std::string> bundles;
    pluginInstance_->serializer_->Deserialize(policyData, bundles);
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(bundles.size());
    reply.WriteStringVector(bundles);
    return ERR_OK;
}

ErrCode AllowedInstallBundlesPlugin::OnRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, int32_t userId)
{
    EDMLOGD("AllowedInstallBundlesPlugin OnRemovePolicy userId : %{public}d:", userId);
    if (data.empty()) {
        EDMLOGW("AllowedInstallBundlesPlugin OnRemovePolicy data is empty:");
        return ERR_OK;
    }

    std::vector<std::string> mergeData = ArrayStringSerializer::GetInstance()->
        SetDifferencePolicyData(data, currentData);
    ErrCode res = GetAppControlProxy()->
        DeleteAppInstallControlRule(AppExecFwk::AppInstallControlRuleType::ALLOWED_INSTALL, data, userId);
    if (res != ERR_OK) {
        EDMLOGE("AllowedInstallBundlesPlugin DeleteAppInstallControlRule OnRemovePolicy faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = mergeData;
    return ERR_OK;
}

sptr<AppExecFwk::IAppControlMgr> AllowedInstallBundlesPlugin::GetAppControlProxy()
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    return proxy->GetAppControlProxy();
}

void AllowedInstallBundlesPlugin::OnAdminRemoveDone(const std::string &adminName, std::vector<std::string> &data,
    int32_t userId)
{
    EDMLOGI("AllowedInstallBundlesPlugin OnAdminRemoveDone adminName : %{public}s userId : %{public}d",
        adminName.c_str(), userId);
    ErrCode res = GetAppControlProxy()->
        DeleteAppInstallControlRule(AppExecFwk::AppInstallControlRuleType::ALLOWED_INSTALL, data, userId);
    EDMLOGI("AllowedInstallBundlesPlugin OnAdminRemoveDone result %{public}d:", res);
}
} // namespace EDM
} // namespace OHOS
