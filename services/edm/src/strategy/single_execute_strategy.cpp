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

#include "single_execute_strategy.h"

#include "edm_log.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
ErrCode SingleExecuteStrategy::OnGetExecute(std::uint32_t funcCode, std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    auto plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    if (plugin != nullptr) {
        EDMLOGD("SingleExecuteStrategy::OnGetExecute plugin %{public}d execute single strategy.", plugin->GetCode());
        return plugin->OnGetPolicy(policyData, data, reply, userId);
    }
    EDMLOGE("SingleExecuteStrategy::OnGetExecute plugin %{public}d is not exist.", funcCode);
    return ERR_EDM_GET_POLICY_FAILED;
}

ErrCode SingleExecuteStrategy::OnSetExecute(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    auto plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    if (plugin != nullptr) {
        EDMLOGD("SingleExecuteStrategy::OnSetExecute plugin %{public}d execute single strategy.", plugin->GetCode());
        return plugin->OnHandlePolicy(funcCode, data, reply, policyData, userId);
    }
    EDMLOGE("SingleExecuteStrategy::OnGetExecute plugin %{public}d is not exist.", funcCode);
    return ERR_EDM_HANDLE_POLICY_FAILED;
}

ErrCode SingleExecuteStrategy::OnInitExecute(std::uint32_t interfaceCode, std::string &adminName, int32_t userId)
{
    auto plugin = PluginManager::GetInstance()->GetPluginByCode(interfaceCode);
    if (plugin == nullptr) {
        EDMLOGD("get Plugin fail %{public}d.", interfaceCode);
        return ERR_EDM_HANDLE_POLICY_FAILED;
    }
    plugin->OnOtherServiceStartForAdmin(adminName, userId);
    return ERR_EDM_HANDLE_POLICY_FAILED;
}

ErrCode SingleExecuteStrategy::OnAdminRemoveExecute(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue, int32_t userId)
{
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByPolicyName(policyName);
    if (plugin == nullptr) {
        EDMLOGW("RemoveAdminItem: Get plugin by policy failed: %{public}s\n", policyName.c_str());
        return ERR_EDM_GET_PLUGIN_MGR_FAILED;
    }
    std::string mergedPolicyData;
    plugin->GetOthersMergePolicyData(adminName, userId, mergedPolicyData);
    ErrCode ret = plugin->OnAdminRemove(adminName, policyValue, mergedPolicyData, userId);
    if (ret != ERR_OK) {
        EDMLOGW("RemoveAdminItem: OnAdminRemove failed, admin:%{public}s, value:%{public}s, res:%{public}d\n",
            adminName.c_str(), policyValue.c_str(), ret);
        return ERR_EDM_HANDLE_POLICY_FAILED;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
