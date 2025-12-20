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

#include "enhance_execute_strategy.h"

#include "edm_log.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
ErrCode ReplaceExecuteStrategy::OnGetExecute(std::uint32_t funcCode, std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    auto plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    if (plugin != nullptr) {
        EDMLOGD("ReplaceExecuteStrategy::OnGetExecute plugin %{public}d execute replace strategy.", plugin->GetCode());
        auto extensionPlugin = plugin->GetExtensionPlugin();
        if (extensionPlugin != nullptr && extensionPlugin->GetPluginType() == IPlugin::PluginType::EXTENSION) {
            EDMLOGD("ReplaceExecuteStrategy::OnGetExecute extensionPlugin %{public}d start execute.",
                extensionPlugin->GetCode());
            return extensionPlugin->OnGetPolicy(policyData, data, reply, userId);
        }
        return plugin->OnGetPolicy(policyData, data, reply, userId);
    }
    EDMLOGE("ReplaceExecuteStrategy::OnGetExecute plugin %{public}d is not exist.", funcCode);
    return ERR_EDM_GET_POLICY_FAILED;
}

ErrCode ReplaceExecuteStrategy::OnSetExecute(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    auto plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    if (plugin != nullptr) {
        EDMLOGD("ReplaceExecuteStrategy::OnSetExecute plugin %{public}d execute replace strategy.", plugin->GetCode());
        auto extensionPlugin = plugin->GetExtensionPlugin();
        if (extensionPlugin != nullptr && extensionPlugin->GetPluginType() == IPlugin::PluginType::EXTENSION) {
            EDMLOGD("ReplaceExecuteStrategy::OnSetExecute extensionPlugin %{public}d start execute.",
                extensionPlugin->GetCode());
            return extensionPlugin->OnHandlePolicy(funcCode, data, reply, policyData, userId);
        }
        return plugin->OnHandlePolicy(funcCode, data, reply, policyData, userId);
    }
    EDMLOGE("ReplaceExecuteStrategy::OnSetExecute plugin %{public}d is not exist.", funcCode);
    return ERR_EDM_HANDLE_POLICY_FAILED;
}

ErrCode ReplaceExecuteStrategy::OnInitExecute(std::uint32_t interfaceCode, std::string &adminName, int32_t userId)
{
    auto plugin = PluginManager::GetInstance()->GetPluginByCode(interfaceCode);
    if (plugin == nullptr) {
        EDMLOGD("get Plugin fail %{public}d.", interfaceCode);
        return ERR_EDM_HANDLE_POLICY_FAILED;
    }
    auto extensionPlugin = plugin->GetExtensionPlugin();
    if (extensionPlugin != nullptr && extensionPlugin->GetPluginType() == IPlugin::PluginType::EXTENSION) {
        EDMLOGD("ReplaceExecuteStrategy::OnSetExecute extensionPlugin %{public}d start execute.",
            extensionPlugin->GetCode());
        extensionPlugin->OnOtherServiceStartForAdmin(adminName, userId);
        return ERR_OK;
    }
    plugin->OnOtherServiceStartForAdmin(adminName, userId);
    EDMLOGE("ReplaceExecuteStrategy::OnInitExecute plugin %{public}d is not exist.", interfaceCode);
    return ERR_EDM_HANDLE_POLICY_FAILED;
}

} // namespace EDM
} // namespace OHOS
