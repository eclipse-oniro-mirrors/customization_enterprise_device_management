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

#include "clipboard_policy_plugin.h"

#include "cJSON.h"
#include "clipboard_utils.h"
#include "edm_ipc_interface_code.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(ClipboardPolicyPlugin::GetPlugin());
const int32_t MAX_PASTEBOARD_POLICY_NUM = 100;

void ClipboardPolicyPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<ClipboardPolicyPlugin, std::map<int32_t, ClipboardPolicy>>> ptr)
{
    EDMLOGI("ClipboardPolicyPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::CLIPBOARD_POLICY,
        "clipboard_policy", "ohos.permission.ENTERPRISE_MANAGE_SECURITY",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ClipboardSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ClipboardPolicyPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&ClipboardPolicyPlugin::OnAdminRemove);
}

ErrCode ClipboardPolicyPlugin::OnSetPolicy(std::map<int32_t, ClipboardPolicy> &data,
    std::map<int32_t, ClipboardPolicy> &currentData, int32_t userId)
{
    EDMLOGI("ClipboardPolicyPlugin OnSetPolicy.");
    if (data.empty()) {
        EDMLOGD("ClipboardPolicyPlugin data is empty.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto it = data.begin();
    if (it->second == ClipboardPolicy::DEFAULT) {
        currentData.erase(it->first);
    } else {
        currentData[it->first] = it->second;
    }
    if (currentData.size() > MAX_PASTEBOARD_POLICY_NUM) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    return ClipboardUtils::HandlePasteboardPolicy(currentData);
}

ErrCode ClipboardPolicyPlugin::OnGetPolicy(std::string &policyData,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    EDMLOGI("ClipboardPolicyPlugin OnGetPolicy.");
    int32_t tokenId = data.ReadInt32();
    std::string policy = policyData;
    if (tokenId != 0) {
        std::map<int32_t, ClipboardPolicy> policyMap;
        if (!pluginInstance_->serializer_->Deserialize(policyData, policyMap)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        std::map<int32_t, ClipboardPolicy> resultMap;
        resultMap[tokenId] = policyMap[tokenId];
        pluginInstance_->serializer_->Serialize(resultMap, policy);
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(policy);
    return ERR_OK;
}

ErrCode ClipboardPolicyPlugin::OnAdminRemove(const std::string &adminName,
    std::map<int32_t, ClipboardPolicy> &data, int32_t userId)
{
    EDMLOGI("ClipboardPolicyPlugin OnAdminRemove.");
    return ClipboardUtils::RemoveAllPasteboardPolicy(data);
}
} // namespace EDM
} // namespace OHOS