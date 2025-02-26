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
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "pasteboard_client.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(ClipboardPolicyPlugin::GetPlugin());
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
    std::map<int32_t, ClipboardPolicy> &currentData, std::map<int32_t, ClipboardPolicy> &mergeData, int32_t userId)
{
    EDMLOGI("ClipboardPolicyPlugin OnSetPolicy.");
    if (data.empty()) {
        EDMLOGD("ClipboardPolicyPlugin data is empty.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto it = data.begin();
    std::map<int32_t, ClipboardPolicy> afterHandle = currentData;
    if (it->second == ClipboardPolicy::DEFAULT) {
        afterHandle.erase(it->first);
    } else {
        afterHandle[it->first] = it->second;
    }
    std::map<int32_t, ClipboardPolicy> afterMerge = mergeData;
    for (auto policy : afterHandle) {
        if (afterMerge.find(policy.first) == afterMerge.end() ||
            static_cast<int32_t>(policy.second) < static_cast<int32_t>(afterMerge[policy.first])) {
            afterMerge[policy.first] = policy.second;
        }
    }
    if (afterMerge.size() > MAX_PASTEBOARD_POLICY_NUM) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (mergeData.find(it->first) != mergeData.end()) {
        data[it->first] = afterMerge[it->first];
    }
    EDMLOGD("ClipboardPolicyPlugin HandlePasteboardPolicy.%{public}d, %{public}d", it->first,
        static_cast<int32_t>(it->second));
    if (FAILED(HandlePasteboardPolicy(data))) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode ClipboardPolicyPlugin::OnAdminRemove(const std::string &adminName,
    std::map<int32_t, ClipboardPolicy> &data, std::map<int32_t, ClipboardPolicy> &mergeData, int32_t userId)
{
    EDMLOGI("ClipboardPolicyPlugin OnAdminRemove.");
    for (auto &iter : data) {
        if (mergeData.find(iter.first) != mergeData.end()) {
            data[iter.first] = mergeData[iter.first];
        } else {
            data[iter.first] = ClipboardPolicy::DEFAULT;
        }
        EDMLOGD("ClipboardPolicyPlugin HandlePasteboardPolicy.%{public}d, %{public}d", iter.first,
            static_cast<int32_t>(data[iter.first]));
    }
    return HandlePasteboardPolicy(data);
}

ErrCode ClipboardPolicyPlugin::HandlePasteboardPolicy(std::map<int32_t, ClipboardPolicy> &data)
{
    EDMLOGI("ClipboardUtils handlePasteboardPolicy.");
    auto pasteboardClient = MiscServices::PasteboardClient::GetInstance();
    if (pasteboardClient == nullptr) {
        EDMLOGE("HandlePasteboardPolicy PasteboardClient null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::map<uint32_t, MiscServices::ShareOption> setMap;
    std::vector<uint32_t> removeVector;
    for (const auto &item : data) {
        switch (item.second) {
            case ClipboardPolicy::DEFAULT:
                removeVector.emplace_back(item.first);
                break;
            case ClipboardPolicy::IN_APP:
                setMap.insert(std::make_pair(item.first, MiscServices::ShareOption::InApp));
                break;
            case ClipboardPolicy::LOCAL_DEVICE:
                setMap.insert(std::make_pair(item.first, MiscServices::ShareOption::LocalDevice));
                break;
            case ClipboardPolicy::CROSS_DEVICE:
                setMap.insert(std::make_pair(item.first, MiscServices::ShareOption::CrossDevice));
                break;
            default:
                break;
        }
    }
    ErrCode setRet = ERR_OK;
    ErrCode rmRet = ERR_OK;
    if (!setMap.empty()) {
        setRet = pasteboardClient->SetGlobalShareOption(setMap);
    }
    if (!removeVector.empty()) {
        rmRet = pasteboardClient->RemoveGlobalShareOption(removeVector);
    }
    if (setRet != ERR_OK || rmRet != ERR_OK) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS