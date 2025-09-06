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
#include "edm_bundle_manager_impl.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "pasteboard_client.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(ClipboardPolicyPlugin::GetPlugin());
const int32_t MAX_PASTEBOARD_POLICY_NUM = 100;

void ClipboardPolicyPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<ClipboardPolicyPlugin, std::map<int32_t, ClipboardInfo>>> ptr)
{
    EDMLOGI("ClipboardPolicyPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::CLIPBOARD_POLICY,
        PolicyName::POLICY_CLIPBOARD_POLICY, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ClipboardSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ClipboardPolicyPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&ClipboardPolicyPlugin::OnAdminRemove);
    ptr->SetOtherServiceStartListener(&ClipboardPolicyPlugin::OnOtherServiceStart);
}

ErrCode ClipboardPolicyPlugin::OnSetPolicy(std::map<int32_t, ClipboardInfo> &data,
    std::map<int32_t, ClipboardInfo> &currentData, std::map<int32_t, ClipboardInfo> &mergeData, int32_t userId)
{
    EDMLOGI("ClipboardPolicyPlugin OnSetPolicy.");
    if (data.empty()) {
        EDMLOGD("ClipboardPolicyPlugin data is empty.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::map<int32_t, ClipboardInfo> afterHandle = currentData;
    auto it = data.begin();
    ErrCode ret;
    if (it->second.policy == ClipboardPolicy::UNKNOWN) {
        EDMLOGE("OnSetPolicy ClipboardPolicy is UNKNOWN.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (it->second.policy == ClipboardPolicy::DEFAULT) {
        ret = DeleteHandle(data, afterHandle);
    } else {
        ret = UpdateHandle(data, afterHandle);
    }
    if (ret != ERR_OK) {
        EDMLOGE("OnSetPolicy ClipboardPolicy PARAM_ERROR.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    it = data.begin();
    std::map<int32_t, ClipboardInfo> afterMerge = mergeData;
    for (const auto& pair : afterHandle) {
        if (afterMerge.find(pair.first) == afterMerge.end() ||
            static_cast<int32_t>(pair.second.policy) < static_cast<int32_t>(afterMerge[pair.first].policy)) {
            afterMerge[pair.first] = pair.second;
        }
    }
    if (afterMerge.size() > MAX_PASTEBOARD_POLICY_NUM) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (mergeData.find(it->first) != mergeData.end()) {
        data[it->first] = afterMerge[it->first];
    }
    if (FAILED(HandlePasteboardPolicy(data))) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode ClipboardPolicyPlugin::DeleteHandle(std::map<int32_t, ClipboardInfo> &data,
    std::map<int32_t, ClipboardInfo> &afterHandle)
{
    auto it = data.begin();
    ClipboardInfo info = it->second;
    int32_t tokenId = it->first;
    if (it->first == 0) {
        for (const auto& pair: afterHandle) {
            if (pair.second.userId == (it->second).userId && pair.second.bundleName == (it->second).bundleName) {
                tokenId = pair.first;
            }
        }
        if (tokenId == 0) {
            auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
            tokenId = bundleMgr->GetTokenId((it->second).bundleName, (it->second).userId);
        }
        data.erase(it->first);
        data.insert(std::make_pair(tokenId, info));
    }
    afterHandle.erase(tokenId);
    return ERR_OK;
}

ErrCode ClipboardPolicyPlugin::UpdateHandle(std::map<int32_t, ClipboardInfo> &data, std::map<int32_t,
    ClipboardInfo> &afterHandle)
{
    auto it = data.begin();
    ClipboardInfo info = it->second;
    if (it->first == 0) {
        if ((it->second).bundleName.empty() || (it->second).userId == -1) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
        int32_t tokenId = bundleMgr->GetTokenId((it->second).bundleName, (it->second).userId);
        if (tokenId == 0) {
            return EdmReturnErrCode::PARAM_ERROR;
        }
        info = it->second;
        data.erase(it);
        data.insert(std::make_pair(tokenId, info));
        it = data.begin();
    } else {
        auto iter = afterHandle.find(it->first);
        if (iter != afterHandle.end()) {
            info = {(it->second).policy, (iter->second).userId, (iter->second).bundleName};
        }
    }
    afterHandle[it->first] = info;
    return ERR_OK;
}

ErrCode ClipboardPolicyPlugin::OnAdminRemove(const std::string &adminName,
    std::map<int32_t, ClipboardInfo> &data, std::map<int32_t, ClipboardInfo> &mergeData, int32_t userId)
{
    EDMLOGI("ClipboardPolicyPlugin OnAdminRemove.");
    for (auto &iter : data) {
        if (mergeData.find(iter.first) != mergeData.end()) {
            data[iter.first] = mergeData[iter.first];
        } else {
            ClipboardInfo info = {ClipboardPolicy::DEFAULT, -1, ""};
            data[iter.first] = info;
        }
        EDMLOGI("ClipboardPolicyPlugin HandlePasteboardPolicy.%{public}d, %{public}d", iter.first,
            static_cast<int32_t>(data[iter.first].policy));
    }
    return HandlePasteboardPolicy(data);
}

ErrCode ClipboardPolicyPlugin::HandlePasteboardPolicy(std::map<int32_t, ClipboardInfo> &data)
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
        switch (item.second.policy) {
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
    pasteboardClient->DetachPasteboardClient();
    if (setRet != ERR_OK || rmRet != ERR_OK) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

void ClipboardPolicyPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    std::string policyData;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_CLIPBOARD_POLICY,
        policyData, EdmConstants::DEFAULT_USER_ID);
    auto clipboardSerializer_ = ClipboardSerializer::GetInstance();
    std::map<int32_t, ClipboardInfo> policyMap;
    clipboardSerializer_->Deserialize(policyData, policyMap);
    HandlePasteboardPolicy(policyMap);
}
} // namespace EDM
} // namespace OHOS