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

#include "basic_bool_plugin.h"

#include <algorithm>

#include "parameters.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "ipolicy_manager.h"

namespace OHOS {
namespace EDM {
ErrCode BasicBoolPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    bool handelData = data.ReadBool();
    bool currentData = policyData.policyData == EdmConstants::CONST_TRUE;
    bool mergeData = policyData.mergePolicyData == EdmConstants::CONST_TRUE;
    ErrCode result = OnSetPolicy(handelData, currentData, mergeData, userId);
    if (result != ERR_OK) {
        return result;
    }
    std::string afterHandle = currentData ? EdmConstants::CONST_TRUE : EdmConstants::CONST_FALSE;
    std::string afterMerge = mergeData ? EdmConstants::CONST_TRUE : EdmConstants::CONST_FALSE;
    policyData.isChanged = (policyData.policyData != afterHandle);
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
    currentPolicyData_ = currentData;
    return ERR_OK;
}

ErrCode BasicBoolPlugin::OnAdminRemove(const std::string &adminName, const std::string &policyData,
    const std::string &mergeData, int32_t userId)
{
    bool policy = policyData == EdmConstants::CONST_TRUE;
    bool merge = mergeData == EdmConstants::CONST_TRUE;
    return OnAdminRemove(adminName, policy, merge, userId);
}

ErrCode BasicBoolPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    bool ret = policyData == EdmConstants::CONST_TRUE;
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(ret);
    return ERR_OK;
}

ErrCode BasicBoolPlugin::GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
    std::string &othersMergePolicyData)
{
    std::unordered_map<std::string, std::string> adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues, userId);
    EDMLOGD("IPluginTemplate::GetOthersMergePolicyData %{public}s value size %{public}d.", GetPolicyName().c_str(),
        (uint32_t)adminValues.size());

    auto entry = adminValues.find(adminName);
    if (entry != adminValues.end()) {
        adminValues.erase(entry);
    }
    if (adminValues.empty()) {
        return ERR_OK;
    }
    for (const auto &item : adminValues) {
        if (item.second == EdmConstants::CONST_TRUE) {
            othersMergePolicyData = EdmConstants::CONST_TRUE;
            break;
        }
    }
    return ERR_OK;
}

ErrCode BasicBoolPlugin::OnSetPolicy(bool &data, bool &currentData, bool &mergePolicy, int32_t userId)
{
    EDMLOGE("BasicBoolPlugin %{public}d, %{public}d, %{public}d.", data, currentData, mergePolicy);
    if (mergePolicy) {
        currentData = data;
        return ERR_OK;
    }
    ErrCode ret = ERR_OK;
    if (data) {
        ret = CheckConflictPolicy(userId);
        if (FAILED(ret)) {
            return ret;
        }
    }
    ret = SetOtherModulePolicy(data, userId);
    if (FAILED(ret)) {
        return ret;
    }
    if (!persistParam_.empty() && !system::SetParameter(persistParam_, data ? EdmConstants::CONST_TRUE :
        EdmConstants::CONST_FALSE)) {
        EDMLOGE("BasicBoolPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergePolicy = data;
    return ERR_OK;
}

ErrCode BasicBoolPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    return ERR_OK;
}

ErrCode BasicBoolPlugin::OnAdminRemove(const std::string &adminName, bool &data, bool &mergeData, int32_t userId)
{
    EDMLOGI("BasicBoolPlugin OnAdminRemove adminName : %{public}s, data : %{public}d", adminName.c_str(), data);
    if (!mergeData && data) {
        ErrCode ret = SetOtherModulePolicy(false, userId);
        if (FAILED(ret)) {
            return ret;
        }
        if (!persistParam_.empty() && !system::SetParameter(persistParam_, EdmConstants::CONST_FALSE)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode BasicBoolPlugin::CheckConflictPolicy(int32_t userId)
{
    return ERR_OK;
}

void BasicBoolPlugin::OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName,
    bool isGlobalChanged, int32_t userId)
{
    OnHandlePolicyDone(currentPolicyData_, isGlobalChanged, userId);
}
 
void BasicBoolPlugin::OnAdminRemoveDone(const std::string &adminName,
    const std::string &currentJsonData, int32_t userId)
{
    OnAdminRemoveDone(userId);
}

void BasicBoolPlugin::OnHandlePolicyDone(bool data, bool isGlobalChanged, int32_t userId) {}
 
void BasicBoolPlugin::OnAdminRemoveDone(int32_t userId) {}
} // namespace EDM
} // namespace OHOS
