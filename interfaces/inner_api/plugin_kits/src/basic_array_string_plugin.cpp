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

#include "basic_array_string_plugin.h"

#include "array_string_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
ErrCode BasicArrayStringPlugin::OnBasicSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
    std::vector<std::string> &mergeData, int32_t userId)
{
    if (data.empty()) {
        EDMLOGW("BasicArrayStringPlugin OnSetPolicy data is empty.");
        return ERR_OK;
    }
    if (data.size() > maxListSize_) {
        EDMLOGE("BasicArrayStringPlugin OnSetPolicy input data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<std::string> needAddData =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(currentData, data);
    std::vector<std::string> needAddMergeData =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(mergeData, needAddData);
    std::vector<std::string> afterHandle =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(currentData, needAddData);
    std::vector<std::string> afterMerge =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    if (afterMerge.size() > maxListSize_) {
        EDMLOGE("BasicArrayStringPlugin OnSetPolicy merge data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    std::vector<std::string> failedData;
    if (!needAddMergeData.empty()) {
        ErrCode ret = SetOtherModulePolicy(needAddMergeData, userId, failedData);
        if (FAILED(ret)) {
            return ret;
        }
    }
    if (failedData.empty()) {
        currentData = afterHandle;
        mergeData = afterMerge;
    } else {
        currentData = ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(failedData, afterHandle);
        mergeData = ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(failedData, afterMerge);
    }
    return ERR_OK;
}

ErrCode BasicArrayStringPlugin::BasicGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::vector<std::string> policies;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData, policies);
    reply.WriteInt32(ERR_OK);
    reply.WriteStringVector(policies);
    return ERR_OK;
}

ErrCode BasicArrayStringPlugin::OnBasicRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId)
{
    if (data.empty()) {
        EDMLOGW("BasicArrayStringPlugin OnRemovePolicy data is empty.");
        return ERR_OK;
    }
    if (data.size() > maxListSize_) {
        EDMLOGE("BasicArrayStringPlugin OnRemovePolicy input data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<std::string> needRemovePolicy =
        ArrayStringSerializer::GetInstance()->SetIntersectionPolicyData(data, currentData);
    std::vector<std::string> needRemoveMergePolicy =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(mergeData, needRemovePolicy);

    std::vector<std::string> failedData;
    if (!needRemoveMergePolicy.empty()) {
        ErrCode ret = RemoveOtherModulePolicy(needRemoveMergePolicy, userId, failedData);
        if (FAILED(ret)) {
            return ret;
        }
    }
    if (failedData.empty()) {
        currentData = ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(needRemovePolicy, currentData);
    } else {
        auto removeData = ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(failedData, needRemovePolicy);
        currentData = ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(removeData, currentData);
    }
    mergeData = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(mergeData, currentData);
    return ERR_OK;
}

ErrCode BasicArrayStringPlugin::OnBasicAdminRemove(const std::string &adminName, std::vector<std::string> &data,
    std::vector<std::string> &mergeData, int32_t userId)
{
    EDMLOGI("BasicArrayStringPlugin OnAdminRemove adminName : %{public}s userId : %{public}d",
        adminName.c_str(), userId);

    std::vector<std::string> needRemoveMergePolicy =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(mergeData, data);

    std::vector<std::string> failedData;
    return RemoveOtherModulePolicy(needRemoveMergePolicy, userId, failedData);
}

ErrCode BasicArrayStringPlugin::SetOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
    std::vector<std::string> &failedData)
{
    return ERR_OK;
}

ErrCode BasicArrayStringPlugin::RemoveOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
    std::vector<std::string> &failedData)
{
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
