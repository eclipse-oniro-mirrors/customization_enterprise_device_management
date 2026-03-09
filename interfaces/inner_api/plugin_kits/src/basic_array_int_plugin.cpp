/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "basic_array_int_plugin.h"

#include "array_int_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
ErrCode BasicArrayIntPlugin::OnBasicSetPolicy(std::vector<int32_t> &data, std::vector<int32_t> &currentData,
    std::vector<int32_t> &mergeData, int32_t userId)
{
    if (data.empty()) {
        EDMLOGW("BasicArrayIntPlugin OnSetPolicy data is empty.");
        return ERR_OK;
    }
    if (data.size() > maxListSize_) {
        EDMLOGE("BasicArrayIntPlugin OnSetPolicy input data is too large.");
        return overMaxReturnErrCode_;
    }
    std::vector<int32_t> needAddData =
        ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(currentData, data);
    std::vector<int32_t> needAddMergeData =
        ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(mergeData, needAddData);
    std::vector<int32_t> afterHandle =
        ArrayIntSerializer::GetInstance()->SetUnionPolicyData(currentData, needAddData);
    std::vector<int32_t> afterMerge =
        ArrayIntSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    if (afterMerge.size() > maxListSize_) {
        EDMLOGE("BasicArrayIntPlugin OnSetPolicy merge data is too large.");
        return overMaxReturnErrCode_;
    }
    std::vector<int32_t> failedData;
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
        currentData = ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(failedData, afterHandle);
        mergeData = ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(failedData, afterMerge);
    }
    return ERR_OK;
}

ErrCode BasicArrayIntPlugin::BasicGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::vector<int32_t> policies;
    ArrayIntSerializer::GetInstance()->Deserialize(policyData, policies);
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32Vector(policies);
    return ERR_OK;
}

ErrCode BasicArrayIntPlugin::OnBasicRemovePolicy(std::vector<int32_t> &data,
    std::vector<int32_t> &currentData, std::vector<int32_t> &mergeData, int32_t userId)
{
    if (data.empty()) {
        EDMLOGW("BasicArrayIntPlugin OnRemovePolicy data is empty.");
        return ERR_OK;
    }
    if (data.size() > maxListSize_) {
        EDMLOGE("BasicArrayIntPlugin OnRemovePolicy input data is too large.");
        return overMaxReturnErrCode_;
    }
    std::vector<int32_t> needRemovePolicy =
        ArrayIntSerializer::GetInstance()->SetIntersectionPolicyData(data, currentData);
    std::vector<int32_t> needRemoveMergePolicy =
        ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(mergeData, needRemovePolicy);

    std::vector<int32_t> failedData;
    if (!needRemoveMergePolicy.empty()) {
        ErrCode ret = RemoveOtherModulePolicy(needRemoveMergePolicy, userId, failedData);
        if (FAILED(ret)) {
            return ret;
        }
    }
    if (failedData.empty()) {
        currentData = ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(needRemovePolicy, currentData);
    } else {
        auto removeData = ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(failedData, needRemovePolicy);
        currentData = ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(removeData, currentData);
    }
    mergeData = ArrayIntSerializer::GetInstance()->SetUnionPolicyData(mergeData, currentData);
    return ERR_OK;
}

ErrCode BasicArrayIntPlugin::OnBasicAdminRemove(const std::string &adminName, std::vector<int32_t> &data,
    std::vector<int32_t> &mergeData, int32_t userId)
{
    EDMLOGI("BasicArrayIntPlugin OnAdminRemove adminName : %{public}s", adminName.c_str());
    std::vector<int32_t> needRemoveMergePolicy =
        ArrayIntSerializer::GetInstance()->SetDifferencePolicyData(mergeData, data);
    std::vector<int32_t> failedData;
    return RemoveOtherModulePolicy(needRemoveMergePolicy, userId, failedData);
}

ErrCode BasicArrayIntPlugin::SetOtherModulePolicy(const std::vector<int32_t> &data, int32_t userId,
    std::vector<int32_t> &failedData)
{
    return ERR_OK;
}

ErrCode BasicArrayIntPlugin::RemoveOtherModulePolicy(const std::vector<int32_t> &data, int32_t userId,
    std::vector<int32_t> &failedData)
{
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS