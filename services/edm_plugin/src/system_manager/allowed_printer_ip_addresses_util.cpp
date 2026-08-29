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
 
#include "allowed_printer_ip_addresses_util.h"
 
namespace OHOS {
namespace EDM {
 
ErrCode AllowedPrinterIpAddressesUtil::CheckPolicyConflict(AllowedPrinterIpAddressesType type)
{
    if (type == AllowedPrinterIpAddressesType::DEVICE_TYPE) {
        if (IsAnyUserLevelPolicySet()) {
            EDMLOGE("AllowedPrinterIpAddressesUtil::CheckPolicyConflict: "
                "device-level operation rejected due to existing user-level policy");
            return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
        }
    } else if (type == AllowedPrinterIpAddressesType::USER_TYPE) {
        if (IsDeviceLevelPolicySet()) {
            EDMLOGE("AllowedPrinterIpAddressesUtil::CheckPolicyConflict: "
                "user-level operation rejected due to existing device-level policy");
            return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
        }
    }
    return ERR_OK;
}
 
ErrCode AllowedPrinterIpAddressesUtil::OnSetPolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId,
    AllowedPrinterIpAddressesType type, uint32_t maxSize, uint32_t maxReturnErrCode)
{
    EDMLOGI("AllowedPrinterIpAddressesUtil::OnSetPolicy start, data.size=%{public}zu, type=%{public}u",
        data.size(), static_cast<uint32_t>(type));
 
    ErrCode conflictResult = CheckPolicyConflict(type);
    if (FAILED(conflictResult)) {
        return conflictResult;
    }
 
    if (data.empty()) {
        return ERR_OK;
    }
 
    if (data.size() > maxSize) {
        EDMLOGE("AllowedPrinterIpAddressesUtil OnSetPolicy input data is too large");
        return maxReturnErrCode;
    }
 
    std::vector<std::string> originalCurrentData = currentData;
    std::vector<std::string> originalMergeData =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(mergeData, currentData);
    std::vector<std::string> needAddData =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(currentData, data);
    std::vector<std::string> needAddMergeData =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(mergeData, needAddData);
    std::vector<std::string> afterHandle =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(currentData, needAddData);
    std::vector<std::string> afterMerge =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
 
    if (afterMerge.size() > maxSize) {
        EDMLOGE("AllowedPrinterIpAddressesUtil OnSetPolicy merge data is too large");
        return maxReturnErrCode;
    }
 
    currentData = afterHandle;
    mergeData = afterMerge;
 
    EDMLOGI("AllowedPrinterIpAddressesUtil::OnSetPolicy success, afterMerge.size=%{public}zu", afterMerge.size());
    return ERR_OK;
}
 
ErrCode AllowedPrinterIpAddressesUtil::OnRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, std::vector<std::string> &mergeData, int32_t userId,
    AllowedPrinterIpAddressesType type, uint32_t maxSize, uint32_t maxReturnErrCode)
{
    EDMLOGI("AllowedPrinterIpAddressesUtil::OnRemovePolicy start, data.size=%{public}zu, type=%{public}u",
        data.size(), static_cast<uint32_t>(type));
    
    ErrCode conflictResult = CheckPolicyConflict(type);
    if (FAILED(conflictResult)) {
        return conflictResult;
    }
 
    if (data.empty()) {
        return ERR_OK;
    }
 
    if (data.size() > maxSize) {
        EDMLOGE("AllowedPrinterIpAddressesUtil OnRemovePolicy input data is too large");
        return maxReturnErrCode;
    }
 
    std::vector<std::string> originalCurrentData = currentData;
    std::vector<std::string> originalMergeData =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(mergeData, currentData);
    std::vector<std::string> needRemovePolicy =
        ArrayStringSerializer::GetInstance()->SetIntersectionPolicyData(data, currentData);
    std::vector<std::string> needRemoveMergePolicy =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(mergeData, needRemovePolicy);
    std::vector<std::string> afterHandle =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(needRemovePolicy, currentData);
    std::vector<std::string> afterMerge =
        ArrayStringSerializer::GetInstance()->SetUnionPolicyData(afterHandle, mergeData);
 
    currentData = afterHandle;
    mergeData = afterMerge;
 
    EDMLOGI("AllowedPrinterIpAddressesUtil::OnRemovePolicy success, afterMerge.size=%{public}zu", afterMerge.size());
    return ERR_OK;
}
 
bool AllowedPrinterIpAddressesUtil::IsDeviceLevelPolicySet()
{
    std::string policyValue;
    IPolicyManager::GetInstance()->GetPolicy("",
        PolicyName::POLICY_ALLOWED_PRINTER_IP_ADDRESSES_FOR_DEVICE, policyValue,
        EdmConstants::DEFAULT_USER_ID);
    return !policyValue.empty();
}
 
bool AllowedPrinterIpAddressesUtil::IsAnyUserLevelPolicySet()
{
    // Check DEFAULT_USER_ID first (not included in GetPolicyUserIds)
    std::string defaultPolicyValue;
    IPolicyManager::GetInstance()->GetPolicy("",
        PolicyName::POLICY_ALLOWED_PRINTER_IP_ADDRESSES_FOR_ACCOUNT, defaultPolicyValue,
        EdmConstants::DEFAULT_USER_ID);
    if (!defaultPolicyValue.empty()) {
        EDMLOGI("AllowedPrinterIpAddressesUtil::IsAnyUserLevelPolicySet found at userId=%{public}d",
            EdmConstants::DEFAULT_USER_ID);
        return true;
    }
    // Check other users
    std::vector<int32_t> userIds;
    IPolicyManager::GetInstance()->GetPolicyUserIds(userIds);
    for (int32_t userId : userIds) {
        std::string policyValue;
        IPolicyManager::GetInstance()->GetPolicy("",
            PolicyName::POLICY_ALLOWED_PRINTER_IP_ADDRESSES_FOR_ACCOUNT, policyValue, userId);
        if (!policyValue.empty()) {
            EDMLOGI("AllowedPrinterIpAddressesUtil::IsAnyUserLevelPolicySet found at userId=%{public}d", userId);
            return true;
        }
    }
    return false;
}
 
void AllowedPrinterIpAddressesUtil::NotifyPrintPolicyChanged(int32_t userId, AllowedPrinterIpAddressesType type)
{
    EDMLOGI("AllowedPrinterIpAddressesUtil::NotifyPrintPolicyChanged userId=%{public}d, type=%{public}u",
        userId, static_cast<uint32_t>(type));
    AAFwk::Want want;
    want.SetAction("edm.event.PRINT_POLICY");
    // DEVICE_TYPE: -1 means all-user policy; USER_TYPE: specific userId
    std::string eventDataJson = (type == AllowedPrinterIpAddressesType::DEVICE_TYPE)
        ? "{\"user_id\":-1}"
        : "{\"user_id\":" + std::to_string(userId) + "}";
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    eventData.SetData(eventDataJson);
    EventFwk::CommonEventPublishInfo publishInfo;
    if (!EventFwk::CommonEventManager::PublishCommonEvent(eventData, publishInfo)) {
        EDMLOGE("AllowedPrinterIpAddressesUtil::NotifyPrintPolicyChanged publish failed");
    }
}
 
} // namespace EDM
} // namespace OHOS