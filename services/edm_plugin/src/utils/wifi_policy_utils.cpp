/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "wifi_policy_utils.h"

#include "array_wifi_id_serializer.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "ipolicy_manager.h"
#include "wifi_device.h"

namespace OHOS {
namespace EDM {
ErrCode WifiPolicyUtils::SetWifiAccessList(std::vector<WifiId> data, bool isAllowed)
{
    EDMLOGI("WifiPolicyUtils SetWifiAccessList....data size = %{public}zu", data.size());
    auto wifiDevice = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (wifiDevice == nullptr) {
        EDMLOGE("wifiDevice GetInstance null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::vector<Wifi::WifiRestrictedInfo> wifiRestrictedList;
    for (const auto& item : data) {
        Wifi::WifiRestrictedInfo wifiRestrictedInfo;
        wifiRestrictedInfo.ssid = item.GetSsid();
        wifiRestrictedInfo.bssid = item.GetBssid();
        if (isAllowed) {
            wifiRestrictedInfo.wifiRestrictedType = Wifi::WifiRestrictedType::MDM_WHITELIST;
        } else {
            wifiRestrictedInfo.wifiRestrictedType = Wifi::WifiRestrictedType::MDM_BLOCKLIST;
        }
        wifiRestrictedList.push_back(wifiRestrictedInfo);
    }
    ErrCode ret = wifiDevice->SetWifiRestrictedList(wifiRestrictedList);
    if (ret != ERR_OK) {
        EDMLOGE("WifiPolicyUtils SetWifiAccessList ret %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode WifiPolicyUtils::AddWifiListPolicy(std::vector<WifiId> &data, std::vector<WifiId> &currentData,
    std::vector<WifiId> &mergeData, int32_t userId, bool isAllowed)
{
    if (data.empty()) {
        EDMLOGW("AddWifiListPolicy data is empty");
        return ERR_OK;
    }
    if (data.size() > EdmConstants::WIFI_LIST_MAX_SIZE) {
        EDMLOGE("AddWifiListPolicy data size=[%{public}zu] is too large", data.size());
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (!CheckWifiId(data, isAllowed)) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (HasConflictPolicy(isAllowed)) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    std::vector<WifiId> needAddData =
        ArrayWifiIdSerializer::GetInstance()->SetDifferencePolicyData(currentData, data);
    std::vector<WifiId> needAddMergeData =
        ArrayWifiIdSerializer::GetInstance()->SetDifferencePolicyData(mergeData, needAddData);
    std::vector<WifiId> afterHandle =
        ArrayWifiIdSerializer::GetInstance()->SetUnionPolicyData(currentData, needAddData);
    std::vector<WifiId> afterMerge =
        ArrayWifiIdSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    if (afterMerge.size() > EdmConstants::WIFI_LIST_MAX_SIZE) {
        EDMLOGE("AddWifiListPolicy union data size=[%{public}zu] is too large", mergeData.size());
        return EdmReturnErrCode::PARAM_ERROR;
    }
    ErrCode errCode = SetWifiAccessList(afterMerge, isAllowed);
    if (errCode != ERR_OK) {
        return errCode;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode WifiPolicyUtils::RemoveWifiListPolicy(std::vector<WifiId> &data, std::vector<WifiId> &currentData,
    std::vector<WifiId> &mergeData, int32_t userId, bool isAllowed)
{
    if (data.empty()) {
        EDMLOGW("RemoveWifiListPolicy data is empty:");
        return ERR_OK;
    }
    if (data.size() > EdmConstants::WIFI_LIST_MAX_SIZE) {
        EDMLOGE("RemoveWifiListPolicy data size=[%{public}zu] is too large", data.size());
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (!CheckWifiId(data, isAllowed)) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<WifiId> afterHandle =
        ArrayWifiIdSerializer::GetInstance()->SetDifferencePolicyData(data, currentData);
    std::vector<WifiId> afterMerge =
        ArrayWifiIdSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);
    ErrCode errCode = SetWifiAccessList(afterMerge, isAllowed);
    if (errCode != ERR_OK) {
        return errCode;
    }
    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

bool WifiPolicyUtils::CheckWifiId(std::vector<WifiId> &data, bool isAllowed)
{
    for (const auto& wifiId : data) {
        std::string ssid = wifiId.GetSsid();
        if (ssid.size() > EdmConstants::WIFI_SSID_MAX_LENGTH || ssid.empty()) {
            EDMLOGE("CheckWifiList ssid is empty or too large!");
            return false;
        }
        std::string bssid = wifiId.GetBssid();
        if (!bssid.empty() && bssid.size() != EdmConstants::WIFI_BSSID_LENGTH) {
            EDMLOGE("CheckWifiList bssid parse error!");
            return false;
        }
    }
    return true;
}

bool WifiPolicyUtils::HasConflictPolicy(bool isAllowed)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string disableWifiPolicy;
    policyManager->GetPolicy("", PolicyName::POLICY_DISABLE_WIFI, disableWifiPolicy);
    if (disableWifiPolicy == "true") {
        EDMLOGE("WifiList policy conflict! Wifi is disabled.");
        return true;
    }
    std::string policyName = PolicyName::POLICY_ALLOWED_WIFI_LIST;
    if (isAllowed) {
        policyName = PolicyName::POLICY_DISALLOWED_WIFI_LIST;
    }
    std::string wifiListPolicy;
    policyManager->GetPolicy("", policyName, wifiListPolicy);
    if (!wifiListPolicy.empty()) {
        EDMLOGE("WifiList policy conflict! Has another wifiListPolicy");
        return true;
    }
    return false;
}
}
}