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

#include "allowed_notification_bundles_plugin.h"

#include "allowed_notification_bundles_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "notification_helper.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    AllowedNotificationBundlesPlugin::GetPlugin());

const char* const RESTRICTED_MODE_TRUST_LIST = "restricted_mode_trust_list";
const char* const TRUE_VALUE = "true";

void AllowedNotificationBundlesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<AllowedNotificationBundlesPlugin,
        std::vector<AllowedNotificationBundlesType>>> ptr)
{
    EDMLOGI("AllowedNotificationBundlesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ALLOWED_NOTIFICATION_BUNDLES,
        PolicyName::POLICY_ALLOWED_NOTIFICATION_BUNDLES,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(AllowedNotificationBundlesSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AllowedNotificationBundlesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&AllowedNotificationBundlesPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
}

ErrCode AllowedNotificationBundlesPlugin::OnSetPolicy(std::vector<AllowedNotificationBundlesType> &data,
    std::vector<AllowedNotificationBundlesType> &currentData,
    std::vector<AllowedNotificationBundlesType> &mergeData, int32_t userId)
{
    EDMLOGI("AllowedNotificationBundlesPlugin OnSetPolicy");
    if (data.size() != 1) {
        EDMLOGE("AllowedNotificationBundlesPlugin OnSetPolicy data size error");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t accountId = data[0].userId;
    if (accountId <= 0 || data[0].trustList.size() == 0) {
        EDMLOGE("AllowedNotificationBundlesPlugin OnSetPolicy param invalid");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (!CheckConflictPolicy()) {
        EDMLOGE("AllowedNotificationBundlesPlugin OnSetPolicy policy conflict");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    std::set<std::string>* trustList = nullptr;
    FindUserTrustList(currentData, accountId, trustList);
    if (trustList == nullptr) {
        AllowedNotificationBundlesType newBundles;
        newBundles.userId = accountId;
        newBundles.trustList = data[0].trustList;
        currentData.push_back(newBundles);
    } else {
        trustList->insert(data[0].trustList.begin(), data[0].trustList.end());
    }
    std::set<std::string>* mergeTrustList = nullptr;
    FindUserTrustList(mergeData, accountId, mergeTrustList);
    if (mergeTrustList == nullptr) {
        AllowedNotificationBundlesType newBundles;
        newBundles.userId = accountId;
        newBundles.trustList = data[0].trustList;
        mergeData.push_back(newBundles);
        mergeTrustList = &currentData[0].trustList;
    } else {
        mergeTrustList->insert(data[0].trustList.begin(), data[0].trustList.end());
    }
    if (mergeTrustList->size() > EdmConstants::NOTIFICATION_BUNDLES_MAX_SIZE) {
        EDMLOGE("AllowedNotificationBundlesPlugin OnSetPolicy exceeds max size");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    ErrCode ret = SetAdditionConfig(mergeData);
    if (ret != ERR_OK) {
        return ret;
    }
    return ERR_OK;
}

ErrCode AllowedNotificationBundlesPlugin::OnRemovePolicy(std::vector<AllowedNotificationBundlesType> &data,
    std::vector<AllowedNotificationBundlesType> &currentData,
    std::vector<AllowedNotificationBundlesType> &mergeData, int32_t userId)
{
    EDMLOGI("AllowedNotificationBundlesPlugin OnRemovePolicy");
    if (data.size() != 1) {
        EDMLOGE("AllowedNotificationBundlesPlugin OnRemovePolicy data size error");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t accountId = data[0].userId;
    if (accountId <= 0 || data[0].trustList.size() == 0) {
        EDMLOGE("AllowedNotificationBundlesPlugin OnRemovePolicy accountId invalid");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::set<std::string>* trustList = nullptr;
    FindUserTrustList(currentData, accountId, trustList);
    if (trustList == nullptr) {
        return ERR_OK;
    }
    
    for (const auto& bundleName : data[0].trustList) {
        trustList->erase(bundleName);
    }
    
    if (trustList->empty()) {
        for (auto it = currentData.begin(); it != currentData.end(); ++it) {
            if (it->userId == accountId) {
                currentData.erase(it);
                break;
            }
        }
    }
    std::set<std::string>* mergeTrustList = nullptr;
    FindUserTrustList(mergeData, accountId, mergeTrustList);
    if (mergeTrustList == nullptr) {
        if (!trustList->empty()) {
            AllowedNotificationBundlesType newBundles;
            newBundles.userId = accountId;
            newBundles.trustList = *trustList;
            mergeData.push_back(newBundles);
        }
    } else {
        mergeTrustList->insert(trustList->begin(), trustList->end());
    }
    ErrCode ret = SetAdditionConfig(mergeData);
    if (ret != ERR_OK) {
        return ret;
    }
    return ERR_OK;
}

ErrCode AllowedNotificationBundlesPlugin::OnAdminRemove(const std::string &adminName,
    std::vector<AllowedNotificationBundlesType> &data,
    std::vector<AllowedNotificationBundlesType> &mergeData, int32_t userId)
{
    auto ret = SetAdditionConfig(mergeData);
    if (ret != ERR_OK) {
        EDMLOGE("DisallowedNotificationPlugin::OnAdminRemove SetAdditionConfig error.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

void AllowedNotificationBundlesPlugin::FindUserTrustList(std::vector<AllowedNotificationBundlesType> &data,
    int32_t userId, std::set<std::string> *&trustList)
{
    for (auto& item : data) {
        if (item.userId == userId) {
            trustList = &item.trustList;
            return;
        }
    }
    trustList = nullptr;
}

ErrCode AllowedNotificationBundlesPlugin::SetAdditionConfig(std::vector<AllowedNotificationBundlesType> &data)
{
    std::string policyData;
    if (!AllowedNotificationBundlesSerializer::GetInstance()->Serialize(data, policyData)) {
        EDMLOGE("SetAdditionConfig Serialize error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (policyData.empty()) {
        policyData = "[]";
    }
    int32_t ret = OHOS::Notification::NotificationHelper::SetAdditionConfig(RESTRICTED_MODE_TRUST_LIST, policyData);
    if (ret != ERR_OK) {
        EDMLOGE("NotificationHelper::SetAdditionConfig error. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

bool AllowedNotificationBundlesPlugin::CheckConflictPolicy()
{
    std::string policyData;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_DISALLOWED_NOTIFICATION,
        policyData, EdmConstants::DEFAULT_USER_ID);
    return policyData != TRUE_VALUE;
}

} // namespace EDM
} // namespace OHOS
