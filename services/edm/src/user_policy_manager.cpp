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

#include "policy_manager.h"
#include <algorithm>
#include <ctime>
#include <fstream>
#include <unistd.h>
#include "directory_ex.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {

UserPolicyManager::UserPolicyManager(int32_t userId)
{
    EDMLOGD("UserPolicyManager::UserPolicyManager %{public}d", userId);
    userIdState_ = userId;
}

ErrCode UserPolicyManager::GetAdminByPolicyName(const std::string &policyName, AdminValueItemsMap &adminValueItems)
{
    auto iter = policyAdmins_.find(policyName);
    if (iter != policyAdmins_.end()) {
        adminValueItems = iter->second;
        return ERR_OK;
    }
    return ERR_EDM_POLICY_NOT_FOUND;
}

ErrCode UserPolicyManager::GetAllPolicyByAdmin(const std::string &adminName, PolicyItemsMap &allAdminPolicy)
{
    auto iter = adminPolicies_.find(adminName);
    if (iter != adminPolicies_.end()) {
        allAdminPolicy = iter->second;
        return ERR_OK;
    }
    return ERR_EDM_POLICY_NOT_FIND;
}

ErrCode UserPolicyManager::GetAdminPolicy(const std::string &adminName, const std::string &policyName,
    std::string &policyValue)
{
    auto iter = adminPolicies_.find(adminName);
    if (iter != adminPolicies_.end()) {
        const PolicyItemsMap &policyItem = iter->second;
        auto it = policyItem.find(policyName);
        if (it != policyItem.end()) {
            policyValue = it->second;
            return ERR_OK;
        }
    }
    return ERR_EDM_POLICY_NOT_FIND;
}

ErrCode UserPolicyManager::GetCombinedPolicy(const std::string &policyName, std::string &policyValue)
{
    auto it = combinedPolicies_.find(policyName);
    if (it != combinedPolicies_.end()) {
        policyValue = it->second;
        return ERR_OK;
    }
    return ERR_EDM_POLICY_NOT_FIND;
}

ErrCode UserPolicyManager::GetPolicy(const std::string &adminName, const std::string &policyName,
    std::string &policyValue)
{
    if (adminName.empty()) {
        return GetCombinedPolicy(policyName, policyValue);
    } else {
        return GetAdminPolicy(adminName, policyName, policyValue);
    }
}

void UserPolicyManager::SetAdminList(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue)
{
    auto iter = policyAdmins_.find(policyName);
    if (iter == policyAdmins_.end()) {
        /* policy first added into map */
        AdminValueItemsMap adminValueItem;
        adminValueItem.insert(std::pair<std::string, std::string>(adminName, policyValue));
        policyAdmins_.insert(std::pair<std::string, AdminValueItemsMap>(policyName, adminValueItem));
        return;
    }

    AdminValueItemsMap &adminValueRef = iter->second;
    auto it = adminValueRef.find(adminName);
    if (it != adminValueRef.end()) {
        it->second = policyValue;
    } else {
        adminValueRef.insert(std::pair<std::string, std::string>(adminName, policyValue));
    }
}

ErrCode UserPolicyManager::SetAdminPolicy(const std::string &adminName, const std::string &policyName,
    const std::string &policyValue)
{
    auto devicePoliciesStorageRdb = DevicePoliciesStorageRdb::GetInstance();
    if (devicePoliciesStorageRdb == nullptr) {
        EDMLOGE("PolicyManager::SetAdminPolicy get devicePoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    SetAdminList(adminName, policyName, policyValue);
    auto iter = adminPolicies_.find(adminName);
    if (iter == adminPolicies_.end()) {
        if (devicePoliciesStorageRdb->InsertAdminPolicy(userIdState_, adminName, policyName, policyValue)) {
            PolicyItemsMap itemMap;
            itemMap.insert(std::pair<std::string, std::string>(policyName, policyValue));
            adminPolicies_.insert(std::pair<std::string, PolicyItemsMap>(adminName, itemMap));
            return ERR_OK;
        }
        EDMLOGE("PolicyManager::SetAdminPolicy failed.");
        return ERR_EDM_POLICY_SET_FAILED;
    }

    PolicyItemsMap &policyItem = iter->second;
    auto it = policyItem.find(policyName);
    if (it != policyItem.end() &&
        devicePoliciesStorageRdb->UpdateAdminPolicy(userIdState_, adminName, policyName, policyValue)) {
        it->second = policyValue;
        return ERR_OK;
    } else if (it == policyItem.end() &&
        devicePoliciesStorageRdb->InsertAdminPolicy(userIdState_, adminName, policyName, policyValue)) {
        policyItem.insert(std::pair<std::string, std::string>(policyName, policyValue));
        return ERR_OK;
    }
    EDMLOGE("PolicyManager::SetAdminPolicy failed.");
    return ERR_EDM_POLICY_SET_FAILED;
}

ErrCode UserPolicyManager::SetCombinedPolicy(const std::string &policyName, const std::string &policyValue)
{
    auto devicePoliciesStorageRdb = DevicePoliciesStorageRdb::GetInstance();
    if (devicePoliciesStorageRdb == nullptr) {
        EDMLOGE("PolicyManager::SetCombinedPolicy get devicePoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    auto it = combinedPolicies_.find(policyName);
    if (it != combinedPolicies_.end() &&
        devicePoliciesStorageRdb->UpdateCombinedPolicy(userIdState_, policyName, policyValue)) {
        it->second = policyValue;
        return ERR_OK;
    } else if (it == combinedPolicies_.end() &&
        devicePoliciesStorageRdb->InsertCombinedPolicy(userIdState_, policyName, policyValue)) {
        combinedPolicies_.insert(std::pair<std::string, std::string>(policyName, policyValue));
        return ERR_OK;
    }
    EDMLOGE("PolicyManager::SetCombinedPolicy failed.");
    return ERR_EDM_POLICY_SET_FAILED;
}

void UserPolicyManager::DeleteAdminList(const std::string &adminName, const std::string &policyName)
{
    auto iter = policyAdmins_.find(policyName);
    if (iter == policyAdmins_.end()) {
        return;
    }

    AdminValueItemsMap &adminValueRef = iter->second;
    auto it = adminValueRef.find(adminName);
    if (it == adminValueRef.end()) {
        return;
    }

    adminValueRef.erase(it);
    if (adminValueRef.empty()) {
        policyAdmins_.erase(iter);
    }
}

ErrCode UserPolicyManager::DeleteAdminPolicy(const std::string &adminName, const std::string &policyName)
{
    auto devicePoliciesStorageRdb = DevicePoliciesStorageRdb::GetInstance();
    if (devicePoliciesStorageRdb == nullptr) {
        EDMLOGE("PolicyManager::DeleteAdminPolicy get devicePoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    if (!devicePoliciesStorageRdb->DeleteAdminPolicy(userIdState_, adminName, policyName)) {
        EDMLOGE("PolicyManager DeleteAdminPolicy failed.");
        return ERR_EDM_POLICY_DEL_FAILED;
    }
    auto iter = adminPolicies_.find(adminName);
    if (iter != adminPolicies_.end()) {
        PolicyItemsMap &policyItem = iter->second;
        auto it = policyItem.find(policyName);
        if (it != policyItem.end()) {
            policyItem.erase(it);
        }

        if (iter->second.empty()) {
            adminPolicies_.erase(iter);
        }

        DeleteAdminList(adminName, policyName);
    }
    return ERR_OK;
}

ErrCode UserPolicyManager::DeleteCombinedPolicy(const std::string &policyName)
{
    auto devicePoliciesStorageRdb = DevicePoliciesStorageRdb::GetInstance();
    if (devicePoliciesStorageRdb == nullptr) {
        EDMLOGE("PolicyManager::DeleteCombinedPolicy get devicePoliciesStorageRdb failed.");
        return ERR_GET_STORAGE_RDB_FAILED;
    }
    if (!devicePoliciesStorageRdb->DeleteCombinedPolicy(userIdState_, policyName)) {
        EDMLOGE("PolicyManager DeleteCombinedPolicy failed.");
        return ERR_EDM_POLICY_DEL_FAILED;
    }
    auto it = combinedPolicies_.find(policyName);
    if (it != combinedPolicies_.end()) {
        combinedPolicies_.erase(it);
    }
    return ERR_OK;
}

void UserPolicyManager::DumpAdminPolicy()
{
    EDMLOGD("UserPolicyManager::DumpAdminPolicy %{public}d ", userIdState_);
    std::for_each(adminPolicies_.begin(), adminPolicies_.end(), [](auto iter) {
        EDMLOGD("UserPolicyManager::AdminName: %{public}s\n", iter.first.c_str());
        std::unordered_map<std::string, std::string> map = iter.second;
        std::for_each(map.begin(), map.end(),
            [](auto subIter) { EDMLOGD("%{public}s : %{public}s\n", subIter.first.c_str(), subIter.second.c_str()); });
    });
}

void UserPolicyManager::DumpAdminList()
{
    EDMLOGD("UserPolicyManager: DumpAdminList %{public}d ", userIdState_);
    std::for_each(policyAdmins_.begin(), policyAdmins_.end(), [](auto iter) {
        EDMLOGD("UserPolicyManager::PolicyName: %{public}s\n", iter.first.c_str());
        std::unordered_map<std::string, std::string> map = iter.second;
        std::for_each(map.begin(), map.end(),
            [](auto subIter) { EDMLOGD("%{public}s : %{public}s\n", subIter.first.c_str(), subIter.second.c_str()); });
    });
}

void UserPolicyManager::DumpCombinedPolicy()
{
    EDMLOGD("UserPolicyManager: DumpCombinedPolicy %{public}d ", userIdState_);
    std::for_each(combinedPolicies_.begin(), combinedPolicies_.end(),
        [](auto iter) { EDMLOGD("%{public}s : %{public}s\n", iter.first.c_str(), iter.second.c_str()); });
}

ErrCode UserPolicyManager::SetPolicy(const std::string &adminName, const std::string &policyName,
    const std::string &adminPolicy, const std::string &mergedPolicy)
{
    if (policyName.empty()) {
        return ERR_EDM_POLICY_SET_FAILED;
    }

    ErrCode err;
    if (mergedPolicy.empty()) {
        err = DeleteCombinedPolicy(policyName);
    } else {
        err = SetCombinedPolicy(policyName, mergedPolicy);
    }
    if (FAILED(err)) {
        EDMLOGW("Set or delete combined policy failed:%{public}d, merged policy:%{public}s\n",
            err, mergedPolicy.c_str());
    }

    if (!adminName.empty()) {
        if (adminPolicy.empty()) {
            err = DeleteAdminPolicy(adminName, policyName);
        } else {
            err = SetAdminPolicy(adminName, policyName, adminPolicy);
        }
    }
    if (FAILED(err)) {
        EDMLOGW("Set or delete admin policy failed:%{public}d, admin policy:%{public}s\n",
            err, adminPolicy.c_str());
    }
    return err;
}

void UserPolicyManager::Init()
{
    auto devicePoliciesStorageRdb = DevicePoliciesStorageRdb::GetInstance();
    if (devicePoliciesStorageRdb != nullptr &&
        devicePoliciesStorageRdb->QueryAdminPolicy(userIdState_, adminPolicies_, policyAdmins_) &&
        devicePoliciesStorageRdb->QueryCombinedPolicy(userIdState_, combinedPolicies_)) {
        EDMLOGI("UserPolicyManager init success.");
    } else {
        EDMLOGE("UserPolicyManager init failed.");
    }
}
} // namespace EDM
} // namespace OHOS
