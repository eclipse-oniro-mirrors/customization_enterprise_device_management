/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

ErrCode PolicyManager::GetAdminByPolicyName(const std::string &policyName, AdminValueItemsMap &adminValueItems,
    int32_t userId)
{
    auto userPolicyMgr = GetUserPolicyMgr(userId);
    return userPolicyMgr->GetAdminByPolicyName(policyName, adminValueItems);
}

ErrCode PolicyManager::GetPolicy(const std::string &adminName, const std::string &policyName, std::string &policyValue,
    int32_t userId)
{
    auto userPolicyMgr = GetUserPolicyMgr(userId);
    return userPolicyMgr->GetPolicy(adminName, policyName, policyValue);
}

void PolicyManager::Init(std::vector<int32_t> userIds)
{
    for (auto userId : userIds) {
        EDMLOGI("PolicyManager::Init userId %{public}d", userId);
        if (userId == EdmConstants::DEFAULT_USER_ID) {
            defaultPolicyMgr_ = std::make_shared<UserPolicyManager>(userId);
            defaultPolicyMgr_->Init();
        } else {
            std::shared_ptr<UserPolicyManager> userPolicyMgr = std::make_shared<UserPolicyManager>(userId);
            userPolicyMgr->Init();
            policyMgrMap_.insert(std::make_pair(userId, userPolicyMgr));
        }
    }
    return;
}

ErrCode PolicyManager::SetPolicy(const std::string &adminName, const std::string &policyName,
    const std::string &adminPolicyValue, const std::string &mergedPolicyValue,
    int32_t userId)
{
    auto userPolicyMgr = GetUserPolicyMgr(userId);
    return userPolicyMgr->SetPolicy(adminName, policyName, adminPolicyValue, mergedPolicyValue);
}

ErrCode PolicyManager::GetAllPolicyByAdmin(const std::string &adminName, PolicyItemsMap &allAdminPolicy,
    int32_t userId)
{
    auto userPolicyMgr = GetUserPolicyMgr(userId);
    return userPolicyMgr->GetAllPolicyByAdmin(adminName, allAdminPolicy);
}

std::shared_ptr<UserPolicyManager> PolicyManager::GetUserPolicyMgr(int32_t userId)
{
    EDMLOGD("PolicyManager::GetUserPolicyMgr by userId:%{public}d", userId);
    if (userId == EdmConstants::DEFAULT_USER_ID) {
        if (defaultPolicyMgr_ == nullptr) {
            defaultPolicyMgr_ = std::make_shared<UserPolicyManager>(userId);
            defaultPolicyMgr_->Init();
        }
        return defaultPolicyMgr_;
    } else {
        auto itr = policyMgrMap_.find(userId);
        if (itr != policyMgrMap_.end()) {
            return itr->second;
        } else {
            std::shared_ptr<UserPolicyManager> userPolicyMgr = std::make_shared<UserPolicyManager>(userId);
            userPolicyMgr->Init();
            policyMgrMap_.insert(std::make_pair(userId, userPolicyMgr));
            return userPolicyMgr;
        }
    }
}

void PolicyManager::GetPolicyUserIds(std::vector<int32_t> &userIds)
{
    for (const auto& pair : policyMgrMap_) {
        userIds.push_back(pair.first);
    }
}

void PolicyManager::Dump()
{
    auto defaultUserPolicyMgr = GetUserPolicyMgr(EdmConstants::DEFAULT_USER_ID);
    defaultUserPolicyMgr->DumpAdminPolicy();
    defaultUserPolicyMgr->DumpAdminList();
    defaultUserPolicyMgr->DumpCombinedPolicy();

    std::vector<int32_t> userIds;
    GetPolicyUserIds(userIds);
    EDMLOGD("PolicyManager::Dump userIds size:%{public}zu", userIds.size());
    for (auto userId : userIds) {
        auto userPolicyMgr = GetUserPolicyMgr(userId);
        userPolicyMgr->DumpAdminPolicy();
        userPolicyMgr->DumpAdminList();
        userPolicyMgr->DumpCombinedPolicy();
    }
}
} // namespace EDM
} // namespace OHOS
