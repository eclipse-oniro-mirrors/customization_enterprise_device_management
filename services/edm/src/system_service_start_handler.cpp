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

#include "system_service_start_handler.h"

#include "admin_manager.h"
#include "edm_log.h"
#include "external_manager_factory.h"
#include "net_policy_client.h"
 
namespace OHOS {
namespace EDM {
std::shared_ptr<SystemServiceStartHandler> SystemServiceStartHandler::GetInstance()
{
    static std::shared_ptr<SystemServiceStartHandler> instance = std::make_shared<SystemServiceStartHandler>();
    return instance;
}

bool SystemServiceStartHandler::AddNetworkAccessPolicy(const std::vector<std::string> &bundleNames)
{
    auto ret = NetManagerStandard::NetPolicyClient::GetInstance().AddNetworkAccessPolicy(bundleNames);
    if (ret != ERR_OK) {
        EDMLOGE("AddNetworkAccessPolicy Failed ret:%{public}d.", ret);
        return false;
    }
    return true;
}

bool SystemServiceStartHandler::RemoveNetworkAccessPolicy(const std::vector<std::string> &bundleNames)
{
    auto ret = NetManagerStandard::NetPolicyClient::GetInstance().RemoveNetworkAccessPolicy(bundleNames);
    if (ret != ERR_OK) {
        EDMLOGE("RemoveNetworkAccessPolicy Failed ret:%{public}d.", ret);
        return false;
    }
    return true;
}

bool SystemServiceStartHandler::OnNetPolicyManagerStart()
{
    // 查询出所有激活的admin的包名
    std::vector<std::shared_ptr<Admin>> admins;
    int32_t userId = std::make_shared<EdmOsAccountManagerImpl>()->GetCurrentUserId();
    AdminManager::GetInstance()->GetAdminByUserId(userId, admins);
    std::vector<std::string> bundleNames;
    for (auto const &admin : admins) {
        if (admin != nullptr) {
            bundleNames.push_back(admin->adminInfo_.packageName_);
        }
    }
    // 调用网络管理接口，设置网络策略
    auto ret = NetManagerStandard::NetPolicyClient::GetInstance().AddNetworkAccessPolicy(bundleNames);
    if (ret != ERR_OK) {
        EDMLOGE("OnNetPolicyManagerStart Failed ret:%{public}d.", ret);
        return false;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS