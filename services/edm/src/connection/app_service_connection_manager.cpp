/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "app_service_connection_manager.h"

#include "ability_manager_client.h"
#include "edm_errors.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
static int32_t MapConnectSyncErrorCode(int32_t abilityManagerCode)
{
    constexpr int32_t RESOLVE_ABILITY_ERR = 2097152;
    constexpr int32_t ERR_WRONG_INTERFACE_CALL = 2097202;
    if (abilityManagerCode == RESOLVE_ABILITY_ERR) {
        return EdmReturnErrCode::ABILITY_NOT_EXIST;
    }
    if (abilityManagerCode == ERR_WRONG_INTERFACE_CALL) {
        return EdmReturnErrCode::CONNECT_APP_SERVICE_EXTENSION_INVALID_TYPE;
    }
    return EdmReturnErrCode::CONNECT_APP_SERVICE_EXTENSION_FAILED;
}

AppServiceConnectionManager& AppServiceConnectionManager::GetInstance()
{
    static AppServiceConnectionManager instance;
    return instance;
}

int32_t AppServiceConnectionManager::ConnectAppServiceExtensionAbilityByOsAccount(
    const AAFwk::Want &want, int32_t accountId,
    const sptr<IEdmConnectionCallback> &callback, const std::string &adminBundleName,
    std::shared_ptr<AAFwk::IndirectCallerInfo> indirectCallerInfo, int32_t &connectionId)
{
    connectionId = -1;
    if (callback == nullptr) {
        EDMLOGE("callback is null");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    int32_t connId = nextConnectionId_.fetch_add(1);
    sptr<AppServiceConnectionStub> stub = new (std::nothrow) AppServiceConnectionStub(connId, callback);
    if (stub == nullptr) {
        EDMLOGE("failed to create stub");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->ConnectAbilityWithIndirectCallerInfo(
        want, stub, nullptr, accountId, AppExecFwk::ExtensionAbilityType::APP_SERVICE, indirectCallerInfo);
    if (FAILED(ret)) {
        EDMLOGE("ConnectAbilityWithIndirectCallerInfo failed ret=%{public}d", ret);
        return MapConnectSyncErrorCode(ret);
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    ConnectionRecord record;
    record.stub = stub;
    record.callback = callback;
    record.adminBundleName = adminBundleName;
    record.accountId = accountId;
    connectionMap_[connId] = record;
    connectionId = connId;
    EDMLOGI("Connect success connectionId=%{public}d admin=%{public}s accountId=%{public}d",
        connId, adminBundleName.c_str(), accountId);
    return ERR_OK;
}

int32_t AppServiceConnectionManager::DisconnectAppServiceExtensionAbility(int32_t connectionId)
{
    sptr<AppServiceConnectionStub> stub;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = connectionMap_.find(connectionId);
        if (it == connectionMap_.end()) {
            EDMLOGE("connectionId=%{public}d not found", connectionId);
            return EdmReturnErrCode::UID_INVALID;
        }
        stub = it->second.stub;
        connectionMap_.erase(it);
    }
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->DisconnectAbility(stub);
    if (FAILED(ret)) {
        EDMLOGE("DisconnectAbility failed ret=%{public}d", ret);
    }
    EDMLOGI("Disconnect success connectionId=%{public}d", connectionId);
    return ERR_OK;
}

void AppServiceConnectionManager::OnAdminRemoved(const std::string &adminBundleName)
{
    EDMLOGI("OnAdminRemoved admin=%{public}s", adminBundleName.c_str());
    std::vector<sptr<AppServiceConnectionStub>> stubsToDisconnect;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        for (auto it = connectionMap_.begin(); it != connectionMap_.end();) {
            if (it->second.adminBundleName == adminBundleName) {
                stubsToDisconnect.push_back(it->second.stub);
                it = connectionMap_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto &stub : stubsToDisconnect) {
        AAFwk::AbilityManagerClient::GetInstance()->DisconnectAbility(stub);
    }
}
} // namespace EDM
} // namespace OHOS
