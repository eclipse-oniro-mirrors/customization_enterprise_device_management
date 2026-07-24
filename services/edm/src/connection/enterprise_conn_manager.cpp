/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "enterprise_conn_manager.h"

#include <chrono>

#include "edm_log.h"
#include "enterprise_connection_callback.h"
#include "extension_manager_client.h"
#include "parameters.h"

using namespace OHOS::AAFwk;

namespace OHOS {
namespace EDM {
constexpr int64_t DEFAULT_TIMEOUT_MS = 10000;
constexpr const char* TIMEOUT_PARAM_NAME = "persist.sys.abilityms.timeout_unit_time_ratio";

bool EnterpriseConnManager::ExecuteCallback(const std::string& bundleName,
    const std::string& abilityName, int32_t userId, std::shared_ptr<ICallbackStrategy> strategy)
{
    if (strategy == nullptr) { // LCOV_EXCL_BR_LINE
        EDMLOGE("ExecuteCallback: strategy is nullptr");
        return false;
    }
    std::string key = GenerateConnectionKey(bundleName, userId);
    sptr<EnterpriseAdminProxy> existingProxy = nullptr;
    bool needCreateConnection = false;
    sptr<EnterpriseConnectionCallback> staleCallback;
    if (!CheckConnectionState(key, strategy, existingProxy, needCreateConnection, staleCallback)) {
        EDMLOGE("ExecuteCallback: check connection state failed");
        return false;
    }
    if (staleCallback != nullptr) {
        DisconnectStaleCallback(staleCallback);
    }
    if (existingProxy != nullptr) {
        if (!existingProxy->IsValid()) { // LCOV_EXCL_BR_LINE
            EDMLOGW("ExecuteCallback: proxy is invalid for %{public}s, reconnect", bundleName.c_str());
            return RequeueAndReconnect(bundleName, abilityName, userId, key, strategy);
        }
        bool ret = strategy->Execute(existingProxy);
        if (!ret) { // LCOV_EXCL_BR_LINE
            EDMLOGW("ExecuteCallback: strategy execute failed for %{public}s, reconnect", bundleName.c_str());
            return RequeueAndReconnect(bundleName, abilityName, userId, key, strategy);
        }
        return true;
    }
    if (!needCreateConnection) {
        return true;
    }
    return EstablishConnection(bundleName, abilityName, userId);
}

void EnterpriseConnManager::SaveProxy(const std::string& bundleName, int32_t userId,
    const sptr<EnterpriseAdminProxy>& proxy)
{
    if (proxy == nullptr) { // LCOV_EXCL_BR_LINE
        EDMLOGE("EnterpriseConnManager::SaveProxy proxy is nullptr");
        return;
    }
    std::string key = GenerateConnectionKey(bundleName, userId);
    std::vector<std::shared_ptr<ICallbackStrategy>> callbacks;
    {
        std::lock_guard<std::mutex> lock(connectionMutex_);
        auto it = connectionMap_.find(key);
        if (it == connectionMap_.end()) {
            EDMLOGE("EnterpriseConnManager::SaveProxy connection not found for %{public}s", bundleName.c_str());
            return;
        }
        auto& info = it->second;
        info.proxy = proxy;
        info.isPending = false;
        EDMLOGD("EnterpriseConnManager::SaveProxy saved proxy for %{public}s, queue size=%{public}zu",
            bundleName.c_str(), info.pendingCallbacks.size());
        callbacks = info.pendingCallbacks;
        info.pendingCallbacks.clear();
    }
    for (auto& cb : callbacks) {
        if (cb != nullptr) {
            EDMLOGI("EnterpriseConnManager::SaveProxy execute pending callback: code=%{public}u", cb->GetCode());
            bool ret = cb->Execute(proxy);
            if (!ret) { // LCOV_EXCL_BR_LINE
                EDMLOGW("EnterpriseConnManager::SaveProxy pending callback failed: code=%{public}u", cb->GetCode());
            }
        }
    }
}

int64_t EnterpriseConnManager::GetCurrentTimeMs()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

bool EnterpriseConnManager::IsConnectionTimeout(const ConnectionInfo& info)
{
    if (!info.isPending) {
        return false;
    }
    int64_t currentTime = GetCurrentTimeMs();
    int64_t elapsed = currentTime - info.createTime;
    int32_t ratio = system::GetIntParameter<int32_t>(TIMEOUT_PARAM_NAME, 1);
    int64_t timeoutMs = static_cast<int64_t>(DEFAULT_TIMEOUT_MS * ratio);
    return elapsed > timeoutMs;
}

bool EnterpriseConnManager::CheckConnectionState(const std::string& key,
    std::shared_ptr<ICallbackStrategy> strategy, sptr<EnterpriseAdminProxy>& existingProxy,
    bool& needCreateConnection, sptr<EnterpriseConnectionCallback>& staleCallback)
{
    std::lock_guard<std::mutex> lock(connectionMutex_);
    auto it = connectionMap_.find(key);

    if (it != connectionMap_.end() && IsConnectionTimeout(it->second)) {
        EDMLOGW("CheckConnectionState: connection timeout for %{public}s,  pending callbacks=%{public}zu",
            key.c_str(), it->second.pendingCallbacks.size());
        if (it->second.callback != nullptr) { // LCOV_EXCL_BR_LINE
            it->second.callback->MarkStale();
            staleCallback = it->second.callback;
        }
        connectionMap_.erase(it);
        it = connectionMap_.end();
    }

    if (it != connectionMap_.end() && it->second.proxy != nullptr) {
        EDMLOGI("CheckConnectionState: proxy exists for %{public}s, code=%{public}u", key.c_str(), strategy->GetCode());
        existingProxy = it->second.proxy;
        return true;
    }

    if (it != connectionMap_.end() && it->second.isPending) {
        EDMLOGI("CheckConnectionState: connection is pending for %{public}s, code=%{public}u",
            key.c_str(), strategy->GetCode());
        it->second.pendingCallbacks.push_back(strategy);
        return true;
    }

    needCreateConnection = PrepareNewConnection(key, strategy);
    return true;
}

bool EnterpriseConnManager::PrepareNewConnection(const std::string& key,
    std::shared_ptr<ICallbackStrategy> strategy)
{
    auto it = connectionMap_.find(key);
    if (it != connectionMap_.end()) {
        auto& info = it->second;
        info.isPending = true;
        info.createTime = GetCurrentTimeMs();
        info.pendingCallbacks.push_back(strategy);
        EDMLOGI("PrepareNewConnection: updated pending connection for %{public}s, pendingCallbacks=%{public}zu",
            key.c_str(), info.pendingCallbacks.size());
    } else {
        ConnectionInfo info;
        info.isPending = true;
        info.createTime = GetCurrentTimeMs();
        info.pendingCallbacks.push_back(strategy);
        connectionMap_[key] = info;
        EDMLOGI("PrepareNewConnection: created pending connection for %{public}s", key.c_str());
    }
    return true;
}

bool EnterpriseConnManager::EstablishConnection(const std::string& bundleName,
    const std::string& abilityName, int32_t userId)
{
    EDMLOGI("EstablishConnection: create new connection for %{public}s", bundleName.c_str());
    std::string key = GenerateConnectionKey(bundleName, userId);

    sptr<EnterpriseConnectionCallback> oldCallback;
    {
        std::lock_guard<std::mutex> lock(connectionMutex_);
        auto it = connectionMap_.find(key);
        if (it != connectionMap_.end() && it->second.callback != nullptr) { // LCOV_EXCL_BR_LINE
            oldCallback = it->second.callback;
        }
    }
    if (oldCallback != nullptr) {
        DisconnectStaleCallback(oldCallback);
    }

    AAFwk::Want want;
    want.SetElementName(bundleName, abilityName);
    sptr<EnterpriseConnectionCallback> connection = new (std::nothrow) EnterpriseConnectionCallback(bundleName, userId);
    if (connection == nullptr) { // LCOV_EXCL_BR_LINE
        EDMLOGE("EstablishConnection: create connection callback failed");
        return false;
    }

    int32_t ret = ExtensionManagerClient::GetInstance().ConnectEnterpriseAdminExtensionAbility(
        want, connection, nullptr, userId);
    if (ret != ERR_OK) {
        EDMLOGE("EstablishConnection: connect failed: %{public}d", ret);
        std::lock_guard<std::mutex> lock(connectionMutex_);
        auto it = connectionMap_.find(key);
        if (it != connectionMap_.end()) {
            EDMLOGW("EstablishConnection: connection request failed, lost %{public}zu pending callbacks",
                it->second.pendingCallbacks.size());
            connectionMap_.erase(it);
        }
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(connectionMutex_);
        auto it = connectionMap_.find(key);
        if (it != connectionMap_.end()) { // LCOV_EXCL_BR_LINE
            it->second.callback = connection;
        }
    }
    return true;
}

std::string EnterpriseConnManager::GenerateConnectionKey(const std::string& bundleName, int32_t userId)
{
    return bundleName + "_" + std::to_string(userId);
}

void EnterpriseConnManager::RemoveRemoteObject(const std::string& bundleName, int32_t userId)
{
    std::string key = GenerateConnectionKey(bundleName, userId);
    std::lock_guard<std::mutex> lock(connectionMutex_);
    auto it = connectionMap_.find(key);
    if (it != connectionMap_.end()) {
        connectionMap_.erase(it);
        EDMLOGI("EnterpriseConnManager::RemoveRemoteObject removed connection for %{public}s, userId=%{public}d",
            bundleName.c_str(), userId);
    }
}

void EnterpriseConnManager::ClearConnections()
{
    std::vector<sptr<EnterpriseConnectionCallback>> staleCallbacks;
    {
        std::lock_guard<std::mutex> lock(connectionMutex_);
        for (auto& pair : connectionMap_) {
            if (pair.second.callback != nullptr) { // LCOV_EXCL_BR_LINE
                pair.second.callback->MarkStale();
                staleCallbacks.push_back(pair.second.callback);
            }
        }
        connectionMap_.clear();
        EDMLOGI("EnterpriseConnManager::ClearConnections cleared all connections");
    }
    for (auto& cb : staleCallbacks) {
        ExtensionManagerClient::GetInstance().DisconnectAbility(cb->AsObject());
    }
}

void EnterpriseConnManager::DisconnectStaleCallback(const sptr<EnterpriseConnectionCallback>& callback)
{
    if (callback == nullptr) { // LCOV_EXCL_BR_LINE
        return;
    }
    callback->MarkStale();
    ExtensionManagerClient::GetInstance().DisconnectAbility(callback->AsObject());
}

bool EnterpriseConnManager::RequeueAndReconnect(const std::string& bundleName, const std::string& abilityName,
    int32_t userId, const std::string& key, std::shared_ptr<ICallbackStrategy> strategy)
{
    EDMLOGI("RequeueAndReconnect: requeue strategy code=%{public}u for %{public}s",
        strategy->GetCode(), bundleName.c_str());
    sptr<EnterpriseConnectionCallback> oldCallback;
    {
        std::lock_guard<std::mutex> lock(connectionMutex_);
        auto it = connectionMap_.find(key);
        if (it == connectionMap_.end()) { // LCOV_EXCL_BR_LINE
            EDMLOGE("RequeueAndReconnect: connection not found for %{public}s", bundleName.c_str());
            return false;
        }
        auto& info = it->second;
        info.proxy = nullptr;
        info.isPending = true;
        info.createTime = GetCurrentTimeMs();
        info.pendingCallbacks.push_back(strategy);
        oldCallback = info.callback;
        EDMLOGI("RequeueAndReconnect: requeued for %{public}s, pendingCallbacks=%{public}zu",
            bundleName.c_str(), info.pendingCallbacks.size());
    }
    if (oldCallback != nullptr) {
        DisconnectStaleCallback(oldCallback);
    }
    return EstablishConnection(bundleName, abilityName, userId);
}
} // namespace EDM
} // namespace OHOS