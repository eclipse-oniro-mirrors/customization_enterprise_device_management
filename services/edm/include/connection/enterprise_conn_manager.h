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

#ifndef SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_CONN_MANAGER_H
#define SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_CONN_MANAGER_H

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "ability_manager_interface.h"
#include "icallback_strategy.h"
#include "enterprise_admin_proxy.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {

class EnterpriseConnManager : public DelayedSingleton<EnterpriseConnManager> {
public:
    bool ExecuteCallback(const std::string& bundleName, const std::string& abilityName, int32_t userId,
        std::shared_ptr<ICallbackStrategy> strategy);
    void SaveProxy(const std::string& bundleName, int32_t userId, const sptr<EnterpriseAdminProxy>& proxy);
    void RemoveRemoteObject(const std::string& bundleName, int32_t userId);
    void ClearConnections();

private:
    struct ConnectionInfo {
        sptr<EnterpriseAdminProxy> proxy;
        std::vector<std::shared_ptr<ICallbackStrategy>> pendingCallbacks;
        bool isPending = false;
        int64_t createTime = 0;
    };

    std::string GenerateConnectionKey(const std::string& bundleName, int32_t userId);
    bool IsConnectionTimeout(const ConnectionInfo& info);
    int64_t GetCurrentTimeMs();
    bool CheckConnectionState(const std::string& key, std::shared_ptr<ICallbackStrategy> strategy,
        sptr<EnterpriseAdminProxy>& existingProxy, bool& needCreateConnection);
    bool PrepareNewConnection(const std::string& key, std::shared_ptr<ICallbackStrategy> strategy);
    bool EstablishConnection(const std::string& bundleName, const std::string& abilityName, int32_t userId);

    std::mutex connectionMutex_;
    std::unordered_map<std::string, ConnectionInfo> connectionMap_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_CONN_MANAGER_H
