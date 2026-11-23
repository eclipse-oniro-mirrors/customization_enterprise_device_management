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

#ifndef SERVICES_EDM_INCLUDE_CONNECTION_APP_SERVICE_CONNECTION_MANAGER_H
#define SERVICES_EDM_INCLUDE_CONNECTION_APP_SERVICE_CONNECTION_MANAGER_H

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "app_service_connection_stub.h"
#include "caller_info.h"
#include "i_edm_connection_callback.h"
#include "iremote_object.h"
#include "want.h"

namespace OHOS {
namespace EDM {
class AppServiceConnectionManager {
public:
    static AppServiceConnectionManager& GetInstance();

    int32_t ConnectAppServiceExtensionAbilityByOsAccount(const AAFwk::Want &want, int32_t accountId,
        const sptr<IEdmConnectionCallback> &callback, const std::string &adminBundleName,
        std::shared_ptr<AAFwk::IndirectCallerInfo> indirectCallerInfo, int32_t &connectionId);
    int32_t DisconnectAppServiceExtensionAbility(int32_t connectionId);
    void OnAdminRemoved(const std::string &adminBundleName);

private:
    AppServiceConnectionManager() = default;
    ~AppServiceConnectionManager() = default;
    DISALLOW_COPY_AND_MOVE(AppServiceConnectionManager);

    struct ConnectionRecord {
        sptr<AppServiceConnectionStub> stub;
        sptr<IEdmConnectionCallback> callback;
        std::string adminBundleName;
        int32_t accountId;
    };

    std::recursive_mutex mutex_;
    std::map<int32_t, ConnectionRecord> connectionMap_;
    std::atomic<int32_t> nextConnectionId_ {1};
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_CONNECTION_APP_SERVICE_CONNECTION_MANAGER_H
