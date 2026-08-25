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

#ifndef SERVICES_EDM_INCLUDE_SYSTEM_MANAGER_SYSTEM_TIMER_MANAGER_H
#define SERVICES_EDM_INCLUDE_SYSTEM_MANAGER_SYSTEM_TIMER_MANAGER_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>

#include "iremote_object.h"
#include "message_parcel.h"
#include "time_service_client.h"

namespace OHOS {
namespace EDM {
class TimerDeathRecipient;

struct TimerOptions {
    bool repeat = false;
    uint64_t interval = 0;
    std::string name;
    sptr<IRemoteObject> clientCallback;
};

struct TimerEntry {
    std::string adminBundleName;
    sptr<IRemoteObject> clientCallback;
};

class SystemTimerManager {
public:
    static SystemTimerManager* GetInstance();

    ErrCode CreateTimer(const TimerOptions &options, const std::string &adminBundleName,
        int32_t userId, uint64_t &timerId);
    ErrCode StartTimer(uint64_t timerId, uint64_t triggerTime, const std::string &adminBundleName);
    ErrCode StopTimer(uint64_t timerId, const std::string &adminBundleName);
    ErrCode DestroyTimer(uint64_t timerId, const std::string &adminBundleName);
    ErrCode HandleTimerOperation(uint32_t funcCode, const std::string &adminBundleName,
        MessageParcel &data, MessageParcel &reply, int32_t userId);
    void OnTimerTriggered(uint64_t timerId);
    void OnRemoteDied(const wptr<IRemoteObject> &remoteObject);
    void OnAdminRemove(const std::string &adminBundleName);
    bool IsTimerOwner(uint64_t timerId, const std::string &adminBundleName);

private:
    SystemTimerManager() = default;
    ~SystemTimerManager();
    void CleanupTimerLocked(uint64_t timerId);
    sptr<TimerDeathRecipient> GetOrCreateDeathRecipientLocked(const sptr<IRemoteObject> &clientCallback);
    void ReleaseRecipientIfUnusedLocked(const sptr<IRemoteObject> &clientCallback);
    ErrCode HandleCreateTimerOperation(const std::string &adminBundleName,
        MessageParcel &data, MessageParcel &reply, int32_t userId);

    std::mutex mutex_;
    std::map<uint64_t, TimerEntry> timerMap_;
    std::map<const IRemoteObject *, sptr<TimerDeathRecipient>> recipientMap_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_SYSTEM_MANAGER_SYSTEM_TIMER_MANAGER_H
