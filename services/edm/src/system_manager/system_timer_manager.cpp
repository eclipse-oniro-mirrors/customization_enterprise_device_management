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

#include "system_timer_manager.h"

#include <vector>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "edm_timer_info_sa.h"
#include "i_timer_callback.h"
#include "timer_death_recipient.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
namespace {
    constexpr uint32_t COMMAND_ON_TIMER_TRIGGERED = 1;
}
SystemTimerManager* SystemTimerManager::GetInstance()
{
    static SystemTimerManager instance;
    return &instance;
}

SystemTimerManager::~SystemTimerManager()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto timer = MiscServices::TimeServiceClient::GetInstance();
    for (auto &[timerId, entry] : timerMap_) {
        if (timer != nullptr) {
            timer->DestroyTimer(timerId);
        }
    }
    timerMap_.clear();
    recipientMap_.clear();
}

ErrCode SystemTimerManager::CreateTimer(const TimerOptions &options,
    const std::string &adminBundleName, int32_t userId, uint64_t &timerId)
{
    EDMLOGI("SystemTimerManager::CreateTimer admin=%{public}s", adminBundleName.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t count = 0;
    for (auto &[id, entry] : timerMap_) {
        if (entry.adminBundleName == adminBundleName) {
            count++;
        }
    }
    if (count >= EdmConstants::SystemTimer::TIMER_MAX_COUNT_PER_ADMIN) {
        EDMLOGE("SystemTimerManager::CreateTimer max count reached for %{public}s", adminBundleName.c_str());
        return EdmReturnErrCode::SYSTEM_TIMER_MAX_COUNT_REACHED;
    }

    auto timerInfo = std::make_shared<EdmTimerInfoSa>(0);
    timerInfo->SetType(EdmConstants::SystemTimer::DEFAULT_TIMER_TYPE);
    timerInfo->SetRepeat(options.repeat);
    timerInfo->SetInterval(options.interval);
    timerInfo->SetName(options.name);
    timerInfo->SetTriggerCallback(
        [this](uint64_t id) { OnTimerTriggered(id); });

    auto timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        EDMLOGE("SystemTimerManager::CreateTimer TimeServiceClient is nullptr");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    timerId = timer->CreateTimer(timerInfo);
    if (timerId == 0) {
        EDMLOGE("SystemTimerManager::CreateTimer CreateTimer failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    timerInfo->SetTimerId(timerId);

    TimerEntry entry;
    entry.adminBundleName = adminBundleName;
    entry.clientCallback = options.clientCallback;
    if (options.clientCallback != nullptr) {
        GetOrCreateDeathRecipientLocked(options.clientCallback);
    }
    timerMap_[timerId] = entry;
    EDMLOGI("SystemTimerManager::CreateTimer success timerId=%{public}llu", static_cast<unsigned long long>(timerId));
    return ERR_OK;
}

ErrCode SystemTimerManager::StartTimer(uint64_t timerId, uint64_t triggerTime,
    const std::string &adminBundleName)
{
    EDMLOGI("SystemTimerManager::StartTimer timerId=%{public}llu", static_cast<unsigned long long>(timerId));
    if (!IsTimerOwner(timerId, adminBundleName)) {
        return EdmReturnErrCode::SYSTEM_TIMER_NOT_FOUND;
    }
    auto timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t ret = timer->StartTimerV9(timerId, triggerTime);
    if (ret != 0) {
        EDMLOGE("SystemTimerManager::StartTimer failed ret=%{public}d", ret);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}

ErrCode SystemTimerManager::StopTimer(uint64_t timerId, const std::string &adminBundleName)
{
    EDMLOGI("SystemTimerManager::StopTimer timerId=%{public}llu", static_cast<unsigned long long>(timerId));
    if (!IsTimerOwner(timerId, adminBundleName)) {
        return EdmReturnErrCode::SYSTEM_TIMER_NOT_FOUND;
    }
    auto timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t ret = timer->StopTimerV9(timerId);
    if (ret != 0) {
        EDMLOGE("SystemTimerManager::StopTimer failed ret=%{public}d", ret);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}

ErrCode SystemTimerManager::DestroyTimer(uint64_t timerId, const std::string &adminBundleName)
{
    EDMLOGI("SystemTimerManager::DestroyTimer timerId=%{public}llu", static_cast<unsigned long long>(timerId));
    if (!IsTimerOwner(timerId, adminBundleName)) {
        return EdmReturnErrCode::SYSTEM_TIMER_NOT_FOUND;
    }
    auto timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer != nullptr) {
        timer->DestroyTimerV9(timerId);
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        CleanupTimerLocked(timerId);
    }
    return ERR_OK;
}

void SystemTimerManager::OnTimerTriggered(uint64_t timerId)
{
    EDMLOGI("SystemTimerManager::OnTimerTriggered timerId=%{public}llu", static_cast<unsigned long long>(timerId));
    sptr<IRemoteObject> clientCallback = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = timerMap_.find(timerId);
        if (it == timerMap_.end()) {
            EDMLOGW("SystemTimerManager::OnTimerTriggered timerId not found");
            return;
        }
        clientCallback = it->second.clientCallback;
    }
    if (clientCallback == nullptr || clientCallback->IsObjectDead()) {
        EDMLOGW("SystemTimerManager::OnTimerTriggered client is dead, cleanup");
        {
            std::lock_guard<std::mutex> lock(mutex_);
            CleanupTimerLocked(timerId);
        }
        auto timer = MiscServices::TimeServiceClient::GetInstance();
        if (timer != nullptr) {
            timer->DestroyTimerV9(timerId);
        }
        return;
    }
    MessageParcel timerData;
    timerData.WriteInterfaceToken(ITimerCallback::GetDescriptor());
    timerData.WriteUint64(timerId);
    MessageParcel timerReply;
    MessageOption option(MessageOption::TF_ASYNC);
    clientCallback->SendRequest(COMMAND_ON_TIMER_TRIGGERED, timerData, timerReply, option);
}

void SystemTimerManager::OnRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    EDMLOGI("SystemTimerManager::OnRemoteDied");
    sptr<IRemoteObject> clientCallback = remoteObject.promote();
    if (clientCallback == nullptr) {
        return;
    }
    std::vector<uint64_t> timerIds;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = timerMap_.begin(); it != timerMap_.end();) {
            if (it->second.clientCallback == clientCallback) {
                EDMLOGI("SystemTimerManager::OnRemoteDied cleanup timerId=%{public}llu",
                    static_cast<unsigned long long>(it->first));
                timerIds.push_back(it->first);
                it = timerMap_.erase(it);
            } else {
                ++it;
            }
        }
        recipientMap_.erase(clientCallback.GetRefPtr());
    }
    auto timer = MiscServices::TimeServiceClient::GetInstance();
    for (auto id : timerIds) {
        if (timer != nullptr) {
            timer->DestroyTimerV9(id);
        }
    }
}

void SystemTimerManager::OnAdminRemove(const std::string &adminBundleName)
{
    EDMLOGI("SystemTimerManager::OnAdminRemove admin=%{public}s", adminBundleName.c_str());
    std::vector<uint64_t> timerIds;
    std::vector<sptr<IRemoteObject>> callbacksToCheck;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = timerMap_.begin(); it != timerMap_.end();) {
            if (it->second.adminBundleName == adminBundleName) {
                EDMLOGI("SystemTimerManager::OnAdminRemove cleanup timerId=%{public}llu",
                    static_cast<unsigned long long>(it->first));
                timerIds.push_back(it->first);
                callbacksToCheck.push_back(it->second.clientCallback);
                it = timerMap_.erase(it);
            } else {
                ++it;
            }
        }
        for (auto &cb : callbacksToCheck) {
            ReleaseRecipientIfUnusedLocked(cb);
        }
    }
    auto timer = MiscServices::TimeServiceClient::GetInstance();
    for (auto id : timerIds) {
        if (timer != nullptr) {
            timer->DestroyTimerV9(id);
        }
    }
}

bool SystemTimerManager::IsTimerOwner(uint64_t timerId, const std::string &adminBundleName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = timerMap_.find(timerId);
    if (it == timerMap_.end()) {
        return false;
    }
    return it->second.adminBundleName == adminBundleName;
}

void SystemTimerManager::CleanupTimerLocked(uint64_t timerId)
{
    auto it = timerMap_.find(timerId);
    if (it == timerMap_.end()) {
        return;
    }
    sptr<IRemoteObject> clientCallback = it->second.clientCallback;
    timerMap_.erase(it);
    ReleaseRecipientIfUnusedLocked(clientCallback);
}

sptr<TimerDeathRecipient> SystemTimerManager::GetOrCreateDeathRecipientLocked(
    const sptr<IRemoteObject> &clientCallback)
{
    if (clientCallback == nullptr) {
        return nullptr;
    }
    auto it = recipientMap_.find(clientCallback.GetRefPtr());
    if (it != recipientMap_.end()) {
        return it->second;
    }
    sptr<TimerDeathRecipient> recipient = new (std::nothrow) TimerDeathRecipient();
    if (recipient == nullptr) {
        EDMLOGE("SystemTimerManager::GetOrCreateDeathRecipientLocked new failed");
        return nullptr;
    }
    clientCallback->AddDeathRecipient(recipient);
    recipientMap_[clientCallback.GetRefPtr()] = recipient;
    return recipient;
}

void SystemTimerManager::ReleaseRecipientIfUnusedLocked(const sptr<IRemoteObject> &clientCallback)
{
    if (clientCallback == nullptr) {
        return;
    }
    for (auto &[id, entry] : timerMap_) {
        if (entry.clientCallback == clientCallback) {
            return;
        }
    }
    auto recIt = recipientMap_.find(clientCallback.GetRefPtr());
    if (recIt == recipientMap_.end()) {
        return;
    }
    if (recIt->second != nullptr) {
        clientCallback->RemoveDeathRecipient(recIt->second);
    }
    recipientMap_.erase(recIt);
}

ErrCode SystemTimerManager::HandleCreateTimerOperation(const std::string &adminBundleName,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    bool repeat = data.ReadBool();
    uint64_t interval = data.ReadUint64();
    std::string name = data.ReadString();
    if (name.length() > EdmConstants::SystemTimer::TIMER_NAME_MAX_LEN) {
        EDMLOGE("HandleCreateTimerOperation: name too long");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (repeat && (interval < EdmConstants::SystemTimer::TIMER_INTERVAL_MIN_MS ||
        interval > EdmConstants::SystemTimer::TIMER_INTERVAL_MAX_MS)) {
        EDMLOGE("HandleCreateTimerOperation: interval out of range");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    auto clientCallback = data.ReadRemoteObject();
    if (clientCallback == nullptr) {
        EDMLOGE("HandleCreateTimerOperation: clientCallback is null");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    TimerOptions options;
    options.repeat = repeat;
    options.interval = interval;
    options.name = name;
    options.clientCallback = clientCallback;
    uint64_t timerId = 0;
    ErrCode ret = CreateTimer(options, adminBundleName, userId, timerId);
    if (FAILED(ret)) {
        return ret;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteUint64(timerId);
    return ERR_OK;
}

ErrCode SystemTimerManager::HandleTimerOperation(uint32_t funcCode, const std::string &adminBundleName,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    int32_t opTypeRaw = static_cast<int32_t>(TimerOperationType::CREATE);
    if (!data.ReadInt32(opTypeRaw)) {
        EDMLOGE("HandleTimerOperation: read operationType failed");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    EDMLOGI("HandleTimerOperation funcCode=%{public}u opType=%{public}d admin=%{public}s",
        funcCode, opTypeRaw, adminBundleName.c_str());
    switch (static_cast<TimerOperationType>(opTypeRaw)) {
        case TimerOperationType::CREATE:
            return HandleCreateTimerOperation(adminBundleName, data, reply, userId);
        case TimerOperationType::START: {
            uint64_t timerId = data.ReadUint64();
            uint64_t triggerTime = data.ReadUint64();
            if (triggerTime == 0) {
                EDMLOGE("HandleTimerOperation: triggerTime must be positive");
                return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
            }
            return StartTimer(timerId, triggerTime, adminBundleName);
        }
        case TimerOperationType::STOP: {
            uint64_t timerId = data.ReadUint64();
            return StopTimer(timerId, adminBundleName);
        }
        case TimerOperationType::DESTROY: {
            uint64_t timerId = data.ReadUint64();
            return DestroyTimer(timerId, adminBundleName);
        }
        default:
            EDMLOGE("HandleTimerOperation: unknown operationType=%{public}d", opTypeRaw);
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
}
} // namespace EDM
} // namespace OHOS
