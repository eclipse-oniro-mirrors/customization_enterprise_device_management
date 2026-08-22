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

#include "edm_client_timer_callback.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "ipc_skeleton.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace EDM {
namespace {
    constexpr uint32_t COMMAND_ON_TIMER_TRIGGERED = 1;
}

EdmClientTimerCallback::~EdmClientTimerCallback()
{
    ClearAll();
}

void EdmClientTimerCallback::ClearAll()
{
    EDMLOGI("EdmClientTimerCallback::ClearAll");
    std::vector<std::pair<napi_env, napi_ref>> refsToRelease;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto &[timerId, info] : callbackMap_) {
            if (info.env != nullptr && info.ref != nullptr) {
                refsToRelease.emplace_back(info.env, info.ref);
            }
        }
        callbackMap_.clear();
    }
    for (const auto &item : refsToRelease) {
        napi_env env = item.first;
        napi_ref ref = item.second;
        auto task = [env, ref]() {
            napi_delete_reference(env, ref);
        };
        napi_status status = napi_send_event(env, task, napi_eprio_immediate, "edm:systemTimer");
        if (status != napi_ok) {
            EDMLOGE("EdmClientTimerCallback::ClearAll napi_send_event failed");
        }
    }
}

int32_t EdmClientTimerCallback::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    if (code == COMMAND_ON_TIMER_TRIGGERED) {
        std::u16string descriptor = data.ReadInterfaceToken();
        if (descriptor != ITimerCallback::GetDescriptor()) {
            EDMLOGE("EdmClientTimerCallback::OnRemoteRequest descriptor mismatch");
            return static_cast<int32_t>(EdmReturnErrCode::PARAM_ERROR);
        }
        if (IPCSkeleton::GetCallingUid() != EdmConstants::EDM_UID) {
            EDMLOGE("EdmClientTimerCallback::OnRemoteRequest caller is not edm sa");
            return static_cast<int32_t>(EdmReturnErrCode::PERMISSION_DENIED);
        }
        uint64_t timerId = data.ReadUint64();
        OnTimerTriggered(timerId);
        return ERR_OK;
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

void EdmClientTimerCallback::OnTimerTriggered(uint64_t timerId)
{
    EDMLOGI("EdmClientTimerCallback::OnTimerTriggered timerId=%{public}llu", static_cast<unsigned long long>(timerId));
    napi_env env = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = callbackMap_.find(timerId);
        if (it == callbackMap_.end()) {
            EDMLOGW("EdmClientTimerCallback::OnTimerTriggered timerId not found");
            return;
        }
        env = it->second.env;
    }
    if (env == nullptr) {
        EDMLOGE("EdmClientTimerCallback::OnTimerTriggered env is null");
        return;
    }
    // Do not capture napi_ref here: it could be released by a concurrently
    // queued RemoveCallback/ClearAll task before this task runs, causing UAF.
    // Look up the ref on the JS thread at execution time so the map is the
    // single serialization point (use and delete both run on the JS thread).
    auto task = [this, env, timerId]() {
        napi_ref ref = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = callbackMap_.find(timerId);
            if (it == callbackMap_.end()) {
                EDMLOGW("EdmClientTimerCallback::OnTimerTriggered timerId already removed");
                return;
            }
            ref = it->second.ref;
        }
        if (ref == nullptr) {
            EDMLOGE("EdmClientTimerCallback::OnTimerTriggered ref is null");
            return;
        }
        napi_value undefined = nullptr;
        napi_get_undefined(env, &undefined);
        napi_value callback = nullptr;
        napi_get_reference_value(env, ref, &callback);
        if (callback != nullptr) {
            napi_value result = nullptr;
            napi_call_function(env, undefined, callback, 0, nullptr, &result);
        }
    };
    napi_status status = napi_send_event(env, task, napi_eprio_immediate, "edm:systemTimer");
    if (status != napi_ok) {
        EDMLOGE("EdmClientTimerCallback::OnTimerTriggered napi_send_event failed");
    }
}

void EdmClientTimerCallback::InsertCallback(uint64_t timerId, napi_env env, napi_ref ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callbackMap_[timerId] = {env, ref};
}

void EdmClientTimerCallback::RemoveCallback(uint64_t timerId)
{
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = callbackMap_.find(timerId);
        if (it != callbackMap_.end()) {
            env = it->second.env;
            ref = it->second.ref;
            callbackMap_.erase(it);
        }
    }
    if (env == nullptr || ref == nullptr) {
        return;
    }
    auto task = [env, ref]() {
        napi_delete_reference(env, ref);
    };
    napi_status status = napi_send_event(env, task, napi_eprio_immediate, "edm:systemTimer");
    if (status != napi_ok) {
        EDMLOGE("EdmClientTimerCallback::RemoveCallback napi_send_event failed");
    }
}
} // namespace EDM
} // namespace OHOS
