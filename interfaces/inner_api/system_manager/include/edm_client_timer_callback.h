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

#ifndef INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_EDM_CLIENT_TIMER_CALLBACK_H
#define INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_EDM_CLIENT_TIMER_CALLBACK_H

#include <cstdint>
#include <map>
#include <mutex>
#include <utility>
#include <vector>

#include "i_timer_callback.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace EDM {
class EdmClientTimerCallback : public IRemoteStub<ITimerCallback> {
public:
    EdmClientTimerCallback() = default;
    ~EdmClientTimerCallback() override;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnTimerTriggered(uint64_t timerId) override;

    void InsertCallback(uint64_t timerId, napi_env env, napi_ref ref);
    void RemoveCallback(uint64_t timerId);
    void ClearAll();

private:
    struct CallbackInfo {
        napi_env env = nullptr;
        napi_ref ref = nullptr;
    };
    std::map<uint64_t, CallbackInfo> callbackMap_;
    std::mutex mutex_;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_EDM_CLIENT_TIMER_CALLBACK_H
