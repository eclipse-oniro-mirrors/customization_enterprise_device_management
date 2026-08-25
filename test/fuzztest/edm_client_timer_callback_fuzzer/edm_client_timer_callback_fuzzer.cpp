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

#define FUZZ_PROJECT_NAME "edm_client_timer_callback_fuzzer"

#include "get_data_template.h"
#include "message_parcel.h"
#include "utils.h"

#define private public
#define protected public
#include "edm_client_timer_callback.h"
#include "i_timer_callback.h"
#undef protected
#undef private

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 16;
constexpr uint32_t MAX_TIMER_ID = 10;
constexpr uint32_t BINARY_DECISION_DIVISOR = 2;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }
    g_data = data;
    g_size = size;
    g_pos = 0;

    sptr<EdmClientTimerCallback> callback = new EdmClientTimerCallback();
    if (callback == nullptr) {
        return 0;
    }

    uint32_t code = GetData<uint32_t>();
    uint64_t timerId = GetData<uint64_t>();
    uint64_t insertTimerId = timerId % MAX_TIMER_ID;

    if (code % BINARY_DECISION_DIVISOR == 0) {
        callback->InsertCallback(insertTimerId, nullptr, nullptr);
    }

    MessageParcel dataParcel;
    dataParcel.WriteUint64(timerId);
    MessageParcel reply;
    MessageOption option;
    callback->OnRemoteRequest(code, dataParcel, reply, option);

    callback->OnTimerTriggered(insertTimerId);

    callback->RemoveCallback(insertTimerId);

    if (code % BINARY_DECISION_DIVISOR == 1) {
        callback->InsertCallback(insertTimerId, nullptr, nullptr);
        callback->InsertCallback((insertTimerId + 1) % MAX_TIMER_ID, nullptr, nullptr);
        callback->ClearAll();
    }

    callback = nullptr;
    return 0;
}
} // namespace EDM
} // namespace OHOS
