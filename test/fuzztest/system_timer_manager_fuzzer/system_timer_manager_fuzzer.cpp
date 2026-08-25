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

#define FUZZ_PROJECT_NAME "system_timer_manager_fuzzer"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "get_data_template.h"
#include "message_parcel.h"
#include "utils.h"

#define private public
#define protected public
#include "system_timer_manager.h"
#undef protected
#undef private

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 32;
constexpr int32_t FUZZ_MAX_STRING = 64;
constexpr int32_t TIMER_OP_TYPE_COUNT =
    static_cast<int32_t>(TimerOperationType::DESTROY) + 1;
constexpr size_t OP_TYPE_SELECTOR_INDEX = 0;
constexpr size_t INITIAL_POS_OFFSET = 1;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}

std::string GetFuzzString()
{
    if (g_data == nullptr || g_pos >= g_size) {
        return "";
    }
    size_t remaining = g_size - g_pos;
    size_t strLen = remaining < static_cast<size_t>(FUZZ_MAX_STRING) ? remaining : FUZZ_MAX_STRING;
    std::string ret(reinterpret_cast<const char*>(g_data + g_pos), strLen);
    g_pos += strLen;
    if (g_pos > g_size) {
        g_pos = 0;
    }
    return ret;
}

void DoFuzzHandleTimerOperation(const uint8_t* data, size_t size)
{
    auto* manager = SystemTimerManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SYSTEM_TIMER_OPERATION);

    int32_t opType = static_cast<int32_t>(data[OP_TYPE_SELECTOR_INDEX] % TIMER_OP_TYPE_COUNT);
    std::string adminBundleName = GetFuzzString();
    int32_t userId = GetData<int32_t>();

    MessageParcel dataParcel;
    MessageParcel reply;

    switch (opType) {
        case static_cast<int32_t>(TimerOperationType::CREATE): {
            bool repeat = GetData<bool>();
            uint64_t interval = GetData<uint64_t>();
            std::string name = GetFuzzString();
            dataParcel.WriteInt32(static_cast<int32_t>(TimerOperationType::CREATE));
            dataParcel.WriteBool(repeat);
            dataParcel.WriteUint64(interval);
            dataParcel.WriteString(name);
            dataParcel.WriteRemoteObject(nullptr);
            break;
        }
        case static_cast<int32_t>(TimerOperationType::START): {
            uint64_t timerId = GetData<uint64_t>();
            uint64_t triggerTime = GetData<uint64_t>();
            dataParcel.WriteInt32(static_cast<int32_t>(TimerOperationType::START));
            dataParcel.WriteUint64(timerId);
            dataParcel.WriteUint64(triggerTime);
            break;
        }
        case static_cast<int32_t>(TimerOperationType::STOP): {
            uint64_t timerId = GetData<uint64_t>();
            dataParcel.WriteInt32(static_cast<int32_t>(TimerOperationType::STOP));
            dataParcel.WriteUint64(timerId);
            break;
        }
        case static_cast<int32_t>(TimerOperationType::DESTROY): {
            uint64_t timerId = GetData<uint64_t>();
            dataParcel.WriteInt32(static_cast<int32_t>(TimerOperationType::DESTROY));
            dataParcel.WriteUint64(timerId);
            break;
        }
        default: {
            int32_t unknownOp = GetData<int32_t>();
            dataParcel.WriteInt32(unknownOp);
            break;
        }
    }
    manager->HandleTimerOperation(funcCode, adminBundleName, dataParcel, reply, userId);
}

void DoFuzzOnTimerTriggered()
{
    auto* manager = SystemTimerManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint64_t timerId = GetData<uint64_t>();
    manager->OnTimerTriggered(timerId);
}

void DoFuzzOnAdminRemove()
{
    auto* manager = SystemTimerManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    std::string adminBundleName = GetFuzzString();
    manager->OnAdminRemove(adminBundleName);
}

void DoFuzzIsTimerOwner()
{
    auto* manager = SystemTimerManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint64_t timerId = GetData<uint64_t>();
    std::string adminBundleName = GetFuzzString();
    manager->IsTimerOwner(timerId, adminBundleName);
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
    g_pos = INITIAL_POS_OFFSET;

    DoFuzzHandleTimerOperation(data, size);
    DoFuzzOnTimerTriggered();
    DoFuzzOnAdminRemove();
    DoFuzzIsTimerOwner();
    return 0;
}
} // namespace EDM
} // namespace OHOS
