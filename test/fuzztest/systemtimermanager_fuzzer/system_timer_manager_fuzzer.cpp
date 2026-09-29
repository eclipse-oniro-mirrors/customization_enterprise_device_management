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

#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "message_parcel.h"
#include "utils.h"

#define private public
#define protected public
#include "system_timer_manager.h"
#undef protected
#undef private

namespace OHOS {
namespace EDM {
constexpr size_t STRING_COUNT = 4;
constexpr size_t INT32_COUNT = 3;
constexpr size_t LONG_COUNT = 4;
constexpr size_t MIN_SIZE = sizeof(int32_t) * INT32_COUNT + sizeof(long) * LONG_COUNT + STRING_COUNT;
constexpr int32_t TIMER_OP_TYPE_COUNT =
    static_cast<int32_t>(TimerOperationType::DESTROY) + 1;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}

void DoFuzzHandleTimerOperation(const uint8_t* data, int32_t& pos, int32_t stringSize, size_t size)
{
    auto* manager = SystemTimerManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SYSTEM_TIMER_OPERATION);
    int32_t opType = CommonFuzzer::GetU32Data(data, pos, size) % TIMER_OP_TYPE_COUNT;
    std::string adminBundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
    int32_t userId = CommonFuzzer::GetU32Data(data, pos, size);

    MessageParcel dataParcel;
    MessageParcel reply;
    switch (opType) {
        case static_cast<int32_t>(TimerOperationType::CREATE): {
            bool repeat = CommonFuzzer::GetU32Data(data, pos, size) % 2;
            uint64_t interval = static_cast<uint64_t>(CommonFuzzer::GetLong(data, pos, size));
            std::string name = CommonFuzzer::GetString(data, pos, stringSize, size);
            dataParcel.WriteInt32(opType);
            dataParcel.WriteBool(repeat);
            dataParcel.WriteUint64(interval);
            dataParcel.WriteString(name);
            dataParcel.WriteRemoteObject(nullptr);
            break;
        }
        case static_cast<int32_t>(TimerOperationType::START): {
            uint64_t timerId = static_cast<uint64_t>(CommonFuzzer::GetLong(data, pos, size));
            uint64_t triggerTime = static_cast<uint64_t>(CommonFuzzer::GetLong(data, pos, size));
            dataParcel.WriteInt32(opType);
            dataParcel.WriteUint64(timerId);
            dataParcel.WriteUint64(triggerTime);
            break;
        }
        case static_cast<int32_t>(TimerOperationType::STOP):
        case static_cast<int32_t>(TimerOperationType::DESTROY): {
            uint64_t timerId = static_cast<uint64_t>(CommonFuzzer::GetLong(data, pos, size));
            dataParcel.WriteInt32(opType);
            dataParcel.WriteUint64(timerId);
            break;
        }
        default: {
            dataParcel.WriteInt32(CommonFuzzer::GetU32Data(data, pos, size));
            break;
        }
    }
    manager->HandleTimerOperation(funcCode, adminBundleName, dataParcel, reply, userId);
}

void DoFuzzOnTimerTriggered(const uint8_t* data, int32_t& pos, size_t size)
{
    auto* manager = SystemTimerManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint64_t timerId = static_cast<uint64_t>(CommonFuzzer::GetLong(data, pos, size));
    manager->OnTimerTriggered(timerId);
}

void DoFuzzOnAdminRemove(const uint8_t* data, int32_t& pos, int32_t stringSize, size_t size)
{
    auto* manager = SystemTimerManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    std::string adminBundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
    manager->OnAdminRemove(adminBundleName);
}

void DoFuzzIsTimerOwner(const uint8_t* data, int32_t& pos, int32_t stringSize, size_t size)
{
    auto* manager = SystemTimerManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint64_t timerId = static_cast<uint64_t>(CommonFuzzer::GetLong(data, pos, size));
    std::string adminBundleName = CommonFuzzer::GetString(data, pos, stringSize, size);
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
    int32_t pos = 0;
    int32_t stringSize = (static_cast<int32_t>(size) - sizeof(int32_t) * INT32_COUNT
        - sizeof(long) * LONG_COUNT) / static_cast<int32_t>(STRING_COUNT);

    DoFuzzHandleTimerOperation(data, pos, stringSize, size);
    DoFuzzOnTimerTriggered(data, pos, size);
    DoFuzzOnAdminRemove(data, pos, stringSize, size);
    DoFuzzIsTimerOwner(data, pos, stringSize, size);
    return 0;
}
} // namespace EDM
} // namespace OHOS
