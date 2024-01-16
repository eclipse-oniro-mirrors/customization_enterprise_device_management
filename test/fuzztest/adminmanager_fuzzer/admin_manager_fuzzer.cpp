/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "admin_manager_fuzzer.h"

#include "edm_ipc_interface_code.h"
#include "common_fuzzer.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 5;
constexpr uint32_t MIN_INTERAFCE_CODE = 1000;

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }
    for (uint32_t code = EdmInterfaceCode::ADD_DEVICE_ADMIN; code <= EdmInterfaceCode::AUTHORIZE_ADMIN; code++) {
        CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size);
    }
    uint32_t code = ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]) % 3100;
    if (code == EdmInterfaceCode::RESET_FACTORY || code == EdmInterfaceCode::SHUTDOWN ||
        code == EdmInterfaceCode::REBOOT || code == EdmInterfaceCode::USB_READ_ONLY ||
        code == EdmInterfaceCode::DISABLED_HDC || code == EdmInterfaceCode::DISABLE_USB ||
        code < MIN_INTERAFCE_CODE) {
        return 0;
    }
    uint32_t operateType = data[4] % 3;
    code = POLICY_FUNC_CODE(operateType, code);
    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size);
    return 0;
}
} // namespace EDM
} // namespace OHOS