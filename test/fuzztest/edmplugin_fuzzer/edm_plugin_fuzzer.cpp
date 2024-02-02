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

#include "edm_plugin_fuzzer.h"

#include "common_fuzzer.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 0;
constexpr uint32_t MAX_EDMEXT_INTERAFCE_CODE = 3100;
constexpr uint32_t MAX_EDM_INTERFACE_CODE = 1100;
constexpr uint32_t MIN_EDMEXT_INTERFACE_CODE = 3000;

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }
    for (uint32_t operateType = static_cast<uint32_t>(FuncOperateType::GET);
         operateType <= static_cast<uint32_t>(FuncOperateType::REMOVE); operateType++) {
        for (uint32_t code = EdmInterfaceCode::SET_DATETIME; code <= MAX_EDM_INTERFACE_CODE; code++) {
            if (code == EdmInterfaceCode::RESET_FACTORY || code == EdmInterfaceCode::SHUTDOWN ||
                code == EdmInterfaceCode::REBOOT || code == EdmInterfaceCode::USB_READ_ONLY ||
                code == EdmInterfaceCode::DISABLED_HDC || code == EdmInterfaceCode::DISABLE_USB) {
                continue;
            }
            code = POLICY_FUNC_CODE(operateType, code);
            MessageParcel parcel;
            CommonFuzzer::SetParcelContent(parcel, data, size);
            CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
        }
        for (uint32_t code = MIN_EDMEXT_INTERFACE_CODE; code <= MAX_EDMEXT_INTERAFCE_CODE; code++) {
            code = POLICY_FUNC_CODE(operateType, code);
            MessageParcel parcel;
            CommonFuzzer::SetParcelContent(parcel, data, size);
            CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
        }
    }
    return 0;
}
} // namespace EDM
} // namespace OHOS