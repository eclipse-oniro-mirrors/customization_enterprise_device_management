/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#define FUZZ_PROJECT_NAME "enterprise_device_mgr_stub_mock_fuzzer"

#include "edm_ipc_interface_code.h"
#include "common_fuzzer.h"
#include "func_code.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 6;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }

    uint32_t code = (CommonFuzzer::GetU32Data(data)) % 3100;
    if (code == EdmInterfaceCode::RESET_FACTORY || code == EdmInterfaceCode::SHUTDOWN ||
        code == EdmInterfaceCode::REBOOT || code == EdmInterfaceCode::USB_READ_ONLY ||
        code == EdmInterfaceCode::DISABLED_HDC || code == EdmInterfaceCode::DISABLE_USB) {
        return 0;
    }
    uint32_t funcFlag = data[4] % 2;
    uint32_t operateType = data[5] % 3;
    code = CREATE_FUNC_CODE(funcFlag, operateType, code);

    MessageParcel parcel;
    CommonFuzzer::SetParcelContent(parcel, data, size);
    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
    return 0;
}
} // namespace EDM
} // namespace OHOS
