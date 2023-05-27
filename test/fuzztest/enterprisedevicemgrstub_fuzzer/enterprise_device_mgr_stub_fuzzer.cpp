/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define FUZZ_PROJECT_NAME "enterprise_device_mgr_stub_fuzzer"

#include <system_ability_definition.h>

#include "edm_sys_manager.h"
#include "ienterprise_device_mgr.h"
#include "parcel.h"
#include "utils.h"

namespace OHOS {
namespace EDM {
constexpr size_t MAX_SIZE = 1024;
constexpr size_t MIN_SIZE = 4;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size > MAX_SIZE || size < MIN_SIZE) {
        return 0;
    }

    uint32_t code = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    MessageParcel parcel;
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgr::GetDescriptor());
    parcel.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;

    TEST::Utils::SetEdmServiceEnable();
    auto remote = EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    if (remote == nullptr) {
        return 0;
    }
    remote->SendRequest(code, parcel, reply, option);

    TEST::Utils::SetEdmServiceDisable();
    return 0;
}
} // namespace EDM
} // namespace OHOS

