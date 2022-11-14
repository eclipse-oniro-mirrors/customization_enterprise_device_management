/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>

#include "enterprise_device_mgr_proxy.h"
#include "parcel.h"
#include "isadminenabled_fuzzer.h"

using namespace OHOS::EDM;
namespace OHOS {
constexpr int32_t MIN_SIZE_NUM = 4;
bool FuzzIsAdminEnabled(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_SIZE_NUM) {
        return false;
    }

    auto enterpriseDeviceManager = EnterpriseDeviceMgrProxy::GetInstance();
    if (enterpriseDeviceManager == nullptr) {
        return false;
    }

    std::string name(reinterpret_cast<const char*>(data), size);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(name);
    admin.SetAbilityName(name);
    int32_t userId = static_cast<int32_t>((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);
    enterpriseDeviceManager->IsAdminEnabled(admin, userId);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::FuzzIsAdminEnabled(data, size);
    return 0;
}