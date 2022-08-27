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
#include "disablesuperadmin_fuzzer.h"

using namespace OHOS::EDM;
namespace OHOS {
    bool fuzzDisableSuperAdmin(const uint8_t* data, size_t size)
    {
        if (size != 1) {
            return false;
        }

        auto enterpriseDeviceManager = EnterpriseDeviceMgrProxy::GetInstance();
        if (enterpriseDeviceManager == nullptr) {
            return false;
        }

        std::string bundleName(reinterpret_cast<const char*>(data), size);
        enterpriseDeviceManager->DisableSuperAdmin(bundleName);
        return true;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::fuzzDisableSuperAdmin(data, size);
    return 0;
}