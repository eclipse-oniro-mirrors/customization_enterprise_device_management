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

#include "ent_info.h"
#include "parcel.h"
#include "entinfo_fuzzer.h"

using namespace OHOS::EDM;
namespace OHOS {
    bool fuzzEntInfo(const uint8_t* data, size_t size)
    {
        Parcel dataMessageParcel;
        EntInfo entInfo;
        entInfo.enterpriseName = reinterpret_cast<const char*>(data);
        auto ent = EntInfo::Unmarshalling(dataMessageParcel);
        return ent != nullptr;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::fuzzEntInfo(data, size);
    return 0;
}