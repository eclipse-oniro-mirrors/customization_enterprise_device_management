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
#ifndef COMMON_FUZZER_INCLUDE_COMMON_FUZZER_TEST_H
#define COMMON_FUZZER_INCLUDE_COMMON_FUZZER_TEST_H

#include <iostream>

#include "message_parcel.h"

namespace OHOS {
namespace EDM {
static constexpr uint32_t BINARY_DECISION_DIVISOR = 2;
static constexpr uint32_t OPERATE_TYPE_DIVISOR = 3;
static constexpr uint32_t INTERFACE_CODE_DIVISOR = 3100;
class CommonFuzzer {
public:
    static void OnRemoteRequestFuzzerTest(uint32_t code, const uint8_t* data, size_t size, MessageParcel &parcel);
    static void SetParcelContent(MessageParcel &parcel, const uint8_t* data, size_t size);
    static uint32_t GetU32Data(const uint8_t* ptr);
    static int32_t GetU32Data(const uint8_t* ptr, int32_t& pos, size_t size);
    static long GetLong(const uint8_t* ptr, int32_t& pos, size_t size);
    static std::string GetString(const uint8_t* ptr, int32_t& pos, int32_t stringSize, size_t size);
};
} // namespace EDM
} // namespace OHOS
#endif // COMMON_FUZZER_INCLUDE_COMMON_FUZZER_TEST_H