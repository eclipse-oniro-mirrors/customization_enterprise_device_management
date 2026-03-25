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

#ifndef COMMON_NATIVE_INCLUDE_BLUETOOTH_PROTOCOL_MODELS_H
#define COMMON_NATIVE_INCLUDE_BLUETOOTH_PROTOCOL_MODELS_H

#include <map>

namespace OHOS {
namespace EDM {
enum class BtProtocol {
    GATT = 0,
    SPP = 1,
    OPP = 2,
};

enum class TransferPolicy {
    SEND_ONLY = 0,
    RECEIVE_ONLY = 1,
    RECEIVE_SEND = 2,
};

namespace BluetoothPolicyType {
    constexpr int32_t SET_DISALLOWED_PROTOCOLS = 1;
    constexpr int32_t SET_DISALLOWED_PROTOCOLS_WITH_POLICY = 2;
}

struct BluetoothProtocolPolicy {
    std::map<int32_t, std::vector<std::string>> protocolDenyList;
    std::map<int32_t, std::vector<std::string>> protocolRecDenyList;
};
}
}
#endif // COMMON_NATIVE_INCLUDE_BLUETOOTH_PROTOCOL_MODELS_H


