/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_APN_INFO_UTILS_H
#define INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_APN_INFO_UTILS_H

#include <tuple>

#include "message_parcel.h"

namespace OHOS {
namespace EDM {

const int32_t APNINFO_APNNAME_IND = 0;
const int32_t APNINFO_APN_IND = 1;
const int32_t APNINFO_MCC_IND = 2;
const int32_t APNINFO_MNC_IND = 3;
const int32_t APNINFO_USER_IND = 4;
const int32_t APNINFO_TYPE_IND = 5;
const int32_t APNINFO_PROXY_IND = 6;
const int32_t APNINFO_MMSPROXY_IND = 7;

using ApnInfo = std::tuple<std::string /*apnName*/, std::string /*apn*/, std::string /*mcc*/, std::string /*mnc*/, std::string /*user*/,
    std::string /*type*/, std::string /*proxy*/, std::string /*mmsproxy*/>;

class ApnInfoParcel {
public:
    ApnInfoParcel() = default;
    explicit ApnInfoParcel(ApnInfo info);

    ApnInfo GetInfo() const;

    bool Marshalling(MessageParcel& parcel) const;

    static bool Unmarshalling(MessageParcel& parcel, ApnInfoParcel& apnInfoParcel);

private:
    ApnInfo info_;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_APN_INFO_UTILS_H
