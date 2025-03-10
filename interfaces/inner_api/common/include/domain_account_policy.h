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

#ifndef INTERFACES_INNER_API_INCLUDE_DOMAIN_ACCOUNT_POLICY_H
#define INTERFACES_INNER_API_INCLUDE_DOMAIN_ACCOUNT_POLICY_H

#include "message_parcel.h"

namespace OHOS {
namespace EDM {
struct DomainAccountPolicy {
    DomainAccountPolicy();
    DomainAccountPolicy(int32_t authenticationValidityPeriod, int32_t passwordValidityPeriod,
        int32_t passwordExpirationNotification);
    ~DomainAccountPolicy();

    int32_t authenticationValidityPeriod = INT32_MIN;
    int32_t passwordValidityPeriod = INT32_MIN;
    int32_t passwordExpirationNotification = INT32_MIN;

    bool ReadFromParcel(MessageParcel &parcel);
    bool Marshalling(MessageParcel &parcel) const;
    static bool Unmarshalling(MessageParcel &parcel, DomainAccountPolicy &domainAccountPolicy);

    bool ConvertDomainAccountPolicyToJsonStr(std::string &jsonStr);
    static bool JsonStrToDomainAccountPolicy(const std::string &jsonStr, DomainAccountPolicy &domainAccountPolicy);

    bool CheckParameterValidity();
    bool IsParameterNeedShow(int32_t param);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_INCLUDE_DOMAIN_ACCOUNT_POLICY_H
