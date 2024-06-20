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

#ifndef SERVICES_EDM_INCLUDE_UTILS_DISALLOW_FOR_ACCOUNT_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_DISALLOW_FOR_ACCOUNT_SERIALIZER_H

#include "fingerprint_policy.h"
#include "ipolicy_serializer.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
class FingerprintPolicySerializer : public IPolicySerializer<FingerprintPolicy>,
    public DelayedSingleton<FingerprintPolicySerializer> {
public:
    bool Deserialize(const std::string &jsonString, FingerprintPolicy &dataObj) override;

    bool Serialize(const FingerprintPolicy &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, FingerprintPolicy &result) override;

    bool WritePolicy(MessageParcel &reply, FingerprintPolicy &result) override;

    bool MergePolicy(std::vector<FingerprintPolicy> &data, FingerprintPolicy &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_DISALLOW_FOR_ACCOUNT_SERIALIZER_H