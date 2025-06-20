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

#ifndef SERVICES_EDM_INCLUDE_UTILS_ARRAY_INT_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_ARRAY_INT_SERIALIZER_H

#include "ipolicy_serializer.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
/*
 * Policy data serializer of type std::vector<int32_t>.
 */
class ArrayIntSerializer : public IPolicySerializer<std::vector<int32_t>>, public DelayedSingleton<ArrayIntSerializer> {
public:
    std::vector<int32_t> SetUnionPolicyData(std::vector<int32_t> &data, std::vector<int32_t> &currentData);
    std::vector<int32_t> SetDifferencePolicyData(std::vector<int32_t> &data,
        std::vector<int32_t> &currentData);
    bool Deserialize(const std::string &jsonString, std::vector<int32_t> &dataObj) override;

    bool Serialize(const std::vector<int32_t> &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, std::vector<int32_t> &result) override;

    bool WritePolicy(MessageParcel &reply, std::vector<int32_t> &result) override;

    bool MergePolicy(std::vector<std::vector<int32_t>> &data, std::vector<int32_t> &result) override;

private:
    void Deduplication(std::vector<int32_t> &dataObj);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_ARRAY_INT_SERIALIZER_H
