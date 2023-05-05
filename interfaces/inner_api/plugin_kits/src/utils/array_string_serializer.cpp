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

#include "array_string_serializer.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {
ArrayStringSerializer::ArrayStringSerializer()
{
    serializerInner_ = StringSerializer::GetInstance();
}

ArrayStringSerializer::~ArrayStringSerializer()
{
    if (serializerInner_ != nullptr) {
        serializerInner_.reset();
        serializerInner_ = nullptr;
    }
}

std::vector<std::string> ArrayStringSerializer::SetUnionPolicyData(std::vector<std::string> &data,
    std::vector<std::string> &currentData)
{
    std::vector<std::string> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_union(data.begin(), data.end(), currentData.begin(), currentData.end(), back_inserter(mergeData));
    return mergeData;
}

std::vector<std::string> ArrayStringSerializer::SetDifferencePolicyData(std::vector<std::string> &data,
    std::vector<std::string> &currentData)
{
    std::vector<std::string> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData));
    return mergeData;
}
} // namespace EDM
} // namespace OHOS