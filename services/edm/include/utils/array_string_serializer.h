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

#ifndef SERVICES_EDM_INCLUDE_UTILS_ARRAY_STRING_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_ARRAY_STRING_SERIALIZER_H

#include "ipolicy_serializer.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
/*
 * Policy data serializer of type std::vector<std::string>.
 */
class ArrayStringSerializer : public ArraySerializer<std::string, std::vector<std::string>>,
    public DelayedSingleton<ArrayStringSerializer> {
public:
    ArrayStringSerializer();
    ~ArrayStringSerializer() override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_ARRAY_STRING_SERIALIZER_H
