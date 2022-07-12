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

#ifndef SERVICES_EDM_INCLUDE_UTILS_BOOL_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_BOOL_SERIALIZER_H

#include "ipolicy_serializer.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
#define TRUE_VALUE "true"
#define FALSE_VALUE "false"

/*
 * Policy data serializer of type bool.
 */
class BoolSerializer : public IPolicySerializer<bool>, public DelayedSingleton<BoolSerializer> {
public:
    virtual bool Deserialize(const std::string &jsonString, bool &dataObj) override;

    virtual bool Serialize(const bool &dataObj, std::string &jsonString) override;

    virtual bool GetPolicy(MessageParcel &data, bool &result) override;

    virtual bool WritePolicy(MessageParcel &reply, bool &result) override;

    virtual bool MergePolicy(std::vector<bool> &data, bool &result) override;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_UTILS_BOOL_SERIALIZER_H
