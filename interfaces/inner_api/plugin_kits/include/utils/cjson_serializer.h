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

#ifndef SERVICES_EDM_INCLUDE_UTILS_CJSON_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_CJSON_SERIALIZER_H

#include "ipolicy_serializer.h"
#include "singleton.h"
#include "cJSON.h"

namespace OHOS {
namespace EDM {
/*
 * Policy data serializer of type cJSON.
 */
class CjsonSerializer : public IPolicySerializer<cJSON*>, public DelayedSingleton<CjsonSerializer> {
public:
    bool Deserialize(const std::string &jsonString, cJSON* &dataObj) override;

    bool Serialize(cJSON *const &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, cJSON* &result) override;

    bool WritePolicy(MessageParcel &reply, cJSON* &result) override;

    bool MergePolicy(std::vector<cJSON*> &data, cJSON* &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_CJSON_SERIALIZER_H
