/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_UTILS_HTTP_PROXY_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_HTTP_PROXY_SERIALIZER_H

#include "http_proxy.h"
#include "ipolicy_serializer.h"
#include "json/json.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
/*
 * Policy data serializer of type http proxy.
 */
class HttpProxySerializer : public IPolicySerializer<OHOS::NetManagerStandard::HttpProxy>,
                            public DelayedSingleton<HttpProxySerializer> {
public:
    bool Deserialize(const std::string &jsonString, OHOS::NetManagerStandard::HttpProxy &dataObj) override;

    bool Serialize(const OHOS::NetManagerStandard::HttpProxy &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, OHOS::NetManagerStandard::HttpProxy &result) override;

    bool WritePolicy(MessageParcel &reply, OHOS::NetManagerStandard::HttpProxy &result) override;

    bool MergePolicy(std::vector<OHOS::NetManagerStandard::HttpProxy> &data,
        OHOS::NetManagerStandard::HttpProxy &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_HTTP_PROXY_SERIALIZER_H
