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

#include "http_proxy_serializer.h"

namespace OHOS {
namespace EDM {
bool HttpProxySerializer::Deserialize(const std::string &jsonString, NetManagerStandard::HttpProxy &config)
{
    return true;
}

bool HttpProxySerializer::Serialize(const NetManagerStandard::HttpProxy &config, std::string &jsonString)
{
    return true;
}

bool HttpProxySerializer::GetPolicy(MessageParcel &data, NetManagerStandard::HttpProxy &httpProxy)
{
    return OHOS::NetManagerStandard::HttpProxy::Unmarshalling(data, httpProxy);
}

bool HttpProxySerializer::WritePolicy(MessageParcel &reply, NetManagerStandard::HttpProxy &result)
{
    return true;
}

bool HttpProxySerializer::MergePolicy(std::vector<NetManagerStandard::HttpProxy> &data,
    NetManagerStandard::HttpProxy &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS