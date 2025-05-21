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

#ifndef INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_CLIPBOARD_POLICY_SERIALIZER_H
#define INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_CLIPBOARD_POLICY_SERIALIZER_H

#include <map>
#include "clipboard_info.h"
#include "clipboard_policy.h"
#include "ipolicy_serializer.h"

namespace OHOS {
namespace EDM {

const std::string TOKEN_ID = "tokenId";
const std::string USER_ID = "userId";
const std::string BUNDLE_NAME = "bundleName";
const std::string CLIPBOARD_POLICY_STR = "clipboardPolicy";

/*
 * Policy data serializer of type int.
 */
class ClipboardSerializer : public IPolicySerializer<std::map<int32_t, ClipboardInfo>>,
    public DelayedSingleton<ClipboardSerializer> {
public:

    bool Deserialize(const std::string &policy, std::map<int32_t, ClipboardInfo> &dataObj) override;

    bool Serialize(const std::map<int32_t, ClipboardInfo> &dataObj, std::string &policy) override;

    bool GetPolicy(MessageParcel &data, std::map<int32_t, ClipboardInfo> &result) override;

    bool WritePolicy(MessageParcel &reply, std::map<int32_t, ClipboardInfo> &result) override;

    bool MergePolicy(std::vector<std::map<int32_t, ClipboardInfo>> &data,
        std::map<int32_t, ClipboardInfo> &result) override;

private:
    ClipboardPolicy ConvertToClipboardPolicy(int32_t policy);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_CLIPBOARD_POLICY_SERIALIZER_H
