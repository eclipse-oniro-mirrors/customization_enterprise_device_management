/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "clipboard_policy_query.h"

#include "clipboard_policy_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string ClipboardPolicyQuery::GetPolicyName()
{
    return "clipboard_policy";
}

std::string ClipboardPolicyQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return "ohos.permission.ENTERPRISE_MANAGE_SECURITY";
}

ErrCode ClipboardPolicyQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("ClipboardPolicyQuery OnGetPolicy.");
    int32_t tokenId = data.ReadInt32();
    std::string policy = policyData;
    if (tokenId != 0) {
        std::map<int32_t, ClipboardPolicy> policyMap;
        if (!ClipboardSerializer::GetInstance()->Deserialize(policyData, policyMap)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        std::map<int32_t, ClipboardPolicy> resultMap;
        resultMap[tokenId] = policyMap[tokenId];
        ClipboardSerializer::GetInstance()->Serialize(resultMap, policy);
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(policy);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS