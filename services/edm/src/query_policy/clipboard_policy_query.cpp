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
#include "edm_bundle_manager_impl.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string ClipboardPolicyQuery::GetPolicyName()
{
    return PolicyName::POLICY_CLIPBOARD_POLICY;
}

std::string ClipboardPolicyQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
}

ErrCode ClipboardPolicyQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("ClipboardPolicyQuery OnGetPolicy");
    std::string policy = policyData;
    std::map<int32_t, ClipboardInfo> policyMap;
    if (!ClipboardSerializer::GetInstance()->Deserialize(policyData, policyMap)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::map<int32_t, ClipboardInfo> resultMap;
    int32_t flag = data.ReadInt32();
    ClipboardInfo info;
    if (flag == ClipboardFunctionType::GET_HAS_TOKEN_ID) {
        int32_t tokenId = data.ReadInt32();
        auto it = policyMap.find(tokenId);
        if (it != policyMap.end()) {
            resultMap[tokenId] = policyMap[it->first];
        } else {
            info = {ClipboardPolicy::DEFAULT, -1, ""};
            resultMap[tokenId] = info;
        }
        ClipboardSerializer::GetInstance()->Serialize(resultMap, policy);
    }
    if (flag == ClipboardFunctionType::GET_HAS_BUNDLE_NAME) {
        info.bundleName = data.ReadString();
        info.userId = data.ReadInt32();
        auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
        int32_t tokenId = bundleMgr->GetTokenId(info.bundleName, info.userId);
        auto it = policyMap.find(tokenId);
        if (it != policyMap.end()) {
            resultMap[tokenId] = policyMap[it->first];
        } else {
            info.policy = ClipboardPolicy::DEFAULT;
            resultMap[tokenId] = info;
        }
        ClipboardSerializer::GetInstance()->Serialize(resultMap, policy);
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(policy);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS