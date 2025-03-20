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

#include "set_browser_policies_query.h"

#include "bundle_manager_utils.h"
#include "cJSON.h"
#include "cjson_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
const char* const EMPTY_OBJECT_STRING = "{}";
std::string SetBrowserPoliciesQuery::GetPolicyName()
{
    return PolicyName::POLICY_SET_BROWSER_POLICIES;
}

std::string SetBrowserPoliciesQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return "";
}

ErrCode SetBrowserPoliciesQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("SetBrowserPoliciesQuery query policy");
    std::string appId = data.ReadString();
    if (appId.empty() && FAILED(BundleManagerUtils::GetAppIdByCallingUid(appId))) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (policyData.empty()) {
        policyData = EMPTY_OBJECT_STRING;
    }
    cJSON *policies = nullptr;
    auto serializer = CjsonSerializer::GetInstance();
    if (!serializer->Deserialize(policyData, policies)) {
        EDMLOGE("SetBrowserPoliciesQuery OnGetPolicy Deserialize error!");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string retString;
    cJSON *policy = cJSON_GetObjectItem(policies, appId.c_str());
    if (policy != nullptr) {
        serializer->Serialize(policy, retString);
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(retString);
    cJSON_Delete(policies);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS