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

#include "snapshot_skip_query.h"

#include "array_string_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string SnapshotSkipQuery::GetPolicyName()
{
    return "snapshot_skip";
}

std::string SnapshotSkipQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS";
}

ErrCode SnapshotSkipQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("SnapshotSkipQuery OnGetPolicy policyData :");
    std::vector<std::string> bundles;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData, bundles);
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(bundles.size());
    reply.WriteStringVector(bundles);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS