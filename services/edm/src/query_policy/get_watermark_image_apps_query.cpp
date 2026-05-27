/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "get_watermark_image_apps_query.h"

#include "edm_log.h"
#include "message_parcel.h"
#include "watermark_image_serializer.h"

namespace OHOS {
namespace EDM {
std::string GetWatermarkImageAppsQuery::GetPolicyName()
{
    return PolicyName::POLICY_WATERMARK_IMAGE_POLICY;
}

std::string GetWatermarkImageAppsQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
}

ErrCode GetWatermarkImageAppsQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::map<std::pair<std::string, int32_t>, WatermarkImageType> watermarkData;
    auto serializer = WatermarkImageSerializer::GetInstance();
    if (!serializer->Deserialize(policyData, watermarkData)) {
        EDMLOGE("GetWatermarkImageAppsQuery::QueryPolicy deserialize failed");
        reply.WriteInt32(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t accountId = data.ReadInt32();
    if (accountId <= 0) {
        EDMLOGE("GetWatermarkImageAppsQuery::QueryPolicy accountId param error");
        reply.WriteInt32(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::vector<std::string> bundleNames;
    for (const auto &item : watermarkData) {
        if (item.first.second == accountId) {
            bundleNames.push_back(item.first.first);
        }
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteStringVector(bundleNames);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS