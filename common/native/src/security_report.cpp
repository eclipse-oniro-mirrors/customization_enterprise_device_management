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

#include "security_report.h"
#include "edm_log.h"
#include "nlohmann/json.hpp"
#ifdef SECURITY_GUARDE_ENABLE
#include "event_info.h"
#include "sg_collect_client.h"
#endif

namespace OHOS {
namespace EDM {

void SecurityReport::ReportSecurityInfo(const std::string &bundleName, const std::string &abilityName,
    const std::string &policyName)
{
#ifdef SECURITY_GUARDE_ENABLE
    const int64_t EVENT_ID = 1011015013; // 1011015013: report event id
    using namespace Security::SecurityGuard;
    nlohmann::json callPkgJson = nlohmann::json {
        {"bundleName", bundleName},
        {"abilityName", abilityName},
    };
    nlohmann::json jsonResult;
    jsonResult["type"] = 0; // default
    jsonResult["subType"] = 0; // default
    jsonResult["caller"] = callPkgJson;
    jsonResult["objectInfo"] = policyName;
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>(EVENT_ID, "1.0", jsonResult.dump());
    int32_t ret = OHOS::Security::SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    if (ret != ERR_OK) {
        EDMLOGE("SecurityReport::ReportSecurityInfo ret: %{public}d", ret);
    }
#endif
}
} // namespace EDM
} // namespace OHOS