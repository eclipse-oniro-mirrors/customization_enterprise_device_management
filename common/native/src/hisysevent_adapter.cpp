/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "hisysevent_adapter.h"

#include "hisysevent.h"
#include "edm_log.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
using namespace OHOS::HiviewDFX;
const std::string EDM_ENTERPRISE_ID = "persist.edm.enterprise_id";
void HiSysEventAdapter::ReportEdmEvent(ReportType reportType, const std::string &apiName, const std::string &msgInfo)
{
    EDMLOGI("hisysevent ReportEdmEvent");
    int ret;
    if (reportType == ReportType::EDM_FUNC_FAILED) {
        ret = HiSysEventWrite(HiSysEvent::Domain::CUSTOMIZATION_EDM, "EDM_FUNC_FAILED", HiSysEvent::EventType::FAULT,
            "APINAME", apiName, "MSG", msgInfo);
    } else {
        ret = HiSysEventWrite(HiSysEvent::Domain::CUSTOMIZATION_EDM, "EDM_FUNC_EVENT", HiSysEvent::EventType::STATISTIC,
            "APINAME", apiName);
    }

    if (ret != 0) {
        EDMLOGE("hisysevent write failed! ret %{public}d, apiName %{public}s, errMsg %{public}s", ret,
            apiName.c_str(), msgInfo.c_str());
    }
}

void HiSysEventAdapter::ReportEdmEventManagerAdmin(const std::string &bundleName, const int32_t &action,
    const int32_t & adminType, const std::string &extraInfo)
{
    EDMLOGI("hisysevent ReportEdmEventManagerAdmin");
    std::string enterpriseId = system::GetParameter(EDM_ENTERPRISE_ID, "");
    int ret = HiSysEventWrite(HiSysEvent::Domain::CUSTOMIZATION_EDM, "EDM_FUNC_EVENT", HiSysEvent::EventType::STATISTIC,
        "BUNDLENAME", bundleName, "ACTION", action, "ADMINTYPE", adminType, "EXTRAINFO", extraInfo,
        "ENTERPRISE_ID", enterpriseId);
    if (ret != 0) {
        EDMLOGE("hisysevent write manager admin failed! ret %{public}d", ret);
    }
}

void HiSysEventAdapter::ReportInstalledBundleInfo(const std::string &adminName, const std::string &installedBundleName,
    InstalledBundleType installedBundleType)
{
    EDMLOGI("hisysevent ReportInstalledBundleInfo");
    int ret = HiSysEventWrite(HiSysEvent::Domain::CUSTOMIZATION_EDM, "EDM_FUNC_EVENT", HiSysEvent::EventType::STATISTIC,
        "MDM_BUNDLE_NAME", adminName, "INSTALLED_BUNDLE_NAME", installedBundleName,
        "INSTALLED_BUNDLE_TYPE", static_cast<int32_t>(installedBundleType));
    if (ret != 0) {
        EDMLOGE("hisysevent write installed bundle info failed! ret %{public}d", ret);
    }
}
} // namespace EDM
} // namespace OHOS
