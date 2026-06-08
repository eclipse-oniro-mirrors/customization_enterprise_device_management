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

#include "hisysevent_c.h"
#include "parameters.h"

#include "edm_log.h"

namespace OHOS {
namespace EDM {
using namespace OHOS::HiviewDFX;
const std::string EDM_ENTERPRISE_ID = "persist.edm.enterprise_id";
void HiSysEventAdapter::ReportEdmEvent(ReportType reportType, const std::string &apiName, const std::string &msgInfo)
{
    EDMLOGI("hisysevent ReportEdmEvent");
    int ret;
    if (reportType == ReportType::EDM_FUNC_FAILED) {
        HiSysEventParam params[] = {
            {.name = "APINAME", .t = HiSysEventParamType::HISYSEVENT_STRING,
                .v = { .s = const_cast<char*>(apiName.c_str()) }, .arraySize = 0},
            {.name = "MSG", .t = HiSysEventParamType::HISYSEVENT_STRING,
                .v = { .s = const_cast<char*>(msgInfo.c_str()) }, .arraySize = 0}
        };
        ret = OH_HiSysEvent_Write("CUST_EDM", "EDM_FUNC_FAILED",
            HiSysEventEventType::HISYSEVENT_FAULT, params, sizeof(params) / sizeof(params[0]));
    } else {
        HiSysEventParam params[] = {
            {.name = "APINAME", .t = HiSysEventParamType::HISYSEVENT_STRING,
                .v = { .s = const_cast<char*>(apiName.c_str()) }, .arraySize = 0}
        };
        ret = OH_HiSysEvent_Write("CUST_EDM", "EDM_FUNC_EVENT",
            HiSysEventEventType::HISYSEVENT_STATISTIC, params, sizeof(params) / sizeof(params[0]));
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
    HiSysEventParam params[] = {
        {.name = "BUNDLENAME", .t = HiSysEventParamType::HISYSEVENT_STRING,
            .v = { .s = const_cast<char*>(bundleName.c_str()) }, .arraySize = 0},
        {.name = "ACTION", .t = HiSysEventParamType::HISYSEVENT_INT32,
            .v = { .i32 = action }, .arraySize = 0},
        {.name = "ADMINTYPE", .t = HiSysEventParamType::HISYSEVENT_INT32,
            .v = { .i32 = adminType }, .arraySize = 0},
        {.name = "EXTRAINFO", .t = HiSysEventParamType::HISYSEVENT_STRING,
            .v = { .s = const_cast<char*>(extraInfo.c_str()) }, .arraySize = 0},
        {.name = "ENTERPRISE_ID", .t = HiSysEventParamType::HISYSEVENT_STRING,
            .v = { .s = const_cast<char*>(enterpriseId.c_str()) }, .arraySize = 0}
    };
    int ret = OH_HiSysEvent_Write("CUST_EDM", "EDM_FUNC_EVENT",
        HiSysEventEventType::HISYSEVENT_STATISTIC, params, sizeof(params) / sizeof(params[0]));
    if (ret != 0) {
        EDMLOGE("hisysevent write manager admin failed! ret %{public}d", ret);
    }
}

bool HiSysEventAdapter::ReportInstalledBundleInfo(const std::string &installedInfo)
{
    EDMLOGI("hisysevent ReportInstalledBundleInfo");
    HiSysEventParam params[] = {
        {.name = "INSTALLED_INFO", .t = HiSysEventParamType::HISYSEVENT_STRING,
            .v = { .s = const_cast<char*>(installedInfo.c_str()) }, .arraySize = 0}
    };
    int ret = OH_HiSysEvent_Write("CUST_EDM", "EDM_INSTALLED_BUNDLE_INFO",
        HiSysEventEventType::HISYSEVENT_STATISTIC, params, sizeof(params) / sizeof(params[0]));
    if (ret != 0) {
        EDMLOGE("hisysevent write installed bundle info failed! ret %{public}d", ret);
        return false;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS