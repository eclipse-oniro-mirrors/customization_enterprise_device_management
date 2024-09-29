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

#include "battery_utils.h"

#ifdef BATTERY_MANAGER_EDM_ENABLE
#include "battery_srv_client.h"
#endif
#include "edm_log.h"
#include "edm_os_account_manager_impl.h"

namespace OHOS {
namespace EDM {
const std::string BatteryUtils::PLUGGED_TYPE_AC = "ac";
const std::string BatteryUtils::PLUGGED_TYPE_DC = "dc";

std::string BatteryUtils::GetBatteryPluggedType()
{
#ifdef BATTERY_MANAGER_EDM_ENABLE
    auto pluggedType = PowerMgr::BatterySrvClient::GetInstance().GetPluggedType();
    EDMLOGD("BatteryUtils GetBatteryPluggedType pluggedType = %{public}d", pluggedType);
    if ((pluggedType == PowerMgr::BatteryPluggedType::PLUGGED_TYPE_AC) ||
        (pluggedType == PowerMgr::BatteryPluggedType::PLUGGED_TYPE_USB) ||
        (pluggedType == PowerMgr::BatteryPluggedType::PLUGGED_TYPE_WIRELESS)) {
        return PLUGGED_TYPE_AC;
    } else {
        return PLUGGED_TYPE_DC;
    }
#else
    return PLUGGED_TYPE_DC;
#endif
}

std::string BatteryUtils::GetSubUserTableUri()
{
    std::string userId = std::to_string(GetCurrentUserId());
    std::string subUserTableUri =
        "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_" + userId + "?Proxy=true";
    return subUserTableUri;
}

int32_t BatteryUtils::GetCurrentUserId()
{
    std::vector<int32_t> ids;
    ErrCode ret = std::make_shared<EdmOsAccountManagerImpl>()->QueryActiveOsAccountIds(ids);
    if (FAILED(ret) || ids.empty()) {
        EDMLOGE("BatteryUtils GetCurrentUserId failed");
        return -1;
    }
    EDMLOGD("BatteryUtils GetCurrentUserId user id = %{public}d", ids.at(0));
    return (ids.at(0));
}
} // namespace EDM
} // namespace OHOS