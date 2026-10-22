/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "battery_optimization_util.h"

#include <algorithm>

#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_os_account_manager_impl.h"
#include "enterprise_device_mgr_proxy.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {

namespace {
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
}

ErrCode BatteryOptimizationUtil::GetOptimizationBatteryExclusionApps(std::vector<std::string> &apps)
{
    if (!EnterpriseDeviceMgrProxy::GetInstance()->IsEdmEnabled()) {
        EDMLOGI("BatteryOptimizationUtil: edm not enabled");
        return ERR_OK;
    }

    int32_t accountId = std::make_shared<EdmOsAccountManagerImpl>()->GetCurrentUserId();
    if (accountId < 0) {
        EDMLOGE("BatteryOptimizationUtil: GetCurrentUserId failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("BatteryOptimizationUtil::GetOptimizationBatteryExclusionApps accountId=%{public}d", accountId);

    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(accountId);
    data.WriteInt32(0); // QueryPolicy::SELF

    MessageParcel reply;
    int32_t ret = EnterpriseDeviceMgrProxy::GetInstance()->GetPolicyNew(
        EdmInterfaceCode::OPTIMIZATION_BATTERY_EXCLUSION_APPS, data, reply);
    if (ret != ERR_OK) {
        EDMLOGE("BatteryOptimizationUtil: GetPolicyNew failed, ret=%{public}d", ret);
        return ret;
    }
    reply.ReadStringVector(&apps);
    return ERR_OK;
}

bool BatteryOptimizationUtil::IsOptimizationBatteryExcluded(const std::string &bundleName)
{
    EDMLOGI("BatteryOptimizationUtil::IsOptimizationBatteryExcluded bundleName=%{public}s", bundleName.c_str());

    std::vector<std::string> apps;
    ErrCode ret = GetOptimizationBatteryExclusionApps(apps);
    if (ret != ERR_OK) {
        EDMLOGE("BatteryOptimizationUtil: GetOptimizationBatteryExclusionApps failed, ret=%{public}d", ret);
        return false;
    }
    return std::find(apps.begin(), apps.end(), bundleName) != apps.end();
}

} // namespace EDM
} // namespace OHOS
