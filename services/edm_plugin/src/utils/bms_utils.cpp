/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "bms_utils.h"

#include <system_ability_definition.h>

#include "app_distribution_type.h"
#include "edm_log.h"
#include "edm_sys_manager.h"

namespace OHOS {
namespace EDM {
ErrCode BmsUtils::DealAppRunningRules(const std::vector<std::string> &data, int32_t userId, bool isTrustList,
    bool isAdd)
{
    EDMLOGI("DealAppRunningRules data size = %{public}zu", data.size());
    std::vector<AppExecFwk::AppRunningControlRule> controlRules;
    std::for_each(data.begin(), data.end(), [&](const std::string &str) {
        AppExecFwk::AppRunningControlRule controlRule;
        controlRule.appId = str;
        controlRule.allowRunning = isTrustList;
        controlRules.push_back(controlRule);
    });
    auto bundleManager = BmsUtils::GetIBundleManager();
    if (!bundleManager) {
        EDMLOGE("DealAppRunningRules OnSetPolicy GetIBundleManager failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto appControlProxy = bundleManager->GetAppControlProxy();
    if (!appControlProxy) {
        EDMLOGE("DealAppRunningRules OnSetPolicy GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode res = ERR_OK;
    if (isAdd) {
        res = appControlProxy->AddAppRunningControlRule(controlRules, userId);
    } else {
        res = appControlProxy->DeleteAppRunningControlRule(controlRules, userId);
    }
    if (res != ERR_OK) {
        EDMLOGE("DealAppRunningRules OnSetPolicyDone Faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

sptr<AppExecFwk::IBundleMgr> BmsUtils::GetIBundleManager()
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    return proxy;
}
} // namespace EDM
} // namespace OHOS