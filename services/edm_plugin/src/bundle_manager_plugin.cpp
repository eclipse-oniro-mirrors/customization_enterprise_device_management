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

#include "bundle_manager_plugin.h"
#include <ipc_skeleton.h>
#include <system_ability_definition.h>

#include "app_control/app_control_proxy.h"
#include "array_string_serializer.h"
#include "edm_errors.h"
#include "edm_sys_manager.h"
#include "policy_info.h"

namespace OHOS {
namespace EDM {
constexpr int32_t MAX_SIZE = 200;

void BundleManagerPlugin::SetAppInstallControlRuleType(AppExecFwk::AppInstallControlRuleType controlRuleType)
{
    controlRuleType_ = controlRuleType;
}

ErrCode BundleManagerPlugin::BundleSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
    int32_t userId)
{
    if (data.empty()) {
        EDMLOGW("BundleManagerPlugin OnSetPolicy data is empty:");
        return ERR_OK;
    }

    std::vector<std::string> mergeData = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(data, currentData);

    if (mergeData.size() > MAX_SIZE) {
        EDMLOGE("BundleManagerPlugin OnSetPolicy data is too large:");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    ErrCode res = GetAppControlProxy()->
        AddAppInstallControlRule(data, controlRuleType_, userId);
    if (res != ERR_OK) {
        EDMLOGE("BundleManagerPlugin OnSetPolicyDone Faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = mergeData;
    return ERR_OK;
}

ErrCode BundleManagerPlugin::BundleGetPolicy(const std::vector<std::string> &bundles, MessageParcel &reply)
{
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(bundles.size());
    reply.WriteStringVector(bundles);
    return ERR_OK;
}

ErrCode BundleManagerPlugin::BundleRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, int32_t userId)
{
    if (data.empty()) {
        EDMLOGW("BundleManagerPlugin OnRemovePolicy data is empty:");
        return ERR_OK;
    }

    std::vector<std::string> mergeData = ArrayStringSerializer::GetInstance()->
        SetDifferencePolicyData(data, currentData);
    ErrCode res = GetAppControlProxy()->
        DeleteAppInstallControlRule(controlRuleType_, data, userId);
    if (res != ERR_OK) {
        EDMLOGE("BundleManagerPlugin DeleteAppInstallControlRule OnRemovePolicy faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = mergeData;
    return ERR_OK;
}

sptr<AppExecFwk::IAppControlMgr> BundleManagerPlugin::GetAppControlProxy()
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    return proxy->GetAppControlProxy();
}

void BundleManagerPlugin::BundleAdminRemoveDone(const std::string &adminName, std::vector<std::string> &data,
    int32_t userId)
{
    ErrCode res = GetAppControlProxy()->
        DeleteAppInstallControlRule(controlRuleType_, data, userId);
    EDMLOGI("BundleManagerPlugin OnAdminRemoveDone result %{public}d:", res);
}
} // namespace EDM
} // namespace OHOS
