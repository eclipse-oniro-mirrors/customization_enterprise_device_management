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

#include "bundle_install_plugin.h"

#include <system_ability_definition.h>

#include "app_control/app_control_proxy.h"
#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_sys_manager.h"

namespace OHOS {
namespace EDM {
void BundleInstallPlugin::SetAppInstallControlRuleType(AppExecFwk::AppInstallControlRuleType controlRuleType)
{
    controlRuleType_ = controlRuleType;
}

ErrCode BundleInstallPlugin::OnSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
    int32_t userId)
{
    if (data.empty()) {
        EDMLOGW("BundleInstallPlugin OnSetPolicy data is empty.");
        return ERR_OK;
    }

    std::vector<std::string> mergeData = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(data, currentData);

    if (mergeData.size() > EdmConstants::APPID_MAX_SIZE) {
        EDMLOGE("BundleInstallPlugin OnSetPolicy data is too large.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    auto appControlProxy = GetAppControlProxy();
    if (!appControlProxy) {
        EDMLOGE("BundleInstallPlugin OnSetPolicy GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode res = appControlProxy->AddAppInstallControlRule(data, controlRuleType_, userId);
    if (res != ERR_OK) {
        EDMLOGE("BundleInstallPlugin OnSetPolicyDone Faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = mergeData;
    return ERR_OK;
}

ErrCode BundleInstallPlugin::GetBundlePolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::vector<std::string> bundles;
    ArrayStringSerializer::GetInstance()->Deserialize(policyData, bundles);
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(bundles.size());
    reply.WriteStringVector(bundles);
    return ERR_OK;
}

ErrCode BundleInstallPlugin::OnRemovePolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
    int32_t userId)
{
    if (data.empty()) {
        EDMLOGW("BundleInstallPlugin OnRemovePolicy data is empty.");
        return ERR_OK;
    }

    std::vector<std::string> mergeData =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(data, currentData);
    auto appControlProxy = GetAppControlProxy();
    if (!appControlProxy) {
        EDMLOGE("BundleInstallPlugin OnRemovePolicy GetAppControlProxy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode res = appControlProxy->DeleteAppInstallControlRule(controlRuleType_, data, userId);
    if (res != ERR_OK) {
        EDMLOGE("BundleInstallPlugin DeleteAppInstallControlRule OnRemovePolicy faild %{public}d:", res);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = mergeData;
    return ERR_OK;
}

void BundleInstallPlugin::OnAdminRemoveDone(const std::string &adminName, std::vector<std::string> &data,
    int32_t userId)
{
    EDMLOGI("AllowedInstallBundlesPlugin OnAdminRemoveDone adminName : %{public}s userId : %{public}d",
        adminName.c_str(), userId);
    auto appControlProxy = GetAppControlProxy();
    if (!appControlProxy) {
        EDMLOGE("BundleInstallPlugin OnAdminRemoveDone GetAppControlProxy failed.");
        return;
    }
    ErrCode res = appControlProxy->DeleteAppInstallControlRule(controlRuleType_, data, userId);
    EDMLOGD("BundleInstallPlugin OnAdminRemoveDone result %{public}d:", res);
}

sptr<AppExecFwk::IAppControlMgr> BundleInstallPlugin::GetAppControlProxy()
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    return proxy->GetAppControlProxy();
}
} // namespace EDM
} // namespace OHOS
