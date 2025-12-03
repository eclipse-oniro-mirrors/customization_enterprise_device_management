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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_USER_NON_STOP_APPS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_USER_NON_STOP_APPS_PLUGIN_H

#include "ability_manager_interface.h"
#include "bundle_mgr_interface.h"
#include "message_parcel.h"
#include "iplugin.h"
#include "iremote_stub.h"
#include "application_instance.h"
#include "session_manager_lite.h"

namespace OHOS {
namespace EDM {
using namespace OHOS::AppExecFwk;
using OHOS::Rosen::SessionManagerLite;
class ManageUserNonStopAppsPlugin : public IPlugin {
public:
    ManageUserNonStopAppsPlugin();
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override{};
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
        const std::string &mergeJsonData, int32_t userId) override;
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override {};
    ErrCode GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
        std::string &othersMergePolicyData) override;
    void OnOtherServiceStart(int32_t systemAbilityId) override;

private:
    ErrCode RemoveOtherModulePolicy(const std::vector<ApplicationInstance> needResetPolicy,
         const std::vector<ApplicationInstance> needRemovePolicy);
    ErrCode OnSetPolicy(std::vector<ApplicationInstance> &data,
        std::vector<ApplicationInstance> &currentData, std::vector<ApplicationInstance> &mergeData);
    ErrCode OnRemovePolicy(std::vector<ApplicationInstance> &data,
        std::vector<ApplicationInstance> &currentData, std::vector<ApplicationInstance> &mergeData);
    ErrCode SetOtherModulePolicy(const std::vector<ApplicationInstance> &userNonStopApps);
    ErrCode ConvertAppPolicyToJsonStr(const ApplicationInstance &userNonStopApps, std::string &appPolicyJsonStr);
    ErrCode ReportLockSession(const std::vector<ApplicationInstance> &userNonStopAppInfo, bool isLocked);
    void GetSessionParam(const ApplicationInstance &userNonStopAppInfo, std::vector<Rosen::AbilityInfoBase> &infoBase);
    ErrCode FilterUninstalledBundle(std::vector<ApplicationInstance> &data,
        std::vector<ApplicationInstance> &uninstalledApp);
    int32_t GetCurrentUserId();
    uint32_t maxListSize_ = 0;
};
} // namespace EDM
} // namespace OHOS

#endif /* SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_USER_NON_STOP_APPS_PLUGIN_H */