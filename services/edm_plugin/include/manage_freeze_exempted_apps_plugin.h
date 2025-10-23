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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_FREEZE_EXEMPTED_APPS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_FREEZE_EXEMPTED_APPS_PLUGIN_H

#include "ability_manager_interface.h"
#include "bundle_mgr_interface.h"
#include "message_parcel.h"
#include "iplugin.h"
#include "iremote_stub.h"
#include "manage_freeze_exempted_apps_info.h"
#include "application_instance.h"

namespace OHOS {
namespace EDM {
class ManageFreezeExemptedAppsPlugin : public IPlugin {
public:
    ManageFreezeExemptedAppsPlugin();
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override{};
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
        const std::string &mergeJsonData, int32_t userId) override;
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override {};
    void OnOtherServiceStart(int32_t systemAbilityId) override;
    ErrCode GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
        std::string &othersMergePolicyData) override;

private:
    ErrCode RemoveOtherModulePolicy();
    ErrCode OnSetPolicy(std::vector<ApplicationMsg> &freezeExemptedApps,
        std::vector<ManageFreezeExemptedAppInfo> &currentData, std::vector<ManageFreezeExemptedAppInfo> &mergeData);
    ErrCode OnRemovePolicy(std::vector<ApplicationMsg> &freezeExemptedApps,
        std::vector<ManageFreezeExemptedAppInfo> &currentData, std::vector<ManageFreezeExemptedAppInfo> &mergeData);
    ErrCode SetOtherModulePolicy(const std::vector<ApplicationMsg> &freezeExemptedApps);
    std::vector<ManageFreezeExemptedAppInfo> FilterUninstalledBundle(std::vector<ManageFreezeExemptedAppInfo> &data);
    std::string SerializeApplicationInstanceVectorToJson(const std::vector<ApplicationMsg> &apps);
    uint32_t maxListSize_ = 0;
};
} // namespace EDM
} // namespace OHOS

#endif /* SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_FREEZE_EXEMPTED_APPS_PLUGIN_H */
