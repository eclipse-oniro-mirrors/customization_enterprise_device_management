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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_AUTO_START_APPS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_AUTO_START_APPS_PLUGIN_H

#include "ability_manager_interface.h"
#include "bundle_mgr_interface.h"
#include "message_parcel.h"
#include "iplugin.h"
#include "iremote_stub.h"
#include "manage_auto_start_app_info.h"

namespace OHOS {
namespace EDM {
class ManageAutoStartAppsPlugin : public IPlugin {
public:
    ManageAutoStartAppsPlugin();
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

private:
    ErrCode SetOrRemoveOtherModulePolicy(const std::vector<ManageAutoStartAppInfo> &data, bool isSet,
        std::vector<ManageAutoStartAppInfo> &failedData, int32_t userId);
    ErrCode OnSetPolicy(std::vector<std::string> &data, bool disallowModify,
        std::vector<ManageAutoStartAppInfo> &currentData, std::vector<ManageAutoStartAppInfo> &mergeData,
        int32_t userId);
    ErrCode OnRemovePolicy(std::vector<std::string> &data,
        std::vector<ManageAutoStartAppInfo> &currentData, std::vector<ManageAutoStartAppInfo> &mergeData,
        int32_t userId);
    ErrCode SetOtherModulePolicy(const std::vector<std::string> &keepAliveApps,
        int32_t userId, std::vector<ManageAutoStartAppInfo> &failedData, bool disallowModify);
    bool CheckBundleAndAbilityExited(const std::string &bundleName, const std::string &abilityName, int32_t userId);
    uint32_t maxListSize_ = 0;
};
} // namespace EDM
} // namespace OHOS

#endif /* SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_AUTO_START_APPS_PLUGIN_H */