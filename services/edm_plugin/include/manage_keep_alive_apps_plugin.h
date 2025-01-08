/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_KEEP_ALIVE_APPS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_KEEP_ALIVE_APPS_PLUGIN_H

#include "ability_manager_interface.h"
#include "bundle_mgr_interface.h"
#include "message_parcel.h"
#include "iplugin.h"
#include "iremote_stub.h"

#include "basic_array_string_plugin.h"

namespace OHOS {
namespace EDM {
class ManageKeepAliveAppsPlugin : public IPlugin, public BasicArrayStringPlugin {
public:
    ManageKeepAliveAppsPlugin();
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override{};
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
        const std::string &mergeJsonData, int32_t userId) override;
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override {};
    ErrCode GetOthersMergePolicyData(const std::string &adminName,
        std::string &othersMergePolicyData) override;

private:
    ErrCode SetOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
        std::vector<std::string> &failedData) override;
    ErrCode RemoveOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
        std::vector<std::string> &failedData) override;
    ErrCode AddKeepAliveApps(std::vector<std::string> &keepAliveApps, int32_t userId);
    ErrCode RemoveKeepAliveApps(std::vector<std::string> &keepAliveApps, int32_t userId);
    void ParseErrCode(ErrCode &ret);
    void GetErrorMessage(ErrCode &errCode, std::string &errMessage);
    sptr<AAFwk::IAbilityManager> GetAbilityManager();
    sptr<AppExecFwk::IAppControlMgr> GetAppControlProxy();
};
} // namespace EDM
} // namespace OHOS

#endif /* SERVICES_EDM_PLUGIN_INCLUDE_MANAGE_KEEP_ALIVE_APPS_PLUGIN_H */
