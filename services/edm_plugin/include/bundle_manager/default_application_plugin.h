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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_BUNDLE_MANAGER_DEFAULT_APPLICATION_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_BUNDLE_MANAGER_DEFAULT_APPLICATION_PLUGIN_H

#include "bundle_mgr_interface.h"
#include "default_app_interface.h"
#include "external_manager_factory.h"
#include "iplugin.h"

namespace OHOS {
namespace EDM {
class DefaultApplicationPlugin : public IPlugin {
public:
    DefaultApplicationPlugin();

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

protected:
    virtual sptr<AppExecFwk::IBundleMgr> GetBundleMgrProxy();
    virtual sptr<AppExecFwk::IDefaultApp> GetDefaultAppProxy();
    virtual ErrCode QueryModuleName(const std::string &bundleName, const std::string &abilityName,
        int32_t accountId, std::string &moduleName);

private:
    std::shared_ptr<IExternalManagerFactory> externalManagerFactory_ = std::make_shared<ExternalManagerFactory>();
    static ErrCode ConvertAppType(int32_t type, std::string &appType);
    ErrCode CheckAccountId(int32_t accountId);
    ErrCode InnerSetDefaultApplication(const std::string &appType, const std::string &bundleName,
        const std::string &abilityName, int32_t accountId);
    ErrCode InnerGetDefaultApplicationBundleName(const std::string &appType, int32_t accountId,
        std::string &bundleName);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_BUNDLE_MANAGER_DEFAULT_APPLICATION_PLUGIN_H
