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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_BUNDLEMANAGER_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_BUNDLEMANAGER_PLUGIN_H

#include <bundle_mgr_interface.h>
#include <vector>
#include "iplugin_template.h"

namespace OHOS {
namespace EDM {
class BundleManagerPlugin {
public:
    void SetAppInstallControlRuleType(AppExecFwk::AppInstallControlRuleType controlRuleType);
    virtual ErrCode BundleSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData, int32_t userId);
    virtual ErrCode BundleGetPolicy(const std::vector<std::string> &bundles, MessageParcel &reply);
    virtual ErrCode BundleRemovePolicy(std::vector<std::string> &data, std::vector<std::string> &currentData, int32_t userId);
    virtual void BundleAdminRemoveDone(const std::string &adminName, std::vector<std::string> &data, int32_t userId);

    sptr<AppExecFwk::IAppControlMgr> GetAppControlProxy();
private:
    AppExecFwk::AppInstallControlRuleType controlRuleType_ = AppExecFwk::AppInstallControlRuleType::UNSPECIFIED;

};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_BUNDLEMANAGER_PLUGIN_H
