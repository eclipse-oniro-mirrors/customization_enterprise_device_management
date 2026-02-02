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

#ifndef INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_I_EXTERNAL_MODULE_ADAPTER_H
#define INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_I_EXTERNAL_MODULE_ADAPTER_H

#include <string>

#include "errors.h"

#include "update_policy_info.h"

namespace OHOS {
namespace EDM {
class IExternalModuleAdapter {
public:
    virtual ~IExternalModuleAdapter() = default;
    
    virtual ErrCode NotifyUpgradePackages(const UpgradePackageInfo &packagesInfo, std::string &errorMsg)
    {
        return ERR_OK;
    }

    virtual ErrCode SetUpdatePolicy(const UpdatePolicy &updatePolicy, std::string &errorMsg)
    {
        return ERR_OK;
    }

    virtual std::string GetCallingBundleName()
    {
        return "";
    }
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_PLUGIN_KITS_INCLUDE_I_EXTERNAL_MODULE_ADAPTER_H
