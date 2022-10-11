/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORK_EXTENSION_INCLUDE_IENTERPRISE_ADMIN_H
#define FRAMEWORK_EXTENSION_INCLUDE_IENTERPRISE_ADMIN_H

#include <iremote_broker.h>
#include <string_ex.h>

namespace OHOS {
namespace EDM {
class IEnterpriseAdmin : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.EDM.IEnterpriseAdmin");

    virtual void OnAdminEnabled() = 0;

    virtual void OnAdminDisabled() = 0;

    /**
     * Called when a new application package has been installed on the device.
     * @param bundleName Indicates the name of the bundle whose state has been installed.
     */
    virtual void OnBundleAdded(const std::string &bundleName) = 0;

    /**
     * Called when a new application package has been Removed on the device.
     * @param bundleName Indicates the name of the bundle whose state has been Removed.
     */
    virtual void OnBundleRemoved(const std::string &bundleName) = 0;

    enum {
        COMMAND_ON_ADMIN_ENABLED = 1,
        COMMAND_ON_ADMIN_DISABLED = 2,
        COMMAND_ON_BUNDLE_ADDED = 3,
        COMMAND_ON_BUNDLE_REMOVED = 4
    };
};
} // namespace EDM
} // namespace OHOS
#endif // FRAMEWORK_EXTENSION_INCLUDE_IENTERPRISE_ADMIN_H