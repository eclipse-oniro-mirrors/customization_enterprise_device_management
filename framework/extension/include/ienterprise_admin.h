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

#ifndef FRAMEWORK_EXTENSION_INCLUDE_IENTERPRISE_ADMIN_H_
#define FRAMEWORK_EXTENSION_INCLUDE_IENTERPRISE_ADMIN_H_

#include <iremote_broker.h>
#include <string_ex.h>

namespace OHOS {
namespace EDM {
class IEnterpriseAdmin : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.EDM.IEnterpriseAdmin");
    /**
     * @brief The OnAdminEnabled callback.
     */
    virtual void OnAdminEnabled() = 0;

    /**
     * @brief The OnAdminDisabled callback.
     */
    virtual void OnAdminDisabled() = 0;

    enum {
        COMMAND_ON_ADMIN_ENABLED = 1,
        COMMAND_ON_ADMIN_DISABLED = 2
    };
};
} // namespace EDM
} // namespace OHOS
#endif // FRAMEWORK_EXTENSION_INCLUDE_IENTERPRISE_ADMIN_H_