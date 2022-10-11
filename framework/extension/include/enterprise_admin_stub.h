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

#ifndef FRAMEWORK_EXTENSION_INCLUDE_ENTERPRISE_ADMIN_STUB_H
#define FRAMEWORK_EXTENSION_INCLUDE_ENTERPRISE_ADMIN_STUB_H

#include <iremote_stub.h>
#include <map>

#include "ienterprise_admin.h"

namespace OHOS {
namespace EDM {
class EnterpriseAdminStub : public IRemoteStub<IEnterpriseAdmin> {
public:
    EnterpriseAdminStub();

    virtual ~EnterpriseAdminStub();

    /**
     * @brief The OnRemoteRequest callback.
     *
     * @param code The code.
     * @param data The data.
     * @param reply The reply.
     * @param option The option.
     * @return ERR_OK on success, others on failure.
     */
    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
private:
    void AddCallFuncMap();

    void OnAdminEnabledInner(MessageParcel& data, MessageParcel& reply);

    void OnAdminDisabledInner(MessageParcel& data, MessageParcel& reply);

    void OnBundleAddedInner(MessageParcel& data, MessageParcel& reply);

    void OnBundleRemovedInner(MessageParcel& data, MessageParcel& reply);

    using EnterpriseAdminFunc = void (EnterpriseAdminStub::*)(MessageParcel& data, MessageParcel& reply);

    std::map<uint32_t, EnterpriseAdminFunc> memberFuncMap_;
};
} // namespace EDM
} // namespace OHOS
#endif // FRAMEWORK_EXTENSION_INCLUDE_ENTERPRISE_ADMIN_STUB_H

