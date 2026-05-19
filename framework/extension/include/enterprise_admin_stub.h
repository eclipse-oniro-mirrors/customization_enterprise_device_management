/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <functional>
#include <unordered_map>

#include "ienterprise_admin.h"

namespace OHOS {
namespace EDM {
class EnterpriseAdminStub : public IRemoteStub<IEnterpriseAdmin> {
public:
    EnterpriseAdminStub();

    virtual ~EnterpriseAdminStub();

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    using HandleFunc = std::function<bool(uint32_t code, MessageParcel& data, MessageParcel& reply)>;

    int32_t CallFuncByCode(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption &option);

    void InitHandleFuncMap();
    void InitAdminHandleFuncs();
    void InitBundleHandleFuncs();
    void InitAppHandleFuncs();
    void InitAccountHandleFuncs();
    void InitKioskHandleFuncs();
    void InitOtherHandleFuncs();

    bool OnAdminInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnBundleInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnAppInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnSystemUpdateInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnAccountInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnKioskModeInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnMarketAppsInstallStatusChangedInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnDeviceAdminInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnLogCollectedInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnKeyEventInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnStartupGuideCompletedInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnDeviceBootCompletedInner(uint32_t code, MessageParcel& data, MessageParcel& reply);
    bool OnAdminPolicyChangedInner(uint32_t code, MessageParcel& data, MessageParcel& reply);

    std::unordered_map<uint32_t, HandleFunc> handleFuncMap_;
};
} // namespace EDM
} // namespace OHOS
#endif // FRAMEWORK_EXTENSION_INCLUDE_ENTERPRISE_ADMIN_STUB_H

