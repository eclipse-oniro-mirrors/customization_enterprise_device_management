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

#ifndef EDM_UNIT_TEST_ENTERPRISE_ADMIN_STUB_MOCK_H
#define EDM_UNIT_TEST_ENTERPRISE_ADMIN_STUB_MOCK_H

#include <gmock/gmock.h>
#include <iremote_stub.h>
#include <map>

#include "ienterprise_admin.h"

namespace OHOS {
namespace EDM {
class EnterpriseAdminStubMock : public IRemoteStub<IEnterpriseAdmin> {
public:
    EnterpriseAdminStubMock() : code_(0) {}

    virtual ~EnterpriseAdminStubMock() {}

    MOCK_METHOD4(SendRequest, int(uint32_t, MessageParcel &, MessageParcel &, MessageOption &));

    int InvokeSendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        code_ = code;
        return 0;
    }

    bool OnAdmin(uint32_t code) override { return true; }

    bool OnBundle(uint32_t code, const std::string &bundleName, int32_t accountId) override { return true; }

    bool OnApp(uint32_t code, const std::string &bundleName) override { return true; }

    bool OnSystemUpdate(const UpdateInfo &updateInfo) override { return true; }

    bool OnAccount(uint32_t code, const int32_t accountId) override { return true; }

    bool OnKioskMode(uint32_t code, const std::string &bundleName, int32_t accountId) override { return true; }

    bool OnMarketAppsInstallStatusChanged(const std::string &bundleName, int32_t status) override { return true; }

    bool OnDeviceAdmin(uint32_t code, const std::string &bundleName) override { return true; }

    bool OnLogCollected(bool isSuccess) override { return true; }

    bool OnKeyEvent(const std::string &event) override { return true; }

    bool OnStartupGuideCompleted(int32_t type) override { return true; }

    bool OnDeviceBootCompleted() override { return true; }

    bool OnAdminPolicyChanged(const PolicyChangedEvent &policyChangedEvent) override { return true; }

    uint32_t code_ = 0;
};
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_ENTERPRISE_ADMIN_STUB_MOCK_H

