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

    void OnAdminEnabled() override {}

    void OnAdminDisabled() override {}

    void OnBundleAdded(const std::string &bundleName) override {}

    void OnBundleRemoved(const std::string &bundleName) override {}

    uint32_t code_ = 0;
};
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_ENTERPRISE_ADMIN_STUB_MOCK_H

