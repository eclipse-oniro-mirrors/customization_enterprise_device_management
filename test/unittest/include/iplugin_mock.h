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

#ifndef EDM_UNIT_TEST_IPLUGIN_MOCK_H
#define EDM_UNIT_TEST_IPLUGIN_MOCK_H

#include <gmock/gmock.h>
#include <map>

#include "iplugin.h"

namespace OHOS {
namespace EDM {
class IPluginMock : public IPlugin {
public:
    IPluginMock() {}

    virtual ~IPluginMock() {}

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, std::string &policyData,
        bool &isChanged) override
    {
        return 0;
    }

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged) override {}

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData) override
    {
        return 0;
    }

    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData) override {}

    void MockSetPolicyName(std::string policyName)
    {
        policyName_ = policyName;
    }
};
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_ENTERPRISE_ADMIN_STUB_MOCK_H

