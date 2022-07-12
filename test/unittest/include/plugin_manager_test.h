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

#ifndef EDM_UNIT_TEST_PLUGIN_MANAGER_TEST_H
#define EDM_UNIT_TEST_PLUGIN_MANAGER_TEST_H

#include <gtest/gtest.h>
#include <iremote_object.h>
#include "edm_log.h"
#include "iplugin.h"

namespace OHOS {
namespace EDM {
namespace TEST {
class TestPlugin : public IPlugin {
public:
    TestPlugin()
    {
        policyCode_ = 0;
        policyName_ = "TestPlugin";
        permission_ = "ohos.permission.EDM_TEST_PERMISSION";
        EDMLOGD("TestPlugin constructor");
    }

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, std::string &policyData,
        bool &isChanged) override
    {
        return ERR_OK;
    }

    ErrCode MergePolicyData(const std::string &adminName, std::string &policyData) override
    {
        return IPlugin::MergePolicyData(adminName, policyData);
    }

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged) override {}

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData) override
    {
        return ERR_OK;
    }

    void OnAdminRemoveDone(const std::string &adminName, const std::string &policyData) override {}

    ErrCode WritePolicyToParcel(const std::string &policyData, MessageParcel &reply) override
    {
        return IPlugin::WritePolicyToParcel(policyData, reply);
    }

    ~TestPlugin() override = default;
};

class PluginManagerTest : public testing::Test {
protected:
    virtual void SetUp() override;

    virtual void TearDown() override;
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_PLUGIN_MANAGER_TEST_H
