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

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "func_code.h"
#include "iplugin_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class IPluginTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};

/**
 * @tc.name: TestIsGlobalPolicy
 * @tc.desc: Test IsGlobalPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(IPluginTest, TestIsGlobalPolicy, TestSize.Level1)
{
    IPluginMock iplugin1;
    EXPECT_TRUE(iplugin1.IsGlobalPolicy());
    iplugin1.MockSetPolicyName("test");
    std::string mergeJsonData;
    ErrCode err = iplugin1.MergePolicyData("com.edm.test.demo", mergeJsonData);
    EXPECT_TRUE(err == ERR_OK);
    MessageParcel reply;
    err = iplugin1.WritePolicyToParcel("name:test", reply);
    EXPECT_TRUE(err == ERR_OK);
}

/**
 * @tc.name: TestPolicyPermissionConfig
 * @tc.desc: Test PolicyPermissionConfig struct.
 * @tc.type: FUNC
 */
HWTEST_F(IPluginTest, TestPolicyPermissionConfig, TestSize.Level1)
{
    IPlugin::PolicyPermissionConfig config1 = IPlugin::PolicyPermissionConfig();
    EXPECT_TRUE(config1.permissionType == IPlugin::PermissionType::UNKNOWN);
    EXPECT_TRUE(config1.apiType == IPlugin::ApiType::UNKNOWN);

    IPlugin::PolicyPermissionConfig config2 = IPlugin::PolicyPermissionConfig("test_permission",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    EXPECT_TRUE(config2.permission == "test_permission");
    EXPECT_TRUE(config2.permissionType == IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    EXPECT_TRUE(config2.apiType == IPlugin::ApiType::PUBLIC);

    std::map<std::string, std::string> perms;
    perms.insert(std::make_pair("tag1", "permission1"));
    perms.insert(std::make_pair("tag2", "permission2"));
    IPlugin::PolicyPermissionConfig config3 = IPlugin::PolicyPermissionConfig(perms,
        IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::SYSTEM);
    EXPECT_TRUE(config3.tagPermissions.size() == 2);
    EXPECT_TRUE(config3.permissionType == IPlugin::PermissionType::NORMAL_DEVICE_ADMIN);
    EXPECT_TRUE(config3.apiType == IPlugin::ApiType::SYSTEM);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS