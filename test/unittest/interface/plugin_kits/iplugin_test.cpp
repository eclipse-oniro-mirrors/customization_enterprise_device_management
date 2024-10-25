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
#define private public
#define protected public
#include "iplugin.h"
#undef protected
#undef private
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

/**
 * @tc.name: TestGetApiType
 * @tc.desc: Test GetApiType func.
 * @tc.type: FUNC
 */
HWTEST_F(IPluginTest, TestGetApiType, TestSize.Level1)
{
    FuncOperateType operaType = FuncOperateType::GET;
    IPluginMock::ApiType ret;

    std::map<FuncOperateType, IPluginMock::PolicyPermissionConfig> permissionMap1;
    IPluginMock::PolicyPermissionConfig permissionConfig1;
    std::unique_ptr<IPlugin> iplugin1 = std::make_unique<IPluginMock>();
    permissionMap1[operaType] = permissionConfig1;
    iplugin1->permissionMap_ = permissionMap1;
    iplugin1->permissionConfig_ = permissionConfig1;
    ret = iplugin1->GetApiType(operaType);
    EXPECT_TRUE(ret == IPluginMock::ApiType::UNKNOWN);

    std::map<FuncOperateType, IPluginMock::PolicyPermissionConfig> permissionMap2;
    IPluginMock::PolicyPermissionConfig permissionConfig2;
    std::unique_ptr<IPlugin> iplugin2 = std::make_unique<IPluginMock>();
    iplugin2->permissionMap_ = permissionMap2;
    permissionConfig2.apiType = IPluginMock::ApiType::PUBLIC;
    iplugin2->permissionConfig_ = permissionConfig2;
    ret = iplugin2->GetApiType(operaType);
    EXPECT_TRUE(ret == IPluginMock::ApiType::PUBLIC);

    std::map<FuncOperateType, IPluginMock::PolicyPermissionConfig> permissionMap3;
    IPluginMock::PolicyPermissionConfig permissionConfig3;
    std::unique_ptr<IPlugin> iplugin3 = std::make_unique<IPluginMock>();
    permissionConfig3.apiType = IPluginMock::ApiType::PUBLIC;
    permissionMap3[operaType] = permissionConfig3;
    iplugin3->permissionMap_ = permissionMap3;
    ret = iplugin3->GetApiType(operaType);
    EXPECT_TRUE(ret == IPluginMock::ApiType::PUBLIC);

    std::map<FuncOperateType, IPluginMock::PolicyPermissionConfig> permissionMap4;
    IPluginMock::PolicyPermissionConfig permissionConfig4;
    std::unique_ptr<IPlugin> iplugin4 = std::make_unique<IPluginMock>();
    permissionConfig4.apiType = IPluginMock::ApiType::UNKNOWN;
    permissionMap4[operaType] = permissionConfig4;
    iplugin4->permissionConfig_ = permissionConfig4;
    ret = iplugin4->GetApiType(operaType);
    EXPECT_TRUE(ret == IPluginMock::ApiType::UNKNOWN);
}

/**
 * @tc.name: TestGetPermissionWhenIfEstablished
 * @tc.desc: Test GetPermission func when The If Condition is Met.
 * @tc.type: FUNC
 */
HWTEST_F(IPluginTest, TestGetPermissionWhenIfEstablished, TestSize.Level1)
{
    FuncOperateType operaType = FuncOperateType::GET;
    std::string permissionTag = "permissionTag";
    std::map<FuncOperateType, IPluginMock::PolicyPermissionConfig> permissionMap;
    IPluginMock::PolicyPermissionConfig permissionConfig;
    std::unique_ptr<IPlugin> iplugin = std::make_unique<IPluginMock>();

    permissionMap[operaType] = permissionConfig;
    iplugin->permissionMap_ = permissionMap;
    iplugin->permissionConfig_ = permissionConfig;
    std::string ret = iplugin->GetPermission(operaType, permissionTag);
    std::string checkRet = NONE_PERMISSION_MATCH;
    EXPECT_TRUE(ret == checkRet);
}

/**
 * @tc.name: TestSetExtensionPlugin
 * @tc.desc: Test SetExtensionPlugin func.
 * @tc.type: FUNC
 */
HWTEST_F(IPluginTest, TestSetExtensionPlugin, TestSize.Level1)
{
    std::shared_ptr<IPlugin> extensionPlugin = std::make_shared<IPluginMock>();
    std::unique_ptr<IPlugin> iplugin = std::make_unique<IPluginMock>();
    iplugin->SetExtensionPlugin(extensionPlugin);
    EXPECT_TRUE(extensionPlugin == iplugin->GetExtensionPlugin());
}

/**
 * @tc.name: TestSetExecuteStrategy
 * @tc.desc: Test SetExecuteStrategy func.
 * @tc.type: FUNC
 */
HWTEST_F(IPluginTest, TestSetExecuteStrategy, TestSize.Level1)
{
    std::shared_ptr<IPluginExecuteStrategy> strategy = std::make_shared<IPluginExecuteStrategy>();
    std::unique_ptr<IPlugin> iplugin = std::make_unique<IPluginMock>();
    iplugin->SetExecuteStrategy(strategy);
    EXPECT_TRUE(strategy == iplugin->GetExecuteStrategy());
}

/**
 * @tc.name: TestSetPluginType
 * @tc.desc: Test SetPluginType func.
 * @tc.type: FUNC
 */
HWTEST_F(IPluginTest, TestSetPluginType, TestSize.Level1)
{
    IPluginMock::PluginType type = IPluginMock::PluginType::BASIC;
    std::unique_ptr<IPlugin> iplugin = std::make_unique<IPluginMock>();
    iplugin->SetPluginType(type);
    EXPECT_TRUE(type == iplugin->GetPluginType());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS