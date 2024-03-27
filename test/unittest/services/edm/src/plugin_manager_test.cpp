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

#include "plugin_manager_test.h"
#include <ipc_skeleton.h>
#include <iservice_registry.h>
#include "func_code_utils.h"
#define private public
#include "plugin_manager.h"
#undef private
#include "string_ex.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr uint32_t INVAILD_PLUGIN_CODE = 10000;

void PluginManagerTest::SetUp()
{
    PluginManager::GetInstance()->AddPlugin(std::make_shared<TestPlugin>());
}

void PluginManagerTest::TearDown()
{
    PluginManager::GetInstance().reset();
}

/**
 * @tc.name: TestGetInstance
 * @tc.desc: Test PluginManager GetInstance func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetInstance, TestSize.Level1)
{
    ASSERT_TRUE(PluginManager::GetInstance() != nullptr);
    ASSERT_TRUE(PluginManager::GetInstance().get() != nullptr);
}

/**
 * @tc.name: TestGetPluginByFuncCode
 * @tc.desc: Test PluginManager GetPluginByFuncCode func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPluginByFuncCode, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, 0));
    ASSERT_TRUE(plugin != nullptr);
    ASSERT_TRUE(plugin->GetPolicyName() == "TestPlugin");
    ASSERT_TRUE(PluginManager::GetInstance()->GetPluginByFuncCode(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, INVAILD_PLUGIN_CODE)) == nullptr);
}

/**
 * @tc.name: TestGetPluginByPolicyName
 * @tc.desc: Test PluginManager GetPluginByPolicyName func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPluginByPolicyName, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByPolicyName("TestPlugin");
    ASSERT_TRUE(plugin != nullptr);
    ASSERT_TRUE(plugin->GetCode() == 0);
    ASSERT_TRUE(PluginManager::GetInstance()->GetPluginByPolicyName("XXXXExamplePlugin") == nullptr);
}

/**
 * @tc.name: TestGetPluginByCode
 * @tc.desc: Test PluginManager GetPluginByCode func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPluginByCode, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByCode(0);
    ASSERT_TRUE(plugin != nullptr);
    ASSERT_TRUE(plugin->GetPolicyName() == "TestPlugin");
    ASSERT_TRUE(PluginManager::GetInstance()->GetPluginByCode(INVAILD_PLUGIN_CODE) == nullptr);
}

/**
 * @tc.name: TestEnhanceStrategyOnGetPolicy
 * @tc.desc: Test PluginManager CreateExecuteStrategy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestEnhanceStrategyOnGetPolicy, TestSize.Level1)
{
    auto strategy = PluginManager::GetInstance()->CreateExecuteStrategy(ExecuteStrategy::ENHANCE);
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = strategy->OnGetExecute(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::GET, 0), policyData, data, reply, 0);
    ASSERT_TRUE(ret == ERR_OK);
    ret = strategy->OnGetExecute(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::GET, INVAILD_PLUGIN_CODE), policyData, data, reply, 0);
    ASSERT_TRUE(ret == ERR_EDM_GET_POLICY_FAILED);
}

/**
 * @tc.name: TestEnhanceStrategyOnSetPolicy
 * @tc.desc: Test PluginManager CreateExecuteStrategy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestEnhanceStrategyOnSetPolicy, TestSize.Level1)
{
    auto strategy = PluginManager::GetInstance()->CreateExecuteStrategy(ExecuteStrategy::ENHANCE);
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = strategy->OnSetExecute(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, 0), data, reply, policyData, 0);
    ASSERT_TRUE(ret == ERR_OK);
    ret = strategy->OnSetExecute(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, INVAILD_PLUGIN_CODE), data, reply, policyData, 0);
    ASSERT_TRUE(ret == ERR_EDM_HANDLE_POLICY_FAILED);
}

/**
 * @tc.name: TestSingleStrategyOnGetPolicy
 * @tc.desc: Test PluginManager CreateExecuteStrategy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestSingleStrategyOnGetPolicy, TestSize.Level1)
{
    auto strategy = PluginManager::GetInstance()->CreateExecuteStrategy(ExecuteStrategy::SINGLE);
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = strategy->OnGetExecute(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::GET, 0), policyData, data, reply, 0);
    ASSERT_TRUE(ret == ERR_OK);
    ret = strategy->OnGetExecute(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::GET, INVAILD_PLUGIN_CODE), policyData, data, reply, 0);
    ASSERT_TRUE(ret == ERR_EDM_GET_POLICY_FAILED);
}

/**
 * @tc.name: TestSingleStrategyOnSetPolicy
 * @tc.desc: Test PluginManager CreateExecuteStrategy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestSingleStrategyOnSetPolicy, TestSize.Level1)
{
    auto strategy = PluginManager::GetInstance()->CreateExecuteStrategy(ExecuteStrategy::SINGLE);
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = strategy->OnSetExecute(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, 0), data, reply, policyData, 0);
    ASSERT_TRUE(ret == ERR_OK);
    ret = strategy->OnSetExecute(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, INVAILD_PLUGIN_CODE), data, reply, policyData, 0);
    ASSERT_TRUE(ret == ERR_EDM_HANDLE_POLICY_FAILED);
}

/**
 * @tc.name: TestEnhanceStrategyOnGetPolicyWithExtension
 * @tc.desc: Test PluginManager CreateExecuteStrategy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestEnhanceStrategyOnGetPolicyWithExtension, TestSize.Level1)
{
    PluginManager::GetInstance()->AddExtensionPlugin(
        std::make_shared<TestExtensionPlugin>(), 0, ExecuteStrategy::ENHANCE);
    auto strategy = PluginManager::GetInstance()->CreateExecuteStrategy(ExecuteStrategy::ENHANCE);
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = strategy->OnGetExecute(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::GET, 0), policyData, data, reply, 0);
    ASSERT_TRUE(ret == ERR_OK);
    auto extensionPlugin = PluginManager::GetInstance()->pluginsCode_.find(1);
    PluginManager::GetInstance()->pluginsCode_.erase(extensionPlugin);
    ASSERT_TRUE(PluginManager::GetInstance()->GetPluginByCode(1) == nullptr);
}

/**
 * @tc.name: TestEnhanceStrategyOnSetPolicyWithExtension
 * @tc.desc: Test PluginManager CreateExecuteStrategy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestEnhanceStrategyOnSetPolicyWithExtension, TestSize.Level1)
{
    PluginManager::GetInstance()->AddExtensionPlugin(
        std::make_shared<TestExtensionPlugin>(), 0, ExecuteStrategy::ENHANCE);
    auto strategy = PluginManager::GetInstance()->CreateExecuteStrategy(ExecuteStrategy::ENHANCE);
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = strategy->OnSetExecute(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, 0), data, reply, policyData, 0);
    ASSERT_TRUE(ret == ERR_OK);
    auto extensionPlugin = PluginManager::GetInstance()->pluginsCode_.find(1);
    PluginManager::GetInstance()->pluginsCode_.erase(extensionPlugin);
    ASSERT_TRUE(PluginManager::GetInstance()->GetPluginByCode(1) == nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
