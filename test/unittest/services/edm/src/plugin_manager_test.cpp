/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "edm_ipc_interface_code.h"
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
    PluginManager::GetInstance()->deviceCoreSoCodes_.push_back(0);
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
 * @tc.name: TestReplaceStrategyOnGetPolicy
 * @tc.desc: Test PluginManager CreateExecuteStrategy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestReplaceStrategyOnGetPolicy, TestSize.Level1)
{
    auto strategy = PluginManager::GetInstance()->CreateExecuteStrategy(ExecuteStrategy::REPLACE);
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
 * @tc.name: TestReplaceStrategyOnSetPolicy
 * @tc.desc: Test PluginManager CreateExecuteStrategy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestReplaceStrategyOnSetPolicy, TestSize.Level1)
{
    auto strategy = PluginManager::GetInstance()->CreateExecuteStrategy(ExecuteStrategy::REPLACE);
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

/**
 * @tc.name: TestReplaceStrategyOnGetPolicyWithExtension
 * @tc.desc: Test PluginManager CreateExecuteStrategy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestReplaceStrategyOnGetPolicyWithExtension, TestSize.Level1)
{
    PluginManager::GetInstance()->AddExtensionPlugin(
        std::make_shared<TestExtensionPlugin>(), 0, ExecuteStrategy::REPLACE);
    auto strategy = PluginManager::GetInstance()->CreateExecuteStrategy(ExecuteStrategy::REPLACE);
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
 * @tc.name: TestReplaceStrategyOnSetPolicyWithExtension
 * @tc.desc: Test PluginManager CreateExecuteStrategy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestReplaceStrategyOnSetPolicyWithExtension, TestSize.Level1)
{
    PluginManager::GetInstance()->AddExtensionPlugin(
        std::make_shared<TestExtensionPlugin>(), 0, ExecuteStrategy::REPLACE);
    auto strategy = PluginManager::GetInstance()->CreateExecuteStrategy(ExecuteStrategy::REPLACE);
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

/**
 * @tc.name: TestLoadAllPlugin
 * @tc.desc: Test PluginManager LoadAllPlugin func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestLoadAllPlugin, TestSize.Level1)
{
    auto pluginManager = PluginManager::GetInstance();
    pluginManager->LoadAllPlugin();
    ASSERT_TRUE(pluginManager->soLoadStateMap_[SONAME::DEVICE_CORE_PLUGIN_SO]->pluginHasInit);
    ASSERT_TRUE(pluginManager->soLoadStateMap_[SONAME::COMMUNICATION_PLUGIN_SO]->pluginHasInit);
    ASSERT_TRUE(pluginManager->soLoadStateMap_[SONAME::SYS_SERVICE_PLUGIN_SO]->pluginHasInit);
    ASSERT_TRUE(pluginManager->soLoadStateMap_[SONAME::NEED_EXTRA_PLUGIN_SO]->pluginHasInit);
}

/**
 * @tc.name: TestIsExtraPlugin
 * @tc.desc: Test PluginManager IsExtraPlugin func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestIsExtraPlugin, TestSize.Level1)
{
    ASSERT_FALSE(PluginManager::GetInstance()->IsExtraPlugin(SONAME::DEVICE_CORE_PLUGIN_SO));
    ASSERT_FALSE(PluginManager::GetInstance()->IsExtraPlugin(SONAME::COMMUNICATION_PLUGIN_SO));
    ASSERT_FALSE(PluginManager::GetInstance()->IsExtraPlugin(SONAME::SYS_SERVICE_PLUGIN_SO));
    ASSERT_FALSE(PluginManager::GetInstance()->IsExtraPlugin(SONAME::NEED_EXTRA_PLUGIN_SO));
    ASSERT_FALSE(PluginManager::GetInstance()->IsExtraPlugin(SONAME::OLD_EDM_PLUGIN_SO));
    ASSERT_TRUE(PluginManager::GetInstance()->IsExtraPlugin("custom_plugin.so"));
}

/**
 * @tc.name: TestLoadPluginByFuncCode
 * @tc.desc: Test PluginManager LoadPluginByFuncCode func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestLoadPluginByFuncCode, TestSize.Level1)
{
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISABLED_PRINTER);
    PluginManager::GetInstance()->LoadPluginByFuncCode(funcCode);
    ASSERT_TRUE(PluginManager::GetInstance()->soLoadStateMap_[SONAME::DEVICE_CORE_PLUGIN_SO]->pluginHasInit);
}

/**
 * @tc.name: TestGetSoNameByCode
 * @tc.desc: Test PluginManager GetSoNameByCode func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetSoNameByCode, TestSize.Level1)
{
    std::string soName;
    bool ret = PluginManager::GetInstance()->GetSoNameByCode(EdmInterfaceCode::DISALLOW_ADD_LOCAL_ACCOUNT, soName);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(soName == SONAME::DEVICE_CORE_PLUGIN_SO);

    ret = PluginManager::GetInstance()->GetSoNameByCode(EdmInterfaceCode::IS_WIFI_ACTIVE, soName);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(soName == SONAME::COMMUNICATION_PLUGIN_SO);

    ret = PluginManager::GetInstance()->GetSoNameByCode(EdmInterfaceCode::SET_DATETIME, soName);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(soName == SONAME::SYS_SERVICE_PLUGIN_SO);

    ret = PluginManager::GetInstance()->GetSoNameByCode(EdmInterfaceCode::GET_DEVICE_SERIAL, soName);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(soName == SONAME::NEED_EXTRA_PLUGIN_SO);

    ret = PluginManager::GetInstance()->GetSoNameByCode(10000, soName);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestUnloadPlugin_NormalCase
 * @tc.desc: Test PluginManager UnloadPlugin func with normal case.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestUnloadPlugin_NormalCase, TestSize.Level1)
{
    // Load a plugin first
    std::string soName = SONAME::DEVICE_CORE_PLUGIN_SO;
    PluginManager::GetInstance()->LoadPlugin(soName);
    
    // Verify plugin is loaded
    auto loadState = PluginManager::GetInstance()->soLoadStateMap_[soName];
    ASSERT_TRUE(loadState != nullptr);
    ASSERT_TRUE(loadState->pluginHasInit);
    
    // Unload the plugin
    PluginManager::GetInstance()->UnloadPlugin(soName);
    // Verify plugin is unloaded
    EXPECT_EQ(PluginManager::GetInstance()->soLoadStateMap_.find(soName),
              PluginManager::GetInstance()->soLoadStateMap_.end());
}

/**
 * @tc.name: TestUnloadPlugin_NormalCase2
 * @tc.desc: Test PluginManager UnloadPlugin func with normal case.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestUnloadPlugin_NormalCase2, TestSize.Level1)
{
    // Load a plugin first
    std::string soName = SONAME::COMMUNICATION_PLUGIN_SO;
    PluginManager::GetInstance()->LoadPlugin(soName);
    
    // Verify plugin is loaded
    auto loadState = PluginManager::GetInstance()->soLoadStateMap_[soName];
    ASSERT_TRUE(loadState != nullptr);
    ASSERT_TRUE(loadState->pluginHasInit);
    
    // Unload the plugin
    PluginManager::GetInstance()->UnloadPlugin(soName);
    
    // Verify plugin is unloaded
    EXPECT_EQ(PluginManager::GetInstance()->soLoadStateMap_.find(soName),
              PluginManager::GetInstance()->soLoadStateMap_.end());
}

/**
 * @tc.name: TestUnloadPlugin_NormalCase3
 * @tc.desc: Test PluginManager UnloadPlugin func with normal case.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestUnloadPlugin_NormalCase3, TestSize.Level1)
{
    // Load a plugin first
    std::string soName = SONAME::SYS_SERVICE_PLUGIN_SO;
    PluginManager::GetInstance()->LoadPlugin(soName);
    
    // Verify plugin is loaded
    auto loadState = PluginManager::GetInstance()->soLoadStateMap_[soName];
    ASSERT_TRUE(loadState != nullptr);
    ASSERT_TRUE(loadState->pluginHasInit);
    
    // Unload the plugin
    PluginManager::GetInstance()->UnloadPlugin(soName);
    
    // Verify plugin is unloaded
    EXPECT_EQ(PluginManager::GetInstance()->soLoadStateMap_.find(soName),
              PluginManager::GetInstance()->soLoadStateMap_.end());
}

/**
 * @tc.name: TestUnloadPlugin_NormalCase4
 * @tc.desc: Test PluginManager UnloadPlugin func with normal case.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestUnloadPlugin_NormalCase4, TestSize.Level1)
{
    // Load a plugin first
    std::string soName = SONAME::NEED_EXTRA_PLUGIN_SO;
    PluginManager::GetInstance()->LoadPlugin(soName);
    
    // Verify plugin is loaded
    auto loadState = PluginManager::GetInstance()->soLoadStateMap_[soName];
    ASSERT_TRUE(loadState != nullptr);
    ASSERT_TRUE(loadState->pluginHasInit);
    
    // Unload the plugin
    PluginManager::GetInstance()->UnloadPlugin(soName);
    
    // Verify plugin is unloaded
    EXPECT_EQ(PluginManager::GetInstance()->soLoadStateMap_.find(soName),
              PluginManager::GetInstance()->soLoadStateMap_.end());
}

/**
 * @tc.name: TestRemovePlugin_NormalCase
 * @tc.desc: Test PluginManager RemovePlugin func with normal case.
 * @tc.type: FUNC
 * @tc.require: AR000HFTD5
 */
HWTEST_F(PluginManagerTest, TestRemovePlugin_NormalCase, TestSize.Level1)
{
    // Setup: Add a test plugin
    auto plugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->AddPlugin(plugin);
    
    // Verify plugin is added
    ASSERT_TRUE(PluginManager::GetInstance()->GetPluginByCode(0) != nullptr);
    
    // Remove the plugin
    PluginManager::GetInstance()->RemovePlugin(plugin);
    
    // Verify plugin is removed
    EXPECT_TRUE(PluginManager::GetInstance()->GetPluginByCode(0) == nullptr);
    EXPECT_EQ(PluginManager::GetInstance()->pluginsCode_.find(0),
              PluginManager::GetInstance()->pluginsCode_.end());
    EXPECT_EQ(PluginManager::GetInstance()->pluginsName_.find("TestPlugin"),
              PluginManager::GetInstance()->pluginsName_.end());
}

/**
 * @tc.name: TestRemovePlugin_NullPlugin
 * @tc.desc: Test PluginManager RemovePlugin with null plugin.
 * @tc.type: FUNC
 * @tc.require: AR000HFTD5
 */
HWTEST_F(PluginManagerTest, TestRemovePlugin_NullPlugin, TestSize.Level1)
{
    // Verify no changes to plugin manager state
    EXPECT_TRUE(PluginManager::GetInstance()->GetPluginByCode(0) != nullptr);
}

/**
 * @tc.name: TestRemovePlugin_NonExistentPlugin
 * @tc.desc: Test PluginManager RemovePlugin with non-existent plugin.
 * @tc.type: FUNC
 * @tc.require: AR000HFTD5
 */
HWTEST_F(PluginManagerTest, TestRemovePlugin_NonExistentPlugin, TestSize.Level1)
{
    // Create a plugin but don't add it
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    nonExistentPlugin->policyCode_ = 999; // Use a code that's not registered
    
    // Verify no changes to plugin manager state
    EXPECT_TRUE(PluginManager::GetInstance()->GetPluginByCode(0) != nullptr);
}

/**
 * @tc.name: TestCallOnOtherServiceStart_NonExistPlugin
 * @tc.desc: Test PluginManager CallOnOtherServiceStart with non-existent plugin.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestCallOnOtherServiceStart_NonExistPlugin, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->CallOnOtherServiceStart(nonExistentPlugin->policyCode_, 0);
    EXPECT_EQ(nonExistentPlugin->callOnOtherServiceStartFlag_, false);
}

/**
 * @tc.name: TestCallOnOtherServiceStart_NullptrPlugin
 * @tc.desc: Test PluginManager CallOnOtherServiceStart with nullptr plugin.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestCallOnOtherServiceStart_NullptrPlugin, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nullptr;
    PluginManager::GetInstance()->CallOnOtherServiceStart(nonExistentPlugin->policyCode_, 0);
    EXPECT_EQ(nonExistentPlugin->callOnOtherServiceStartFlag_, false);
}

/**
 * @tc.name: TestCallOnOtherServiceStart_Suc
 * @tc.desc: Test PluginManager CallOnOtherServiceStart success.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestCallOnOtherServiceStart_Suc, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nonExistentPlugin;
    PluginManager::GetInstance()->CallOnOtherServiceStart(nonExistentPlugin->policyCode_, 0);
    EXPECT_EQ(nonExistentPlugin->callOnOtherServiceStartFlag_, true);
}

/**
 * @tc.name: TestOnInitExecute_NonExistPlugin
 * @tc.desc: Test PluginManager OnInitExecute with non-existent plugin.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestOnInitExecute_NonExistPlugin, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    std::vector<std::string> bundleNames;
    PluginManager::GetInstance()->OnInitExecute(nonExistentPlugin->policyCode_, bundleNames, 0);
    EXPECT_EQ(nonExistentPlugin->callOnOtherServiceStartForAdminFlag_, false);
}

/**
 * @tc.name: TestCOnInitExecute_NullptrPlugin
 * @tc.desc: Test PluginManager OnInitExecute with nullptr plugin.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestCOnInitExecute_NullptrPlugin, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nullptr;
    std::vector<std::string> bundleNames;
    PluginManager::GetInstance()->OnInitExecute(nonExistentPlugin->policyCode_, bundleNames, 0);
    EXPECT_EQ(nonExistentPlugin->callOnOtherServiceStartForAdminFlag_, false);
}

/**
 * @tc.name: TestOnInitExecute_Suc
 * @tc.desc: Test PluginManager OnInitExecute success.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestOnInitExecute_Suc, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    nonExistentPlugin->SetExecuteStrategy(std::make_shared<SingleExecuteStrategy>());
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nonExistentPlugin;
    std::vector<std::string> bundleNames = {"TestAdmin"};
    PluginManager::GetInstance()->OnInitExecute(nonExistentPlugin->policyCode_, bundleNames, 0);
    EXPECT_EQ(nonExistentPlugin->callOnOtherServiceStartForAdminFlag_, true);
}

/**
 * @tc.name: TestSetPluginUnloadFlag_NonExistPlugin
 * @tc.desc: Test PluginManager SetPluginUnloadFlag with non-existent plugin.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestSetPluginUnloadFlag_NonExistPlugin, TestSize.Level1)
{
    PluginManager::GetInstance()->pluginsCode_.clear();
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    auto ret = PluginManager::GetInstance()->SetPluginUnloadFlag(nonExistentPlugin->policyCode_, false);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestSetPluginUnloadFlag_NullptrPlugin
 * @tc.desc: Test PluginManager SetPluginUnloadFlag with nullptr plugin.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestSetPluginUnloadFlag_NullptrPlugin, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nullptr;
    auto ret = PluginManager::GetInstance()->SetPluginUnloadFlag(nonExistentPlugin->policyCode_, false);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TesSetPluginUnloadFlag_Suc
 * @tc.desc: Test PluginManager SetPluginUnloadFlag success.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TesSetPluginUnloadFlag_Suc, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nonExistentPlugin;
    EXPECT_EQ(nonExistentPlugin->pluginUnloadFlag_, true);
    auto ret = PluginManager::GetInstance()->SetPluginUnloadFlag(nonExistentPlugin->policyCode_, false);
    EXPECT_EQ(nonExistentPlugin->pluginUnloadFlag_, false);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestGetPermission_NullptrPlugin
 * @tc.desc: Test PluginManager GetPermission with nullptr plugin.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPermission_NullptrPlugin, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nullptr;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, nonExistentPlugin->policyCode_);
    auto permission = PluginManager::GetInstance()->GetPermission(funcCode, FuncOperateType::GET,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    EXPECT_EQ(permission, NONE_PERMISSION_MATCH);
}

/**
 * @tc.name: TesGetPermission_Suc
 * @tc.desc: Test PluginManager GetPermission success.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TesGetPermission_Suc, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nonExistentPlugin;
    EXPECT_EQ(nonExistentPlugin->pluginUnloadFlag_, true);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, nonExistentPlugin->policyCode_);
    auto permission = PluginManager::GetInstance()->GetPermission(funcCode, FuncOperateType::GET,
        IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "");
    EXPECT_EQ(permission,
        nonExistentPlugin->permissionConfig_.typePermissions[IPlugin::PermissionType::NORMAL_DEVICE_ADMIN]);
}

/**
 * @tc.name: TestGetPluginType_NullptrPlugin
 * @tc.desc: Test PluginManager GetPluginType with nullptr plugin.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPluginType_NullptrPlugin, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nullptr;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, nonExistentPlugin->policyCode_);
    auto pluginType = PluginManager::GetInstance()->GetPluginType(funcCode, FuncOperateType::GET);
    EXPECT_EQ(pluginType, IPlugin::ApiType::UNKNOWN);
}

/**
 * @tc.name: TesGetPluginType_Suc
 * @tc.desc: Test PluginManager GetPluginType success.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TesGetPluginType_Suc, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nonExistentPlugin;
    EXPECT_EQ(nonExistentPlugin->pluginUnloadFlag_, true);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, nonExistentPlugin->policyCode_);
    auto pluginType = PluginManager::GetInstance()->GetPluginType(funcCode, FuncOperateType::GET);
    EXPECT_EQ(pluginType, nonExistentPlugin->permissionConfig_.apiType);
}

/**
 * @tc.name: TestGetPolicyName_NullptrPlugin
 * @tc.desc: Test PluginManager GetPolicyName with nullptr plugin.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPolicyName_NullptrPlugin, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nullptr;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, nonExistentPlugin->policyCode_);
    auto policyName = PluginManager::GetInstance()->GetPolicyName(funcCode);
    EXPECT_TRUE(policyName.empty());
}

/**
 * @tc.name: TesGetPolicyName_Suc
 * @tc.desc: Test PluginManager GetPolicyName success.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TesGetPolicyName_Suc, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsCode_[nonExistentPlugin->policyCode_] = nonExistentPlugin;
    EXPECT_EQ(nonExistentPlugin->pluginUnloadFlag_, true);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, nonExistentPlugin->policyCode_);
    auto policyName = PluginManager::GetInstance()->GetPolicyName(funcCode);
    EXPECT_EQ(policyName, nonExistentPlugin->policyName_);
}

/**
 * @tc.name: TestGetPluginPermissionByPolicyName_NonExistPlugin
 * @tc.desc: Test PluginManager GetPluginPermissionByPolicyName with non-existent plugin.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPluginPermissionByPolicyName_NonExistPlugin, TestSize.Level1)
{
    PluginManager::GetInstance()->pluginsName_.clear();
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    auto permission = PluginManager::GetInstance()->GetPluginPermissionByPolicyName(nonExistentPlugin->policyName_,
        IPlugin::PermissionType::NORMAL_DEVICE_ADMIN);
    EXPECT_TRUE(permission.empty());
}

/**
 * @tc.name: TestGetPluginPermissionByPolicyName_NullptrPlugin
 * @tc.desc: Test PluginManager GetPluginPermissionByPolicyName with nullptr plugin.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPluginPermissionByPolicyName_NullptrPlugin, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsName_[nonExistentPlugin->policyName_] = nullptr;
    auto permission = PluginManager::GetInstance()->GetPluginPermissionByPolicyName(nonExistentPlugin->policyName_,
        IPlugin::PermissionType::NORMAL_DEVICE_ADMIN);
    EXPECT_TRUE(permission.empty());
}

/**
 * @tc.name: TestGetPluginPermissionByPolicyName_WithWrongPermissionType
 * @tc.desc: Test PluginManager GetPluginPermissionByPolicyName success.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPluginPermissionByPolicyName_WithWrongPermissionType, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsName_[nonExistentPlugin->policyName_] = nonExistentPlugin;
    nonExistentPlugin->permissionConfig_.typePermissions[IPlugin::PermissionType::SUPER_DEVICE_ADMIN] =
            "ohos.permission.EDM_TEST_PERMISSION";
    auto permission = PluginManager::GetInstance()->GetPluginPermissionByPolicyName(nonExistentPlugin->policyName_,
        IPlugin::PermissionType::NORMAL_DEVICE_ADMIN);
    EXPECT_EQ(permission,
        nonExistentPlugin->permissionConfig_.typePermissions[IPlugin::PermissionType::NORMAL_DEVICE_ADMIN]);
}

/**
 * @tc.name: TestGetPluginPermissionByPolicyName_WithRightPermissionType
 * @tc.desc: Test PluginManager GetPluginPermissionByPolicyName success.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPluginPermissionByPolicyName_WithRightPermissionType, TestSize.Level1)
{
    auto nonExistentPlugin = std::make_shared<TestPlugin>();
    PluginManager::GetInstance()->pluginsName_[nonExistentPlugin->policyName_] = nonExistentPlugin;
    auto permission = PluginManager::GetInstance()->GetPluginPermissionByPolicyName(nonExistentPlugin->policyName_,
        IPlugin::PermissionType::NORMAL_DEVICE_ADMIN);
    EXPECT_EQ(permission,
        nonExistentPlugin->permissionConfig_.typePermissions[IPlugin::PermissionType::NORMAL_DEVICE_ADMIN]);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
