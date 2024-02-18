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

#define protected public
#include "iplugin_template_test.h"
#undef protected

#include "policy_manager.h"
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
/**
 * @tc.name: TestTemplate
 * @tc.desc: Test PluginTemplate init.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestTemplate, TestSize.Level1)
{
    PluginManager::GetInstance()->AddPlugin(PLUGIN::ArrayTestPlugin::GetPlugin());
    PluginManager::GetInstance()->AddPlugin(PLUGIN::BoolTestPlugin::GetPlugin());
    PluginManager::GetInstance()->AddPlugin(PLUGIN::MapTestPlugin::GetPlugin());
    PluginManager::GetInstance()->AddPlugin(PLUGIN::ArrayMapTestPlugin::GetPlugin());
    PluginManager::GetInstance()->AddPlugin(PLUGIN::JsonTestPlugin::GetPlugin());
    PluginManager::GetInstance()->AddPlugin(PLUGIN::StringTestPlugin::GetPlugin());

    std::vector<std::uint32_t> policyCodes = {10, 11, 12, 13, 14, 15};
    for (auto policyCode : policyCodes) {
        uint32_t funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
        std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
        ASSERT_TRUE(plugin != nullptr);
        ASSERT_TRUE(plugin->GetCode() == policyCode);
    }
}

/**
 * @tc.name: TestInitAttribute
 * @tc.desc: Test PluginTemplate InitAttribute func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestInitAttribute, TestSize.Level1)
{
    int policyCode = 20;
    PluginManager::GetInstance()->AddPlugin(PLUGIN::InitAttributePlg::GetPlugin());
    uint32_t funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);
    ASSERT_TRUE(plugin->GetPermission(FuncOperateType::GET) == "ohos.permission.EDM_TEST_PERMISSION");
    ASSERT_TRUE(plugin->GetPolicyName() == "InitAttributePlg");
    ASSERT_TRUE(plugin->GetCode() == 20);
}

/**
 * @tc.name: TestHandlePolicySupplier
 * @tc.desc: Test PluginTemplate HandlePolicySupplier func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestHandlePolicySupplier, TestSize.Level1)
{
    int policyCode = 21;
    ErrCode res;
    MessageParcel data;
    MessageParcel reply;
    uint32_t funcCode;
    std::shared_ptr<IPlugin> plugin;
    std::string setPolicyValue;
    HandlePolicyData handlePolicyData{"", false};
    PluginManager::GetInstance()->AddPlugin(PLUGIN::HandlePolicySupplierPlg::GetPlugin());
    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
    plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);

    setPolicyValue = R"({"k1":"v1","k2":"v2","k3":3})";
    data.WriteString(setPolicyValue);
    g_visit = false;
    res = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(res != ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData.empty());
    ASSERT_TRUE(g_visit);

    setPolicyValue = R"({"k1":"v1","k2":"v2","k3":3})";
    handlePolicyData.policyData = "";
    handlePolicyData.isChanged = false;
    data.WriteString(setPolicyValue);
    g_visit = false;
    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::REMOVE, policyCode);
    res = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(res != ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData.empty());
    ASSERT_TRUE(g_visit);
}

/**
 * @tc.name: TestHandlePolicyFunction
 * @tc.desc: Test PluginTemplate HandlePolicyFunction func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestHandlePolicyFunction, TestSize.Level1)
{
    int policyCode = 22;
    ErrCode res;
    MessageParcel data;
    MessageParcel reply;
    uint32_t funcCode;
    std::shared_ptr<IPlugin> plugin;
    std::string setPolicyValue;
    HandlePolicyData handlePolicyData{"", false};
    PluginManager::GetInstance()->AddPlugin(PLUGIN::HandlePolicyFunctionPlg::GetPlugin());

    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
    plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);
    setPolicyValue = "testValue";
    data.WriteString(setPolicyValue);
    res = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "newTestValue");
    ASSERT_TRUE(handlePolicyData.isChanged);

    setPolicyValue = "";
    handlePolicyData.policyData = "";
    handlePolicyData.isChanged = false;
    data.WriteString(setPolicyValue);
    res = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "testValue");
    ASSERT_TRUE(handlePolicyData.isChanged);

    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::REMOVE, policyCode);
    plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);
    setPolicyValue = "";
    handlePolicyData.policyData = "testValue";
    handlePolicyData.isChanged = false;
    data.WriteString(setPolicyValue);
    res = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData.empty());
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestHandlePolicyBiFunction
 * @tc.desc: Test PluginTemplate HandlePolicyBiFunction func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestHandlePolicyBiFunction, TestSize.Level1)
{
    int policyCode = 23;
    ErrCode res;
    MessageParcel data;
    MessageParcel reply;
    uint32_t funcCode;
    std::shared_ptr<IPlugin> plugin;
    std::string setPolicyValue;
    HandlePolicyData handlePolicyData{"", false};
    PluginManager::GetInstance()->AddPlugin(PLUGIN::HandlePolicyBiFunctionPlg::GetPlugin());

    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
    plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);
    setPolicyValue = "testValue";
    data.WriteString(setPolicyValue);
    res = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "testValue");
    ASSERT_TRUE(handlePolicyData.isChanged);

    setPolicyValue = "testValue";
    handlePolicyData.policyData = "testValue";
    handlePolicyData.isChanged = false;
    data.WriteString(setPolicyValue);
    res = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "testValue");
    ASSERT_TRUE(!handlePolicyData.isChanged);

    setPolicyValue = "";
    handlePolicyData.policyData = "testValue";
    handlePolicyData.isChanged = false;
    data.WriteString(setPolicyValue);
    res = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData.empty());
    ASSERT_TRUE(handlePolicyData.isChanged);

    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::REMOVE, policyCode);
    plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);
    setPolicyValue = "";
    handlePolicyData.policyData = "testValue";
    handlePolicyData.isChanged = false;
    data.WriteString(setPolicyValue);
    res = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData.empty());
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestHandlePolicyDone
 * @tc.desc: Test PluginTemplate HandlePolicyDone func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestHandlePolicyDone, TestSize.Level1)
{
    std::vector<int> policyCodes = {24, 25};
    MessageParcel data;
    uint32_t funcCode;
    std::shared_ptr<IPlugin> plugin;
    std::string adminName;
    PluginManager::GetInstance()->AddPlugin(PLUGIN::HandleDoneBoolConsumerPlg::GetPlugin());
    PluginManager::GetInstance()->AddPlugin(PLUGIN::HandleDoneBiBoolConsumerPlg::GetPlugin());

    for (int policyCode : policyCodes) {
        funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
        plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
        ASSERT_TRUE(plugin != nullptr);
        adminName = "com.edm.test.demo";
        g_visit = false;
        plugin->OnHandlePolicyDone(funcCode, adminName, true, DEFAULT_USER_ID);
        ASSERT_TRUE(g_visit);

        g_visit = false;
        funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::REMOVE, policyCode);
        plugin->OnHandlePolicyDone(funcCode, adminName, false, DEFAULT_USER_ID);
        ASSERT_TRUE(g_visit);
    }
}

/**
 * @tc.name: TestAdminRemove
 * @tc.desc: Test PluginTemplate AdminRemove func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestAdminRemove, TestSize.Level1)
{
    std::vector<int> policyCodes = {26, 27};
    MessageParcel data;
    uint32_t funcCode;
    std::shared_ptr<IPlugin> plugin;
    std::string adminName;
    std::string policyValue;
    PluginManager::GetInstance()->AddPlugin(PLUGIN::AdminRemoveSupplierPlg::GetPlugin());
    PluginManager::GetInstance()->AddPlugin(PLUGIN::AdminRemoveBiFunctionPlg::GetPlugin());

    for (int policyCode : policyCodes) {
        funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
        plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);

        adminName = "com.edm.test.demo";
        policyValue = "testValue";
        g_visit = false;
        plugin->OnAdminRemove(adminName, policyValue, DEFAULT_USER_ID);
        ASSERT_TRUE(g_visit);
    }
}

/**
 * @tc.name: TestAdminRemove
 * @tc.desc: Test PluginTemplate AdminRemoveDone func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestAdminRemoveDone, TestSize.Level1)
{
    std::vector<int> policyCodes = {28, 29};
    MessageParcel data;
    uint32_t funcCode;
    std::shared_ptr<IPlugin> plugin;
    std::string adminName;
    std::string policyValue;
    PluginManager::GetInstance()->AddPlugin(PLUGIN::AdminRemoveDoneRunnerPlg::GetPlugin());
    PluginManager::GetInstance()->AddPlugin(PLUGIN::AdminRemoveDoneBiBiConsumerPlg::GetPlugin());

    for (int policyCode : policyCodes) {
        funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
        plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);

        adminName = "com.edm.test.demo";
        policyValue = "testValue";
        g_visit = false;
        plugin->OnAdminRemoveDone(adminName, policyValue, DEFAULT_USER_ID);
        ASSERT_TRUE(g_visit);
    }
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test PluginTemplate OnGetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestOnGetPolicy, TestSize.Level1)
{
    int policyCode = 30;
    MessageParcel reply;
    MessageParcel data;
    PluginManager::GetInstance()->AddPlugin(PLUGIN::HandlePolicyJsonBiFunctionPlg::GetPlugin());
    uint32_t funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::GET, policyCode);
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    std::string policyData{"TestData"};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestWritePolicyToParcel
 * @tc.desc: Test PluginTemplate WritePolicyToParcel func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestWritePolicyToParcel, TestSize.Level1)
{
    int policyCode = 22;
    MessageParcel reply;
    PluginManager::GetInstance()->AddPlugin(PLUGIN::HandlePolicyFunctionPlg::GetPlugin());
    uint32_t funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::GET, policyCode);
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    std::string policyData = "testValue";
    ErrCode ret = plugin->WritePolicyToParcel(policyData, reply);
    ASSERT_TRUE(ret == ERR_OK);
    std::string temp;
    reply.ReadString(temp);
    ASSERT_TRUE(temp == policyData);
}

/**
 * @tc.name: TestHandlePolicyReplyFunctionPlg
 * @tc.desc: Test PluginTemplate TestHandlePolicyReplyFunctionPlg func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestHandlePolicyReplyFunctionPlg, TestSize.Level1)
{
    int policyCode = 32;
    PluginManager::GetInstance()->AddPlugin(PLUGIN::HandlePolicyReplyFunctionPlg::GetPlugin());
    uint32_t funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);
    std::string setPolicyValue = "testValue";
    HandlePolicyData handlePolicyData{"", false};
    MessageParcel data;
    data.WriteString(setPolicyValue);
    MessageParcel reply;
    ErrCode res = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "testValue");
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestDestroyPlugin
 * @tc.desc: Test PluginTemplate DestroyPlugin func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestDestroyPlugin, TestSize.Level1)
{
    MessageParcel reply;
    PLUGIN::HandlePolicyJsonBiFunctionPlg::GetPlugin();
    ASSERT_TRUE(PLUGIN::HandlePolicyJsonBiFunctionPlg::pluginInstance_ != nullptr);
    PLUGIN::HandlePolicyJsonBiFunctionPlg::DestroyPlugin();
    ASSERT_TRUE(PLUGIN::HandlePolicyJsonBiFunctionPlg::pluginInstance_ == nullptr);
}

void PluginTemplateTest::SetUp()
{
    if (policyManager_ == nullptr) {
        policyManager_ = std::make_shared<PolicyManager>();
    }
    IPolicyManager::policyManagerInstance_ = policyManager_.get();
}

void PluginTemplateTest::TearDown()
{
    PluginManager::GetInstance().reset();
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS