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

#include "iplugin_template_test.h"

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

    std::vector<std::uint32_t> policyCodes = { 10, 11, 12, 13, 14, 15 };
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
    ASSERT_TRUE(plugin->GetPermission() == "ohos.permission.EDM_TEST_PERMISSION");
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
    uint32_t funcCode;
    std::shared_ptr<IPlugin> plugin;
    std::string setPolicyValue;
    std::string policyValue;
    bool isChange;
    PluginManager::GetInstance()->AddPlugin(PLUGIN::HandlePolicySupplierPlg::GetPlugin());
    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
    plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);

    setPolicyValue = R"({"k1":"v1","k2":"v2","k3":3})";
    policyValue = "";
    isChange = false;
    data.WriteString16(Str8ToStr16(setPolicyValue));
    g_visit = false;
    res = plugin->OnHandlePolicy(funcCode, data, policyValue, isChange);
    ASSERT_TRUE(res != ERR_OK);
    ASSERT_TRUE(policyValue.empty());
    ASSERT_TRUE(g_visit);

    setPolicyValue = R"({"k1":"v1","k2":"v2","k3":3})";
    policyValue = "";
    isChange = false;
    data.WriteString16(Str8ToStr16(setPolicyValue));
    g_visit = false;
    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::REMOVE, policyCode);
    res = plugin->OnHandlePolicy(funcCode, data, policyValue, isChange);
    ASSERT_TRUE(res != ERR_OK);
    ASSERT_TRUE(policyValue.empty());
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
    uint32_t funcCode;
    std::shared_ptr<IPlugin> plugin;
    std::string setPolicyValue;
    std::string policyValue;
    bool isChange;
    PluginManager::GetInstance()->AddPlugin(PLUGIN::HandlePolicyFunctionPlg::GetPlugin());

    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
    plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);
    setPolicyValue = "testValue";
    policyValue = "";
    isChange = false;
    data.WriteString16(Str8ToStr16(setPolicyValue));
    res = plugin->OnHandlePolicy(funcCode, data, policyValue, isChange);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "newTestValue");
    ASSERT_TRUE(isChange);

    setPolicyValue = "";
    policyValue = "";
    isChange = false;
    data.WriteString16(Str8ToStr16(setPolicyValue));
    res = plugin->OnHandlePolicy(funcCode, data, policyValue, isChange);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "testValue");
    ASSERT_TRUE(isChange);

    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::REMOVE, policyCode);
    plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);
    setPolicyValue = "";
    policyValue = "testValue";
    isChange = false;
    data.WriteString16(Str8ToStr16(setPolicyValue));
    res = plugin->OnHandlePolicy(funcCode, data, policyValue, isChange);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue.empty());
    ASSERT_TRUE(isChange);
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
    uint32_t funcCode;
    std::shared_ptr<IPlugin> plugin;
    std::string setPolicyValue;
    std::string policyValue;
    bool isChange;
    PluginManager::GetInstance()->AddPlugin(PLUGIN::HandlePolicyBiFunctionPlg::GetPlugin());

    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, policyCode);
    plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);
    setPolicyValue = "testValue";
    policyValue = "";
    isChange = false;
    data.WriteString16(Str8ToStr16(setPolicyValue));
    res = plugin->OnHandlePolicy(funcCode, data, policyValue, isChange);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "testValue");
    ASSERT_TRUE(isChange);

    setPolicyValue = "testValue";
    policyValue = "testValue";
    isChange = false;
    data.WriteString16(Str8ToStr16(setPolicyValue));
    res = plugin->OnHandlePolicy(funcCode, data, policyValue, isChange);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "testValue");
    ASSERT_TRUE(!isChange);

    setPolicyValue = "";
    policyValue = "testValue";
    isChange = false;
    data.WriteString16(Str8ToStr16(setPolicyValue));
    res = plugin->OnHandlePolicy(funcCode, data, policyValue, isChange);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue.empty());
    ASSERT_TRUE(isChange);

    funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::REMOVE, policyCode);
    plugin = PluginManager::GetInstance()->GetPluginByFuncCode(funcCode);
    ASSERT_TRUE(plugin != nullptr);
    setPolicyValue = "";
    policyValue = "testValue";
    isChange = false;
    data.WriteString16(Str8ToStr16(setPolicyValue));
    res = plugin->OnHandlePolicy(funcCode, data, policyValue, isChange);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue.empty());
    ASSERT_TRUE(isChange);
}

/**
 * @tc.name: TestHandlePolicyDone
 * @tc.desc: Test PluginTemplate HandlePolicyDone func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginTemplateTest, TestHandlePolicyDone, TestSize.Level1)
{
    std::vector<int> policyCodes = { 24, 25 };
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
        plugin->OnHandlePolicyDone(funcCode, adminName, true);
        ASSERT_TRUE(g_visit);

        g_visit = false;
        funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::REMOVE, policyCode);
        plugin->OnHandlePolicyDone(funcCode, adminName, false);
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
    std::vector<int> policyCodes = { 26, 27 };
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
        plugin->OnAdminRemove(adminName, policyValue);
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
    std::vector<int> policyCodes = { 28, 29 };
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
        plugin->OnAdminRemoveDone(adminName, policyValue);
        ASSERT_TRUE(g_visit);
    }
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS