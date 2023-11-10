/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define private public
#include "domain_filter_rule_plugin.h"
#undef private
#include <gtest/gtest.h>

#define private public
#define protected public
#include "executer_factory.h"
#include "executer_utils.h"
#include "iptables_manager.h"
#undef protected
#undef private

#include "edm_ipc_interface_code.h"
#include "executer_utils_mock.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::EDM;
using namespace OHOS::EDM::IPTABLES;
using namespace OHOS::EDM::IPTABLES::TEST;

namespace OHOS {
namespace EDM {
namespace TEST {
class DomainFilterRulePluginTest : public testing::Test {
public:
    std::shared_ptr<ExecuterUtilsMock> executerUtilsMock;
    std::shared_ptr<IptablesManager> iptablesManager;

protected:
    void SetUp() override;
    void TearDown() override;
};

void DomainFilterRulePluginTest::SetUp()
{
    executerUtilsMock = std::make_shared<ExecuterUtilsMock>();
    ExecuterUtils::instance_ = executerUtilsMock;

    iptablesManager = IptablesManager::GetInstance();
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    iptablesManager->Init();
}

void DomainFilterRulePluginTest::TearDown()
{
    ExecuterUtils::instance_ = nullptr;
    ExecuterFactory::instance_ = nullptr;
    IptablesManager::instance_ = nullptr;
}

/**
 * @tc.name: TestInitPluginSuccess
 * @tc.desc: Test DomainFilterRulePlugin::InitPlugin success.
 * @tc.type: FUNC
 */
HWTEST_F(DomainFilterRulePluginTest, TestInitPluginSuccess, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DomainFilterRulePlugin::GetPlugin();
    ASSERT_TRUE(plugin->IsGlobalPolicy());
    ASSERT_TRUE(!plugin->NeedSavePolicy());
    ASSERT_TRUE(plugin->GetCode() == (std::uint32_t)EdmInterfaceCode::DOMAIN_FILTER_RULE);
    ASSERT_EQ(plugin->GetPolicyName(), "domain_filter_rule");
    ASSERT_EQ(plugin->GetPermission(FuncOperateType::SET), "ohos.permission.ENTERPRISE_MANAGE_NETWORK");
    ASSERT_TRUE(plugin->GetPermissionType(FuncOperateType::SET) == IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ASSERT_TRUE(plugin->GetPermission(FuncOperateType::GET) == "ohos.permission.ENTERPRISE_MANAGE_NETWORK");
    ASSERT_TRUE(plugin->GetPermissionType(FuncOperateType::GET) == IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
}

/**
 * @tc.name: TestOnSetPolicyTestSuccess
 * @tc.desc: Test DomainFilterRulePlugin::OnSetPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(DomainFilterRulePluginTest, TestOnSetPolicyTestSuccess, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    std::shared_ptr<DomainFilterRulePlugin> plugin = std::make_shared<DomainFilterRulePlugin>();
    IPTABLES::DomainFilterRule rule{IPTABLES::Action::ALLOW, "1000", "www.example.com"};
    IPTABLES::DomainFilterRuleParcel ruleParcel{rule};
    ErrCode ret = plugin->OnSetPolicy(ruleParcel);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyTestFail
 * @tc.desc: Test DomainFilterRulePlugin::OnSetPolicy fail.
 * @tc.type: FUNC
 */
HWTEST_F(DomainFilterRulePluginTest, TestOnSetPolicyTestFail, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));

    std::shared_ptr<DomainFilterRulePlugin> plugin = std::make_shared<DomainFilterRulePlugin>();
    IPTABLES::DomainFilterRule rule{IPTABLES::Action::ALLOW, "1000", "www.example.com"};
    IPTABLES::DomainFilterRuleParcel ruleParcel{rule};
    ErrCode ret = plugin->OnSetPolicy(ruleParcel);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: TestOnRemovePolicyTestSuccess
 * @tc.desc: Test DomainFilterRulePlugin::OnRemovePolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(DomainFilterRulePluginTest, TestOnRemovePolicyTestSuccess, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    std::shared_ptr<DomainFilterRulePlugin> plugin = std::make_shared<DomainFilterRulePlugin>();
    IPTABLES::DomainFilterRule rule{IPTABLES::Action::ALLOW, "1000", "www.example.com"};
    IPTABLES::DomainFilterRuleParcel ruleParcel{rule};
    ErrCode ret = plugin->OnRemovePolicy(ruleParcel);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnRemovePolicyTestFail
 * @tc.desc: Test DomainFilterRulePlugin::OnRemovePolicy fail.
 * @tc.type: FUNC
 */
HWTEST_F(DomainFilterRulePluginTest, TestOnRemovePolicyTestFail, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(-1)));

    std::shared_ptr<DomainFilterRulePlugin> plugin = std::make_shared<DomainFilterRulePlugin>();
    IPTABLES::DomainFilterRule rule{IPTABLES::Action::ALLOW, "1000", "www.example.com"};
    IPTABLES::DomainFilterRuleParcel ruleParcel{rule};
    ErrCode ret = plugin->OnRemovePolicy(ruleParcel);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicyTestSuccess
 * @tc.desc: Test DomainFilterRulePlugin::OnGetPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(DomainFilterRulePluginTest, TestOnGetPolicyTestSuccess, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    std::shared_ptr<DomainFilterRulePlugin> plugin = std::make_shared<DomainFilterRulePlugin>();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, 0);
    ASSERT_TRUE(ret == ERR_OK);
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    ASSERT_TRUE(blRes);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS