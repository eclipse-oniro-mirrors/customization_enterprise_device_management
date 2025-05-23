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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "domain_chain_rule.h"
#include "firewall_rule.h"
#include "iptables_manager_test.h"

#define private public
#define protected public
#include "executer_factory.h"
#include "rule_utils.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace testing;
using namespace OHOS::EDM::IPTABLES;

using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgReferee;
using ::testing::Invoke;

namespace OHOS {
namespace EDM {
namespace IPTABLES {
namespace TEST {

void IptablesManagerTest::SetUp()
{
    executerUtilsMock = std::make_shared<ExecuterUtilsMock>();
    ExecuterUtils::instance_ = executerUtilsMock;

    iptablesManager = IptablesManager::GetInstance();
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    iptablesManager->Init();
}

void IptablesManagerTest::TearDown()
{
    ExecuterUtils::instance_ = nullptr;
    ExecuterFactory::instance_ = nullptr;
    IptablesManager::instance_ = nullptr;
}

/**
 * @tc.name: TestInit
 * @tc.desc: Test Init func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestInit, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    iptablesManager->Init();
    EXPECT_EQ(iptablesManager->HasInit(), true);
}

/**
 * @tc.name: TestAddFilewallSuccess
 * @tc.desc: Test AddFilewall func success.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestAddFilewallSuccess, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    std::vector<FirewallRule> validRules{
        {Direction::INPUT, Action::DENY, Protocol::UDP, "192.168.2.100", "192.168.2.200", "80", "90", ""},
        {Direction::INPUT, Action::REJECT, Protocol::UDP, "192.168.2.100", "192.168.2.200", "80", "90", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::TCP, "192.168.2.100", "", "", "", ""},
        {Direction::OUTPUT, Action::DENY, Protocol::ICMP, "", "", "", "", ""},
        {Direction::OUTPUT, Action::REJECT, Protocol::ICMP, "", "", "", "", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "192.168.1.1", "", "", "", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "192.168.1.1/20", "", "", "", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "", "192.168.1.1", "", "", ""},
        {Direction::OUTPUT, Action::DENY, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::OUTPUT, Action::REJECT, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::FORWARD, Action::DENY, Protocol::ICMP, "", "", "", "", ""},
        {Direction::FORWARD, Action::REJECT, Protocol::ICMP, "", "", "", "", ""},
        {Direction::FORWARD, Action::ALLOW, Protocol::INVALID, "192.168.1.1", "", "", "", ""},
        {Direction::FORWARD, Action::ALLOW, Protocol::INVALID, "192.168.1.1/20", "", "", "", ""},
        {Direction::FORWARD, Action::ALLOW, Protocol::INVALID, "", "192.168.1.1", "", "", ""},
        {Direction::FORWARD, Action::DENY, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::FORWARD, Action::REJECT, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "80", "", ""},
        {Direction::INPUT, Action::DENY, Protocol::INVALID, "", "", "80:90", "", ""},
        {Direction::INPUT, Action::REJECT, Protocol::INVALID, "", "", "80:90", "", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "80,90", "99", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "901", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "901:1000", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "901,1000", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "", "5555"}};
    for (const auto &item : validRules) {
        FirewallRuleParcel validFirewallRule{item};
        ErrCode ret = iptablesManager->AddFirewallRule(validFirewallRule);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.name: TestAddFilewallFail
 * @tc.desc: Test AddFilewall func fail.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestAddFilewallFail, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    std::vector<FirewallRule> invalidRules{
        {Direction::INPUT, Action::INVALID, Protocol::INVALID, "", "", "", "", "9999"},
        {Direction::FORWARD, Action::INVALID, Protocol::INVALID, "", "", "", "", "9999"},
        {Direction::INPUT, Action::ALLOW, Protocol::ALL, "", "", "80", "", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::ALL, "", "", "", "90", ""},
        {Direction::INPUT, Action::INVALID, Protocol::INVALID, "192.168.1.1", "", "", "", ""},
        {Direction::OUTPUT, Action::INVALID, Protocol::INVALID, "", "192.168.1.1", "", "", ""},
        {Direction::FORWARD, Action::INVALID, Protocol::INVALID, "", "192.168.1.1", "", "", ""},
        {Direction::INVALID, Action::ALLOW, Protocol::INVALID, "192.168.1.1", "192.168.2.1", "", "", ""},
        {Direction::INVALID, Action::DENY, Protocol::INVALID, "192.168.1.1", "192.168.2.1", "", "", ""},
        {Direction::INVALID, Action::REJECT, Protocol::INVALID, "192.168.1.1", "192.168.2.1", "", "", ""}};
    for (const auto &item : invalidRules) {
        FirewallRuleParcel invalidFirewallRule{item};
        ErrCode ret = iptablesManager->RemoveFirewallRule(invalidFirewallRule);
        EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    }
}

/**
 * @tc.name: TestAddFilewallError
 * @tc.desc: Test AddFilewall func error.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestAddFilewallError, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    ExecuterFactory::instance_ = std::make_shared<ExecuterFactory>();

    std::vector<FirewallRule> validRules{
        {Direction::INPUT, Action::DENY, Protocol::UDP, "192.168.2.100", "192.168.2.200", "80", "90", ""},
        {Direction::INPUT, Action::REJECT, Protocol::UDP, "192.168.2.100", "192.168.2.200", "80", "90", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::TCP, "192.168.2.100", "", "", "", ""},
        {Direction::OUTPUT, Action::DENY, Protocol::ICMP, "", "", "", "", ""},
        {Direction::OUTPUT, Action::REJECT, Protocol::ICMP, "", "", "", "", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "192.168.1.1", "", "", "", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "192.168.1.1/20", "", "", "", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "", "192.168.1.1", "", "", ""},
        {Direction::OUTPUT, Action::DENY, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::OUTPUT, Action::REJECT, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::FORWARD, Action::DENY, Protocol::ICMP, "", "", "", "", ""},
        {Direction::FORWARD, Action::REJECT, Protocol::ICMP, "", "", "", "", ""},
        {Direction::FORWARD, Action::ALLOW, Protocol::INVALID, "192.168.1.1", "", "", "", ""},
        {Direction::FORWARD, Action::ALLOW, Protocol::INVALID, "192.168.1.1/20", "", "", "", ""},
        {Direction::FORWARD, Action::ALLOW, Protocol::INVALID, "", "192.168.1.1", "", "", ""},
        {Direction::FORWARD, Action::DENY, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::FORWARD, Action::REJECT, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "80", "", ""},
        {Direction::INPUT, Action::DENY, Protocol::INVALID, "", "", "80-90", "", ""},
        {Direction::INPUT, Action::REJECT, Protocol::INVALID, "", "", "80-90", "", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "80,90", "", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "901", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "901-1000", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "901,1000", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "", "5555"}};
    for (const auto &item : validRules) {
        FirewallRuleParcel validFirewallRule{item};
        ErrCode ret = iptablesManager->AddFirewallRule(validFirewallRule);
        EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    }
}

/**
 * @tc.name: TestAddFilewallParamError
 * @tc.desc: Test AddFilewall func param error.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestAddFilewallParamError, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    ExecuterFactory::instance_ = std::make_shared<ExecuterFactory>();

    std::vector<FirewallRule> validRules{
        {Direction::OUTPUT, Action::INVALID, Protocol::INVALID, "", "", "", "", "5555"},
        {Direction::FORWARD, Action::INVALID, Protocol::INVALID, "", "", "", "", "5555"},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "901,1000", "123"}};
    for (const auto &item : validRules) {
        FirewallRuleParcel validFirewallRule{item};
        ErrCode ret = iptablesManager->AddFirewallRule(validFirewallRule);
        EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    }
}

/**
 * @tc.name: TestRemoveFilewallSuccess
 * @tc.desc: Test RemoveFilewall func success.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestRemoveFilewallSuccess, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    std::vector<FirewallRule> validRules{{Direction::INVALID, Action::INVALID, Protocol::INVALID, "", "", "", "", ""},
        {Direction::INPUT, Action::DENY, Protocol::UDP, "192.168.2.100", "192.168.2.200", "80", "90", ""},
        {Direction::INPUT, Action::REJECT, Protocol::UDP, "192.168.2.100", "192.168.2.200", "80", "90", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::TCP, "192.168.2.100", "", "", "", ""},
        {Direction::OUTPUT, Action::DENY, Protocol::ICMP, "", "", "", "", ""},
        {Direction::OUTPUT, Action::REJECT, Protocol::ICMP, "", "", "", "", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "192.168.1.1", "", "", "", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "192.168.1.1/20", "", "", "", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "", "192.168.1.1", "", "", ""},
        {Direction::OUTPUT, Action::DENY, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::OUTPUT, Action::REJECT, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::FORWARD, Action::DENY, Protocol::ICMP, "", "", "", "", ""},
        {Direction::FORWARD, Action::REJECT, Protocol::ICMP, "", "", "", "", ""},
        {Direction::FORWARD, Action::ALLOW, Protocol::INVALID, "192.168.1.1", "", "", "", ""},
        {Direction::FORWARD, Action::ALLOW, Protocol::INVALID, "192.168.1.1/20", "", "", "", ""},
        {Direction::FORWARD, Action::ALLOW, Protocol::INVALID, "", "192.168.1.1", "", "", ""},
        {Direction::FORWARD, Action::DENY, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::FORWARD, Action::REJECT, Protocol::INVALID, "", "192.168.1.1/20", "", "", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "80", "", ""},
        {Direction::INPUT, Action::DENY, Protocol::INVALID, "", "", "80-90", "", ""},
        {Direction::INPUT, Action::REJECT, Protocol::INVALID, "", "", "80-90", "", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "80,90", "", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "901", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "901-1000", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "901,1000", ""},
        {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "", "5555"}};
    for (const auto &item : validRules) {
        FirewallRuleParcel validFirewallRule{item};
        ErrCode ret = iptablesManager->RemoveFirewallRule(validFirewallRule);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.name: TestRemoveFilewallFail
 * @tc.desc: Test RemoveFilewall func fail.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestRemoveFilewallFail, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    std::vector<FirewallRule> invalidRules{
        {Direction::INPUT, Action::INVALID, Protocol::INVALID, "", "", "", "", "9999"},
        {Direction::FORWARD, Action::INVALID, Protocol::INVALID, "", "", "", "", "9999"},
        {Direction::INPUT, Action::ALLOW, Protocol::ALL, "", "", "80", "", ""},
        {Direction::INPUT, Action::ALLOW, Protocol::ALL, "", "", "", "90", ""},
        {Direction::INVALID, Action::ALLOW, Protocol::INVALID, "", "", "", "", ""},
        {Direction::INVALID, Action::INVALID, Protocol::ALL, "", "", "", "", ""},
        {Direction::INVALID, Action::INVALID, Protocol::UDP, "", "", "", "", ""},
        {Direction::INVALID, Action::INVALID, Protocol::TCP, "", "", "", "", ""},
        {Direction::INVALID, Action::INVALID, Protocol::ICMP, "", "", "", "", ""},
        {Direction::INVALID, Action::INVALID, Protocol::INVALID, "192.168.1.1", "", "", "", ""},
        {Direction::INVALID, Action::INVALID, Protocol::INVALID, "", "192.168.1.1", "", "", ""},
        {Direction::INVALID, Action::INVALID, Protocol::INVALID, "", "", "80", "", ""},
        {Direction::INVALID, Action::INVALID, Protocol::INVALID, "", "", "", "901", ""},
        {Direction::INVALID, Action::INVALID, Protocol::INVALID, "", "", "", "901", "5555"}};
    for (const auto &item : invalidRules) {
        FirewallRuleParcel invalidFirewallRule{item};
        ErrCode ret = iptablesManager->RemoveFirewallRule(invalidFirewallRule);
        EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    }
}

/**
 * @tc.name: GetFirewallRulesTest1
 * @tc.desc: Test GetFirewallRules func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, GetFirewallRulesTest1, TestSize.Level1)
{
    std::string result =
        "Chain edm_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 DROP       udp  --  *      *       0.0.0.0/0            10.1.1.1             "
        "source IP range 192.168.1.1-192.188.22.66 udp spt:8080 dpt:8080";
    std::string resultEmpty =
        "Chain edm_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(9)
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)));

    std::vector<FirewallRuleParcel> list;
    ErrCode ret = iptablesManager->GetFirewallRules(list);
    EXPECT_TRUE(ret == ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}

/**
 * @tc.name: GetFirewallRulesTest2
 * @tc.desc: Test GetFirewallRules func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, GetFirewallRulesTest2, TestSize.Level1)
{
    std::string result =
        "Chain edm_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 DROP       udp  --  *      *       0.0.0.0/0            10.1.1.1             "
        "source IP range 192.168.1.1-192.188.22.66 udp spt:8080 dpt:8080 owner UID match 9696";
    std::string resultEmpty =
        "Chain edm_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(9)
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)));

    std::vector<FirewallRuleParcel> list;
    ErrCode ret = iptablesManager->GetFirewallRules(list);
    EXPECT_TRUE(ret == ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}

/**
 * @tc.name: GetFirewallRulesTest3
 * @tc.desc: Test GetFirewallRules func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, GetFirewallRulesTest3, TestSize.Level1)
{
    std::string result =
        "Chain edm_deny_input (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 DROP       udp  --  *      *       0.0.0.0/0            10.1.1.1             "
        "source IP range 192.168.1.1-192.188.22.66 udp spt:8080 dpt:8080 owner UID match 9696";
    std::string resultEmpty =
        "Chain edm_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(9)
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)));

    std::vector<FirewallRuleParcel> list;
    ErrCode ret = iptablesManager->GetFirewallRules(list);
    EXPECT_TRUE(ret == ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}

/**
 * @tc.name: GetFirewallRulesTest4
 * @tc.desc: Test GetFirewallRules func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, GetFirewallRulesTest4, TestSize.Level1)
{
    std::string result =
        "Chain edm_reject_forward (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 REJECT     all  --  *      *       172.16.100.2         172.19.90.131        "
        "reject-with icmp-port-unreachable";
    std::string resultEmpty =
        "Chain edm_reject_forward (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(9)
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)));

    std::vector<FirewallRuleParcel> list;
    ErrCode ret = iptablesManager->GetFirewallRules(list);
    EXPECT_TRUE(ret == ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}

/**
 * @tc.name: GetFirewallRulesTest5
 * @tc.desc: Test GetFirewallRules func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, GetFirewallRulesTest5, TestSize.Level1)
{
    std::string result =
        "Chain edm_reject_forward (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 REJECT     udp  --  *      *       172.16.100.2         172.19.90.131        "
        "reject-with icmp-port-unreachable";
    std::string resultEmpty =
        "Chain edm_reject_forward (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(9)
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)));

    std::vector<FirewallRuleParcel> list;
    ErrCode ret = iptablesManager->GetFirewallRules(list);
    EXPECT_TRUE(ret == ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}

/**
 * @tc.name: TestAddDomainFilterSuccess
 * @tc.desc: Test AddDomainFilter func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestAddDomainFilterSuccess, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    std::vector<DomainFilterRule> validRules{
        {Action::ALLOW, "1000", "www.example.com", Direction::INVALID},
        {Action::ALLOW, "1000", "www.example.com", Direction::OUTPUT},
        {Action::DENY, "1000", "www.example.com", Direction::OUTPUT},
        {Action::ALLOW, "", "www.example.com", Direction::OUTPUT},
        {Action::DENY, "", "www.example.com", Direction::OUTPUT},
        {Action::ALLOW, "", "www.example.com", Direction::FORWARD},
        {Action::DENY, "", "www.example.com", Direction::FORWARD},
    };
    for (const auto &item : validRules) {
        DomainFilterRuleParcel validDomainFilterRuleParcel{item};
        ErrCode ret = iptablesManager->AddDomainFilterRule(validDomainFilterRuleParcel);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.name: TestAddDomainFilterFail
 * @tc.desc: Test AddDomainFilter func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestAddDomainFilterFail, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    std::string invalidDomainName;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 63; ++j) {
            invalidDomainName += "a";
        }
        invalidDomainName += ".";
    }

    std::vector<DomainFilterRule> invalidRules{
        {Action::ALLOW, "1000", "", Direction::OUTPUT},
        {Action::INVALID, "1000", "www.example.com", Direction::OUTPUT},
        {Action::DENY, "1000", "www.ex||ample.com", Direction::OUTPUT},
        {Action::ALLOW, "1000", "www.ex/ample.com", Direction::OUTPUT},
        {Action::INVALID, "1000", invalidDomainName, Direction::OUTPUT},
        {Action::ALLOW, "1000", "", Direction::FORWARD},
        {Action::INVALID, "1000", "www.example.com", Direction::FORWARD},
        {Action::DENY, "1000", "www.ex||ample.com", Direction::FORWARD},
        {Action::ALLOW, "1000", "www.ex/ample.com", Direction::FORWARD},
        {Action::INVALID, "1000", invalidDomainName, Direction::FORWARD},
        {Action::ALLOW, "1000", "", Direction::INVALID},
        {Action::INVALID, "1000", "www.example.com", Direction::INVALID},
        {Action::DENY, "1000", "www.ex||ample.com", Direction::INVALID},
        {Action::ALLOW, "1000", "www.ex/ample.com", Direction::INVALID},
        {Action::INVALID, "1000", invalidDomainName, Direction::INVALID}};
    for (const auto &item : invalidRules) {
        DomainFilterRuleParcel invalidDomainFilterRuleParcel{item};
        ErrCode ret = iptablesManager->AddDomainFilterRule(invalidDomainFilterRuleParcel);
        EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    }
}

/**
 * @tc.name: TestAddDomainFilterError
 * @tc.desc: Test AddDomainFilter func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestAddDomainFilterError, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    ExecuterFactory::instance_ = std::make_shared<ExecuterFactory>();

    std::vector<DomainFilterRule> validRules{
        {Action::ALLOW, "1000", "www.example.com", Direction::OUTPUT},
        {Action::DENY, "1000", "www.example.com", Direction::OUTPUT},
        {Action::ALLOW, "", "www.example.com", Direction::OUTPUT},
        {Action::DENY, "", "www.example.com", Direction::OUTPUT},
        {Action::ALLOW, "", "www.example.com", Direction::FORWARD},
        {Action::DENY, "", "www.example.com", Direction::FORWARD},
    };
    for (const auto &item : validRules) {
        DomainFilterRuleParcel validDomainFilterRuleParcel{item};
        ErrCode ret = iptablesManager->AddDomainFilterRule(validDomainFilterRuleParcel);
        EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    }
}

/**
 * @tc.name: TestRemoveDomainFilterSuccess
 * @tc.desc: Test RemoveDomainFilter func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestRemoveDomainFilterSuccess, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    std::vector<DomainFilterRule> validRules{
        {Action::INVALID, "", "", Direction::INVALID},
        {Action::INVALID, "", "", Direction::OUTPUT},
        {Action::ALLOW, "", "", Direction::INVALID},
        {Action::ALLOW, "", "", Direction::OUTPUT},
        {Action::DENY, "", "", Direction::OUTPUT},
        {Action::ALLOW, "1000", "www.example.com", Direction::OUTPUT},
        {Action::DENY, "1000", "www.example.com", Direction::OUTPUT},
        {Action::ALLOW, "", "www.example.com", Direction::OUTPUT},
        {Action::DENY, "", "www.example.com", Direction::OUTPUT},
        {Action::INVALID, "", "", Direction::FORWARD},
        {Action::ALLOW, "", "", Direction::FORWARD},
        {Action::DENY, "", "", Direction::FORWARD},
        {Action::ALLOW, "", "www.example.com", Direction::FORWARD},
        {Action::DENY, "", "www.example.com", Direction::FORWARD},
    };
    for (const auto &item : validRules) {
        DomainFilterRuleParcel validDomainFilterRuleParcel{item};
        ErrCode ret = iptablesManager->RemoveDomainFilterRules(validDomainFilterRuleParcel);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.name: TestRemoveDomainFilterFail
 * @tc.desc: Test RemoveDomainFilter func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestRemoveDomainFilterFail, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    std::vector<DomainFilterRule> invalidRules{
        {Action::ALLOW, "1000", "", Direction::OUTPUT},
        {Action::DENY, "1000", "", Direction::OUTPUT},
        {Action::INVALID, "", "www.example.com", Direction::OUTPUT},
        {Action::INVALID, "1000", "www.example.com", Direction::OUTPUT},
        {Action::DENY, "1000", "www.ex||ample.com", Direction::OUTPUT},
        {Action::ALLOW, "1000", "www.ex/ample.com", Direction::OUTPUT},
        {Action::ALLOW, "1000", "", Direction::FORWARD},
        {Action::DENY, "1000", "", Direction::FORWARD},
        {Action::INVALID, "", "www.example.com", Direction::FORWARD},
        {Action::INVALID, "1000", "www.example.com", Direction::FORWARD},
        {Action::DENY, "1000", "www.ex||ample.com", Direction::FORWARD},
        {Action::ALLOW, "1000", "www.ex/ample.com", Direction::FORWARD},
    };
    for (const auto &item : invalidRules) {
        DomainFilterRuleParcel invalidDomainFilterRuleParcel{item};
        ErrCode ret = iptablesManager->RemoveDomainFilterRules(invalidDomainFilterRuleParcel);
        EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    }
}

/**
 * @tc.name: TestGetDomainFilterRules1
 * @tc.desc: Test GetDomainFilterRules func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestGetDomainFilterRules1, TestSize.Level1)
{
    std::string result =
        "Chain edm_dns_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 DROP       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "udp dpt:53 owner UID match 9696 STRING match  \"|03777777076578616d706c6503636f6d|\" ALGO name bm TO 65535";
    std::string resultEmpty =
        "Chain edm_dns_deny_forward (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(6)
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)));

    std::vector<DomainFilterRuleParcel> list;
    ErrCode ret = iptablesManager->GetDomainFilterRules(list);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}

/**
 * @tc.name: TestGetDomainFilterRules2
 * @tc.desc: Test GetDomainFilterRules func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestGetDomainFilterRules2, TestSize.Level1)
{
    std::string result =
        "Chain edm_dns_reject_forward (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 REJECT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "udp dpt:53 STRING match  \"|037777770667697468756203636f6d|\" ALGO name bm TO 65535 "
        "reject-with icmp-port-unreachable";
    std::string resultEmpty =
        "Chain edm_dns_reject_forward (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(6)
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)));

    std::vector<DomainFilterRuleParcel> list;
    ErrCode ret = iptablesManager->GetDomainFilterRules(list);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}

/**
 * @tc.name: TestGetRemoveChainNameSuccess
 * @tc.desc: Test GetRemoveChainName func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestGetRemoveChainNameSuccess, TestSize.Level1)
{
    std::vector<std::string> chainNameList;
    std::vector<std::string> expectList;
    ErrCode ret = ERR_OK;

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::INPUT, Action::ALLOW, chainNameList);
    EXPECT_TRUE(ret == ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 1);
    expectList = {EDM_ALLOW_INPUT_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::INPUT, Action::DENY, chainNameList);
    EXPECT_TRUE(ret == ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 1);
    expectList = {EDM_DENY_INPUT_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::INPUT, Action::REJECT, chainNameList);
    EXPECT_TRUE(ret == ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 1);
    expectList = {EDM_REJECT_INPUT_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::INPUT, Action::INVALID, chainNameList);
    EXPECT_TRUE(ret == ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 3);
    expectList = {EDM_ALLOW_INPUT_CHAIN_NAME, EDM_DENY_INPUT_CHAIN_NAME, EDM_REJECT_INPUT_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);
}

/**
 * @tc.name: TestGetRemoveChainNameSuccess1
 * @tc.desc: Test GetRemoveChainName func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestGetRemoveChainNameSuccess1, TestSize.Level1)
{
    std::vector<std::string> chainNameList;
    std::vector<std::string> expectList;
    ErrCode ret = ERR_OK;

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::OUTPUT, Action::ALLOW, chainNameList);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 1);
    expectList = {EDM_ALLOW_OUTPUT_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::OUTPUT, Action::DENY, chainNameList);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 1);
    expectList = {EDM_DENY_OUTPUT_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);

        chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::OUTPUT, Action::REJECT, chainNameList);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 1);
    expectList = {EDM_REJECT_OUTPUT_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::OUTPUT, Action::INVALID, chainNameList);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 3);
    expectList = {EDM_ALLOW_OUTPUT_CHAIN_NAME, EDM_DENY_OUTPUT_CHAIN_NAME, EDM_REJECT_OUTPUT_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);
}

/**
 * @tc.name: TestGetRemoveChainNameSuccess2
 * @tc.desc: Test GetRemoveChainName func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestGetRemoveChainNameSuccess2, TestSize.Level1)
{
    std::vector<std::string> chainNameList;
    std::vector<std::string> expectList;
    ErrCode ret = ERR_OK;

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::INVALID, Action::INVALID, chainNameList);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 9);
}

/**
 * @tc.name: TestGetRemoveChainNameSuccess3
 * @tc.desc: Test GetRemoveChainName func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestGetRemoveChainNameSuccess3, TestSize.Level1)
{
    std::vector<std::string> chainNameList;
    std::vector<std::string> expectList;
    ErrCode ret = ERR_OK;

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::FORWARD, Action::ALLOW, chainNameList);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 1);
    expectList = {EDM_ALLOW_FORWARD_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::FORWARD, Action::DENY, chainNameList);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 1);
    expectList = {EDM_DENY_FORWARD_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::FORWARD, Action::REJECT, chainNameList);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 1);
    expectList = {EDM_REJECT_FORWARD_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::FORWARD, Action::INVALID, chainNameList);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(chainNameList.size() == 3);
    expectList = {EDM_ALLOW_FORWARD_CHAIN_NAME, EDM_DENY_FORWARD_CHAIN_NAME, EDM_REJECT_FORWARD_CHAIN_NAME};
    EXPECT_EQ(chainNameList, expectList);
}


/**
 * @tc.name: TestGetRemoveChainNameFail
 * @tc.desc: Test GetRemoveChainName func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestGetRemoveChainNameFail, TestSize.Level1)
{
    std::vector<std::string> chainNameList;
    std::vector<std::string> expectList;
    ErrCode ret = ERR_OK;

    chainNameList = {};
    ret = iptablesManager->GetRemoveChainName(Direction::INVALID, Action::DENY, chainNameList);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);

    ret = iptablesManager->GetRemoveChainName(Direction::INVALID, Action::ALLOW, chainNameList);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestExistOutputAllowFirewallRule
 * @tc.desc: Test ExistOutputAllowFirewallRule func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestExistOutputAllowFirewallRule, TestSize.Level1)
{
    std::string result =
        "Chain edm_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 DROP       udp  --  *      *       0.0.0.0/0            10.1.1.1             "
        "source IP range 192.168.1.1-192.188.22.66 udp spt:8080 dpt:8080";
    std::string resultEmpty =
        "Chain edm_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(2)
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(resultEmpty), Return(ERR_OK)))
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)));

    EXPECT_TRUE(iptablesManager->ExistOutputAllowFirewallRule());

    EXPECT_CALL(*executerUtilsMock, Execute).Times(2).WillOnce(DoAll(Return(ERR_OK))).WillOnce(DoAll(Return(ERR_OK)));
    EXPECT_FALSE(iptablesManager->ExistOutputAllowFirewallRule());
}

/**
 * @tc.name: TestExistOutputAllowDomainRule
 * @tc.desc: Test ExistOutputAllowDomainRule func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestExistOutputAllowDomainRule, TestSize.Level1)
{
    std::string result =
        "Chain edm_dns_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 DROP       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "udp dpt:53 owner UID match 9696 STRING match  \"|03777777076578616d706c6503636f6d|\" ALGO name bm TO 65535";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(1)
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)));

    EXPECT_TRUE(iptablesManager->ExistOutputAllowDomainRule());

    EXPECT_CALL(*executerUtilsMock, Execute).Times(1).WillOnce(DoAll(Return(ERR_OK)));
    EXPECT_FALSE(iptablesManager->ExistOutputAllowDomainRule());
}

/**
 * @tc.name: TestExistForwardAllowFirewallRule
 * @tc.desc: Test ExistForwardAllowFirewallRule func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestExistForwardAllowFirewallRule, TestSize.Level1)
{
    std::string result =
        "Chain edm_reject_forward (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 REJECT     all  --  *      *       172.16.100.2         172.19.90.131        "
        "reject-with icmp-port-unreachable";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(1)
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)));

    EXPECT_TRUE(iptablesManager->ExistForwardAllowFirewallRule());

    EXPECT_CALL(*executerUtilsMock, Execute).Times(1).WillOnce(DoAll(Return(ERR_OK))).WillOnce(DoAll(Return(ERR_OK)));
    EXPECT_FALSE(iptablesManager->ExistForwardAllowFirewallRule());
}

/**
 * @tc.name: TestExistForwardAllowDomainRule
 * @tc.desc: Test ExistForwardAllowDomainRule func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestExistForwardAllowDomainRule, TestSize.Level1)
{
    std::string result =
        "Chain edm_dns_reject_forward (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 REJECT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "udp dpt:53 STRING match  \"|037777770667697468756203636f6d|\" ALGO name bm TO 65535 "
        "reject-with icmp-port-unreachable";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .Times(1)
        .WillOnce(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)));

    EXPECT_TRUE(iptablesManager->ExistForwardAllowDomainRule());

    EXPECT_CALL(*executerUtilsMock, Execute).Times(1).WillOnce(DoAll(Return(ERR_OK)));
    EXPECT_FALSE(iptablesManager->ExistForwardAllowDomainRule());
}

/**
 * @tc.name: TestChainExistRule
 * @tc.desc: Test ChainExistRule func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestChainExistRule, TestSize.Level1)
{
    std::string result =
        "Chain edm_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 DROP       udp  --  *      *       0.0.0.0/0            10.1.1.1             "
        "source IP range 192.168.1.1-192.188.22.66 udp spt:8080 dpt:8080";
    EXPECT_CALL(*executerUtilsMock, Execute)
        .WillRepeatedly(DoAll(Invoke(PrintExecRule), SetArgReferee<1>(result), Return(ERR_OK)));

    std::vector<std::string> chainNameList = {EDM_ALLOW_INPUT_CHAIN_NAME, EDM_DENY_INPUT_CHAIN_NAME,
        EDM_ALLOW_OUTPUT_CHAIN_NAME, EDM_DENY_OUTPUT_CHAIN_NAME, EDM_ALLOW_FORWARD_CHAIN_NAME,
        EDM_DENY_FORWARD_CHAIN_NAME};
    EXPECT_TRUE(iptablesManager->ChainExistRule(chainNameList));

    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Return(ERR_OK)));
    EXPECT_FALSE(iptablesManager->ChainExistRule(chainNameList));
}

/**
 * @tc.name: TestStaticAttribute
 * @tc.desc: Test attribute.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesManagerTest, TestStaticAttribute, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Return(ERR_OK)));

    IptablesManager::g_defaultFirewallOutputChainInit = false;
    IptablesManager::SetDefaultFirewallDenyChain(IPTABLES::Direction::OUTPUT);
    EXPECT_TRUE(IptablesManager::g_defaultFirewallOutputChainInit);

    IptablesManager::ClearDefaultFirewallOutputDenyChain();
    EXPECT_FALSE(IptablesManager::g_defaultFirewallOutputChainInit);

    IptablesManager::g_defaultFirewallForwardChainInit = false;
    IptablesManager::SetDefaultFirewallDenyChain(IPTABLES::Direction::FORWARD);
    EXPECT_TRUE(IptablesManager::g_defaultFirewallForwardChainInit);

    IptablesManager::ClearDefaultFirewallForwardDenyChain();
    EXPECT_FALSE(IptablesManager::g_defaultFirewallForwardChainInit);

    IptablesManager::g_defaultDomainOutputChainInit = false;
    IptablesManager::SetDefaultDomainDenyChain(IPTABLES::Direction::OUTPUT);
    EXPECT_TRUE(IptablesManager::g_defaultDomainOutputChainInit);

    IptablesManager::ClearDefaultDomainOutputDenyChain();
    EXPECT_FALSE(IptablesManager::g_defaultDomainOutputChainInit);

    IptablesManager::g_defaultDomainForwardChainInit = false;
    IptablesManager::SetDefaultDomainDenyChain(IPTABLES::Direction::FORWARD);
    EXPECT_TRUE(IptablesManager::g_defaultDomainForwardChainInit);

    IptablesManager::ClearDefaultDomainForwardDenyChain();
    EXPECT_FALSE(IptablesManager::g_defaultDomainForwardChainInit);
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS