/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ipv4tables_manager_test.h"

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

void Ipv4tablesManagerTest::SetUp()
{
    executerUtilsMock = std::make_shared<ExecuterUtilsMock>();
    ExecuterUtils::instance_ = executerUtilsMock;

    ipv4tablesManager = std::make_shared<Ipv4tablesManager>();
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    ipv4tablesManager->Init();
}

void Ipv4tablesManagerTest::TearDown()
{
    ExecuterUtils::instance_ = nullptr;
    ExecuterFactory::instance_ = nullptr;
}

/**
 * @tc.name: TestHasInit
 * @tc.desc: Test HasInit func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv4tablesManagerTest, TestHasInit, TestSize.Level1)
{
    EXPECT_EQ(ipv4tablesManager->HasInit(), true);
}

/**
 * @tc.name: TestInit
 * @tc.desc: Test Init func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv4tablesManagerTest, TestInit, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    ipv4tablesManager->Init();
    EXPECT_EQ(ipv4tablesManager->HasInit(), true);
}

/**
 * @tc.name: TestAddFilewallRule
 * @tc.desc: Test AddFilewallRule func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv4tablesManagerTest, TestAddFilewallRule, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    FirewallRule firewallRule = {Direction::INPUT, Action::DENY, Protocol::UDP, "192.168.2.100", "192.168.2.200",
        "80", "90", "", Family::IPV4, LogType::NFLOG};
    FirewallRuleParcel firewall(firewallRule);
    ErrCode ret = ipv4tablesManager->AddFirewallRule(firewall);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestRemoveFilewall
 * @tc.desc: Test RemoveFilewall func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv4tablesManagerTest, TestRemoveFilewall, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    FirewallRule firewallRule = {Direction::INVALID, Action::INVALID, Protocol::INVALID, "", "", "", "", "",
        Family::IPV4, LogType::NFLOG};
    FirewallRuleParcel firewall(firewallRule);
    ErrCode ret = ipv4tablesManager->RemoveFirewallRule(firewall);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: GetFirewallRules
 * @tc.desc: Test GetFirewallRules func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv4tablesManagerTest, GetFirewallRules, TestSize.Level1)
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
    ErrCode ret = ipv4tablesManager->GetFirewallRules(list);
    EXPECT_TRUE(ret == ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}

/**
 * @tc.name: TestAddDomainFilter
 * @tc.desc: Test AddDomainFilter func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv4tablesManagerTest, TestAddDomainFilter, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    DomainFilterRule domainFilterRule = {Action::ALLOW, "1000", "www.example.com", Direction::INVALID, Family::IPV4,
        LogType::NFLOG};
    DomainFilterRuleParcel domainFilter(domainFilterRule);
    ErrCode ret = ipv4tablesManager->AddDomainFilterRule(domainFilter);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestRemoveDomainFilter
 * @tc.desc: Test RemoveDomainFilter func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv4tablesManagerTest, TestRemoveDomainFilter, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    DomainFilterRule domainFilterRule = {Action::INVALID, "", "", Direction::INVALID, Family::IPV4, LogType::NFLOG};
    DomainFilterRuleParcel doaminFilter(domainFilterRule);
    ErrCode ret = ipv4tablesManager->RemoveDomainFilterRules(doaminFilter);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestGetDomainFilterRules
 * @tc.desc: Test GetDomainFilterRules func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv4tablesManagerTest, TestGetDomainFilterRules, TestSize.Level1)
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
    ErrCode ret = ipv4tablesManager->GetDomainFilterRules(list);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS