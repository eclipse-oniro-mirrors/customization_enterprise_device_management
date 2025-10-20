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
#include "ipv6tables_manager_test.h"

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

void Ipv6tablesManagerTest::SetUp()
{
    executerUtilsMock = std::make_shared<ExecuterUtilsMock>();
    ExecuterUtils::instance_ = executerUtilsMock;

    ipv6tablesManager = std::make_shared<Ipv6tablesManager>();
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    ipv6tablesManager->Init();
}

void Ipv6tablesManagerTest::TearDown()
{
    ExecuterUtils::instance_ = nullptr;
    ExecuterFactory::instance_ = nullptr;
}

/**
 * @tc.name: TestHasInit
 * @tc.desc: Test HasInit func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv6tablesManagerTest, TestHasInit, TestSize.Level1)
{
    EXPECT_EQ(ipv6tablesManager->HasInit(), true);
}

/**
 * @tc.name: TestInit
 * @tc.desc: Test Init func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv6tablesManagerTest, TestInit, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));
    ipv6tablesManager->Init();
    EXPECT_EQ(ipv6tablesManager->HasInit(), true);
}

/**
 * @tc.name: TestAddFilewallRule
 * @tc.desc: Test AddFilewallRule func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv6tablesManagerTest, TestAddFilewallRule, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    FirewallRule firewallRule = {Direction::INPUT, Action::DENY, Protocol::UDP, "2409:8c54:871:1003::25", "",
        "80", "90", "", Family::IPV6};
    FirewallRuleParcel firewall(firewallRule);
    ErrCode ret = ipv6tablesManager->AddFirewallRule(firewall);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestRemoveFilewall
 * @tc.desc: Test RemoveFilewall func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv6tablesManagerTest, TestRemoveFilewall, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    FirewallRule firewallRule = {Direction::INVALID, Action::INVALID, Protocol::INVALID, "", "", "", "", "",
        Family::IPV6};
    FirewallRuleParcel firewall(firewallRule);
    ErrCode ret = ipv6tablesManager->RemoveFirewallRule(firewall);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: GetFirewallRules
 * @tc.desc: Test GetFirewallRules func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv6tablesManagerTest, GetFirewallRules, TestSize.Level1)
{
    std::string result =
        "Chain edm_deny_output (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source               destination\n"
        "1        0     0 DROP       udp  --  *      *       2409:8c54:871:1003::25  ::/0                 "
        "udp spt:8080";
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
    ErrCode ret = ipv6tablesManager->GetFirewallRules(list);
    EXPECT_TRUE(ret == ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}

/**
 * @tc.name: TestAddDomainFilter
 * @tc.desc: Test AddDomainFilter func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv6tablesManagerTest, TestAddDomainFilter, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    DomainFilterRule domainFilterRule = {Action::ALLOW, "1000", "www.example.com", Direction::INVALID, Family::IPV6};
    DomainFilterRuleParcel domainFilter(domainFilterRule);
    ErrCode ret = ipv6tablesManager->AddDomainFilterRule(domainFilter);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestRemoveDomainFilter
 * @tc.desc: Test RemoveDomainFilter func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv6tablesManagerTest, TestRemoveDomainFilter, TestSize.Level1)
{
    EXPECT_CALL(*executerUtilsMock, Execute).WillRepeatedly(DoAll(Invoke(PrintExecRule), Return(ERR_OK)));

    DomainFilterRule domainFilterRule = {Action::INVALID, "", "", Direction::INVALID, Family::IPV6};
    DomainFilterRuleParcel doaminFilter(domainFilterRule);
    ErrCode ret = ipv6tablesManager->RemoveDomainFilterRules(doaminFilter);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestGetDomainFilterRules
 * @tc.desc: Test GetDomainFilterRules func.
 * @tc.type: FUNC
 */
HWTEST_F(Ipv6tablesManagerTest, TestGetDomainFilterRules, TestSize.Level1)
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
    ErrCode ret = ipv6tablesManager->GetDomainFilterRules(list);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(list.size() == 1);
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS