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
#define protected public
#include "firewall_chain_rule.h"
#undef protected
#undef private

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace testing;
using namespace OHOS::EDM::IPTABLES;

namespace OHOS {
namespace EDM {
namespace IPTABLES {
namespace TEST {

class FirewallChainRuleTest : public testing::Test {};

/**
 * @tc.name: TestToFilterRule
 * @tc.desc: Test ToFilterRule func.
 * @tc.type: FUNC
 */
HWTEST_F(FirewallChainRuleTest, TestToFilterRule, TestSize.Level1)
{
    FirewallRule firewallRule{Direction::INPUT, Action::DENY, Protocol::UDP, "192.168.2.100", "192.168.2.200", "80",
        "90", ""};

    FirewallChainRule firewallChainRule{firewallRule};
    EXPECT_EQ(firewallChainRule.ToFilterRule(Direction::INPUT), firewallRule);

    firewallRule = {Direction::INPUT, Action::ALLOW, Protocol::UDP, "192.168.1.1", "192.168.2.2", "9090", "9091",
        "1234567"};
    std::string rule =
        "1        0     0 ACCEPT     udp  --  *      *       192.168.1.1          192.168.2.2          "
        "udp spt:9090 dpt:9091 owner UID match 1234567";
    FirewallChainRule firewallChainRule1{rule};
    EXPECT_EQ(firewallChainRule1.ToFilterRule(Direction::INPUT), firewallRule);

    firewallRule = {Direction::INPUT, Action::ALLOW, Protocol::UDP, "192.168.4.1", "192.168.5.1-192.168.5.254",
        "55", "55", "6667"};
    rule =
        "2        0     0 ACCEPT     udp  --  *      *       192.168.4.1          0.0.0.0/0            "
        "destination IP range 192.168.5.1-192.168.5.254 udp spt:55 dpt:55 owner UID match 6667";

    FirewallChainRule firewallChainRule2{rule};
    EXPECT_EQ(firewallChainRule2.ToFilterRule(Direction::INPUT), firewallRule);

    firewallRule = {Direction::INPUT, Action::ALLOW, Protocol::UDP, "192.168.6.1-192.168.6.254",
        "192.168.5.1-192.168.5.254", "55:66", "55:77", ""};
    rule =
        "3        0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "source IP range 192.168.6.1-192.168.6.254 destination IP range 192.168.5.1-192.168.5.254 "
        "udp spts:55:66 dpts:55:77 ";

    FirewallChainRule firewallChainRule3{rule};
    EXPECT_EQ(firewallChainRule3.ToFilterRule(Direction::INPUT), firewallRule);

    FirewallChainRule firewallChainRuleEmpty{};
    firewallRule = {Direction::INPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "", ""};
    EXPECT_EQ(firewallChainRuleEmpty.ToFilterRule(Direction::INPUT), firewallRule);

    firewallRule = {Direction::OUTPUT, Action::ALLOW, Protocol::INVALID, "", "", "", "", ""};
    EXPECT_EQ(firewallChainRuleEmpty.ToFilterRule(Direction::OUTPUT), firewallRule);
}

/**
 * @tc.name: TestParameter
 * @tc.desc: Test Parameter func.
 * @tc.type: FUNC
 */
HWTEST_F(FirewallChainRuleTest, TestParameter, TestSize.Level1)
{
    FirewallRule firewallRule{Direction::INPUT, Action::DENY, Protocol::UDP, "192.168.2.100", "192.168.2.200", "80",
        "90", ""};
    std::string parameter = " -p udp -s 192.168.2.100 -d 192.168.2.200 --sport 80 --dport 90";

    FirewallChainRule firewallChainRule{firewallRule};
    EXPECT_EQ(firewallChainRule.Parameter(), parameter);

    firewallRule = {Direction::INPUT, Action::ALLOW, Protocol::ALL, "192.168.2.100", "192.168.2.200", "", "", "9999"};
    parameter = " -p all -s 192.168.2.100 -d 192.168.2.200 -m owner --uid-owner 9999";

    FirewallChainRule firewallChainRule1{firewallRule};
    EXPECT_EQ(firewallChainRule1.Parameter(), parameter);

    firewallRule = {Direction::INPUT, Action::ALLOW, Protocol::TCP, "192.168.2.1/22", "192.168.2.200", "99,100",
        "800-900", "9999"};
    parameter =
        " -p tcp -s 192.168.2.1/22 -d 192.168.2.200 -m multiport --sport 99,100 -m multiport --dport 800-900 "
        "-m owner --uid-owner 9999";

    FirewallChainRule firewallChainRule2{firewallRule};
    EXPECT_EQ(firewallChainRule2.Parameter(), parameter);
}

/**
 * @tc.name: TestIpToParameter
 * @tc.desc: Test IpToParameter func.
 * @tc.type: FUNC
 */
HWTEST_F(FirewallChainRuleTest, TestIpToParameter, TestSize.Level1)
{
    std::string parameter = " -s 192.168.1.1";
    std::string ip = "192.168.1.1";
    std::string ipType = "-s";
    EXPECT_EQ(FirewallChainRule::IpToParameter(ip, ipType), parameter);

    parameter = " -s 192.168.1.1/20";
    ip = "192.168.1.1/20";
    ipType = "-s";
    EXPECT_EQ(FirewallChainRule::IpToParameter(ip, ipType), parameter);

    parameter = " -m iprange --src-range 192.168.1.1-192.168.1.200";
    ip = "192.168.1.1-192.168.1.200";
    ipType = "-s";
    EXPECT_EQ(FirewallChainRule::IpToParameter(ip, ipType), parameter);

    parameter = " -m iprange --dst-range 192.168.1.1-192.168.1.200";
    ip = "192.168.1.1-192.168.1.200";
    ipType = "-d";
    EXPECT_EQ(FirewallChainRule::IpToParameter(ip, ipType), parameter);
}

/**
 * @tc.name: TestPortToParameter
 * @tc.desc: Test PortToParameter func.
 * @tc.type: FUNC
 */
HWTEST_F(FirewallChainRuleTest, TestPortToParameter, TestSize.Level1)
{
    std::string parameter;
    std::string port;
    std::string portType;
    std::string option;
    EXPECT_EQ(FirewallChainRule::PortToParameter(port, portType, option), parameter);

    parameter =" --sport 80";
    port = "80";
    portType = "--sport";
    option = " ";
    EXPECT_EQ(FirewallChainRule::PortToParameter(port, portType, option), parameter);

    parameter =" --dport 90";
    port = "90";
    portType = "--dport";
    option = " ";
    EXPECT_EQ(FirewallChainRule::PortToParameter(port, portType, option), parameter);

    parameter =" -m multiport --dport 90,100";
    port = "90,100";
    portType = "--dport";
    option = " -m multiport ";
    EXPECT_EQ(FirewallChainRule::PortToParameter(port, portType, option), parameter);
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS