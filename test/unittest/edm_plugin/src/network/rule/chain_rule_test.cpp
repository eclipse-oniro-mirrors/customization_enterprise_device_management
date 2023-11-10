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
#include "chain_rule.h"
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

class ChainRuleMock final : public ChainRule {
public:
    explicit ChainRuleMock(const std::string& rule) : ChainRule(rule) {}

    [[nodiscard]] std::string Parameter() const override
    {
        return "";
    }
};

class ChainRuleTest : public testing::Test { };

/**
 * @tc.name: TestChainRule
 * @tc.desc: Test ChainRule func.
 * @tc.type: FUNC
 */
HWTEST_F(ChainRuleTest, TestChainRule, TestSize.Level1)
{
    std::string rule =
        "3        0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            "
        "0.0.0.0/0            source IP range 192.168.6.1-192.168.6.254 destination IP range "
        "192.168.5.1-192.168.5.254 udp spts:55:66 dpts:55:77 ";
    std::shared_ptr<ChainRule> chainRule = std::make_shared<ChainRuleMock>(rule);
    EXPECT_EQ(chainRule->RuleNum(), 3);
    EXPECT_EQ(chainRule->Target(), "ACCEPT");

    rule =
        "1        0     0 ACCEPT     udp  --  *      *       192.168.1.1          192.168.2.2          "
        "udp spt:9090 dpt:9091 owner UID match 1234567";
    chainRule = std::make_shared<ChainRuleMock>(rule);
    EXPECT_EQ(chainRule->srcAddr_, "192.168.1.1");
    EXPECT_EQ(chainRule->destAddr_, "192.168.2.2");
    EXPECT_EQ(chainRule->prot_, "udp");
}

/**
 * @tc.name: TestGetOption
 * @tc.desc: Test GetOption func.
 * @tc.type: FUNC
 */
HWTEST_F(ChainRuleTest, TestGetOption, TestSize.Level1)
{
    std::string rule;
    std::shared_ptr<ChainRule> chainRule = std::make_shared<ChainRuleMock>(rule);
    std::string options = "source IP range 192.168.6.1-192.168.6.254";
    std::string key = "source IP range";
    std::string expectValue = "192.168.6.1-192.168.6.254";
    std::string value;
    chainRule->GetOption(options, key, value);
    EXPECT_EQ(expectValue, value);

    options = "destination IP range 192.168.5.1-192.168.5.254 udp spts:55:66 dpts:55:77";
    key = "owner UID match";
    expectValue = "";
    value = {};
    chainRule->GetOption(options, key, value);
    EXPECT_EQ(expectValue, value);

    options = "spt:55 dpt:55 owner UID match 6667";
    key = "owner UID match";
    uint32_t expectIntValue = 6667;
    uint32_t intValue = 0;
    chainRule->GetOption(options, key, intValue);
    EXPECT_EQ(expectIntValue, intValue);
}

/**
 * @tc.name: TestTruncateOption
 * @tc.desc: Test TruncateOption func.
 * @tc.type: FUNC
 */
HWTEST_F(ChainRuleTest, TestTruncateOption, TestSize.Level1)
{
    std::string rule;
    std::shared_ptr<ChainRule> chainRule = std::make_shared<ChainRuleMock>(rule);
    std::string options = "source IP range 192.168.6.1-192.168.6.254";
    std::string key = "source IP range";
    std::string expectValue = " 192.168.6.1-192.168.6.254";
    std::string value;
    chainRule->TruncateOption(options, key, value);
    EXPECT_EQ(expectValue, value);

    options = "destination IP range 192.168.5.1-192.168.5.254 udp spts:55:66 dpts:55:77";
    key = "owner UID match";
    expectValue = "";
    value = {};
    chainRule->TruncateOption(options, key, value);
    EXPECT_EQ(expectValue, value);
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS