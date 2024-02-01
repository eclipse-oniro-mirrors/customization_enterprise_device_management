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
#include "domain_chain_rule.h"
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

class DomainChainRuleTest : public testing::Test {};

/**
 * @tc.name: TestToFilterRule
 * @tc.desc: Test ToFilterRule func.
 * @tc.type: FUNC
 */
HWTEST_F(DomainChainRuleTest, TestToFilterRule, TestSize.Level1)
{
    DomainFilterRule domainFilterRule{Action::DENY, "9696", "www.example.com"};
    DomainChainRule domainChainRule{domainFilterRule};

    EXPECT_EQ(domainChainRule.ToFilterRule(), domainFilterRule);

    std::string rule =
        "1        0     0 DROP       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            "
        "udp dpt:53 owner UID match 9696 STRING match  \"|03777777076578616d706c6503636f6d|\" ALGO name bm TO 65535";
    DomainChainRule domainChainRule1{rule};
    EXPECT_EQ(domainChainRule1.ToFilterRule(), domainFilterRule);
}

/**
 * @tc.name: TestParameter
 * @tc.desc: Test Parameter func.
 * @tc.type: FUNC
 */
HWTEST_F(DomainChainRuleTest, TestParameter, TestSize.Level1)
{
    DomainFilterRule domainFilterRule{Action::DENY, "9696", "www.example.com"};
    std::string parameter =
        " -p udp --dport 53 -m owner --uid-owner 9696 -m string --hex-string |03|www|07|example|03|com| --algo bm";

    DomainChainRule domainChainRule{domainFilterRule};
    EXPECT_EQ(domainChainRule.Parameter(), parameter);

    DomainFilterRule domainFilterRule1{Action::ALLOW, "", "www.example.com"};
    std::string parameter1 = " -p udp --dport 53 -m string --hex-string |03|www|07|example|03|com| --algo bm";

    DomainChainRule domainChainRule1{domainFilterRule1};
    EXPECT_EQ(domainChainRule1.Parameter(), parameter1);
}

/**
 * @tc.name: TestDomainToFormatData
 * @tc.desc: Test DomainToFormatData func.
 * @tc.type: FUNC
 */
HWTEST_F(DomainChainRuleTest, TestDomainToFormatData, TestSize.Level1)
{
    std::string domainName{"www.example1.com"};
    std::string result = DomainChainRule::DomainToFormatData(domainName);
    EXPECT_EQ(result, "|03|www|08|example1|03|com|");
}

/**
 * @tc.name: TestFormatDataToDomain
 * @tc.desc: Test FormatDataToDomain func.
 * @tc.type: FUNC
 */
HWTEST_F(DomainChainRuleTest, TestFormatDataToDomain, TestSize.Level1)
{
    std::string domainName{"\"|03777777076578616d706c6503636f6d|\""};
    std::string result = DomainChainRule::FormatDataToDomain(domainName);
    EXPECT_EQ(result, "www.example.com");
}

/**
 * @tc.name: TestCharToHex
 * @tc.desc: Test CharToHex func.
 * @tc.type: FUNC
 */
HWTEST_F(DomainChainRuleTest, TestCharToHex, TestSize.Level1)
{
    uint8_t result = DomainChainRule::CharToHex('1', '0');
    EXPECT_TRUE(result == 0x10);

    result = DomainChainRule::CharToHex('2', '2');
    EXPECT_TRUE(result == 0x22);

    result = DomainChainRule::CharToHex('3', '9');
    EXPECT_TRUE(result == 0x39);
}

/**
 * @tc.name: TestCharToHex1
 * @tc.desc: Test CharToHex func.
 * @tc.type: FUNC
 */
HWTEST_F(DomainChainRuleTest, TestCharToHex1, TestSize.Level1)
{
    uint8_t expectChar = 1;
    uint8_t result = DomainChainRule::CharToHex('1');
    EXPECT_TRUE(result == expectChar);

    expectChar = 10;
    result = DomainChainRule::CharToHex('a');
    EXPECT_TRUE(result == expectChar);

    expectChar = 15;
    result = DomainChainRule::CharToHex('F');
    EXPECT_TRUE(result == expectChar);
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS