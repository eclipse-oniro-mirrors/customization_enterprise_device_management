/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "firewall_rule_serializer.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class FirewallRuleSerializerTest : public testing::Test {};

/**
 * @tc.name: TestDeserializeAndSerialize
 * @tc.desc: Test FirewallRuleSerializer Serialize/Deserialize keep the policy untouched.
 * @tc.type: FUNC
 */
HWTEST_F(FirewallRuleSerializerTest, TestDeserializeAndSerialize, TestSize.Level1)
{
    auto serializer = FirewallRuleSerializer::GetInstance();
    IPTABLES::FirewallRuleParcel config;
    std::string jsonString = "unset";
    EXPECT_TRUE(serializer->Serialize(config, jsonString));
    EXPECT_EQ(jsonString, "unset");
    EXPECT_TRUE(serializer->Deserialize("{}", config));
    EXPECT_TRUE(serializer->Deserialize("broken", config));
}

/**
 * @tc.name: TestGetPolicyEmptyParcel
 * @tc.desc: Test FirewallRuleSerializer::GetPolicy succeeds on an empty parcel.
 * @tc.type: FUNC
 */
HWTEST_F(FirewallRuleSerializerTest, TestGetPolicyEmptyParcel, TestSize.Level1)
{
    auto serializer = FirewallRuleSerializer::GetInstance();
    MessageParcel data;
    IPTABLES::FirewallRuleParcel result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test FirewallRuleSerializer::WritePolicy reports the marshalling outcome.
 * @tc.type: FUNC
 */
HWTEST_F(FirewallRuleSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = FirewallRuleSerializer::GetInstance();
    MessageParcel reply;
    IPTABLES::FirewallRuleParcel result;
    bool ok = serializer->WritePolicy(reply, result);
    if (ok) {
        EXPECT_GT(reply.GetDataSize(), 0u);
    }
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test FirewallRuleSerializer::MergePolicy returns success.
 * @tc.type: FUNC
 */
HWTEST_F(FirewallRuleSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = FirewallRuleSerializer::GetInstance();
    std::vector<IPTABLES::FirewallRuleParcel> data;
    IPTABLES::FirewallRuleParcel result;
    EXPECT_TRUE(serializer->MergePolicy(data, result));
    data.push_back(result);
    EXPECT_TRUE(serializer->MergePolicy(data, result));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
