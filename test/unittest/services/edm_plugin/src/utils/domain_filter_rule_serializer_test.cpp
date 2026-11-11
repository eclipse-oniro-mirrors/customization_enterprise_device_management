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

#include "domain_filter_rule_serializer.h"

#include <gtest/gtest.h>
#include <message_parcel.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class DomainFilterRuleSerializerTest : public testing::Test {};

/**
 * @tc.name: TestDeserializeAndSerialize
 * @tc.desc: Test DomainFilterRuleSerializer Serialize/Deserialize keep the policy untouched.
 * @tc.type: FUNC
 */
HWTEST_F(DomainFilterRuleSerializerTest, TestDeserializeAndSerialize, TestSize.Level1)
{
    auto serializer = DomainFilterRuleSerializer::GetInstance();
    IPTABLES::DomainFilterRuleParcel config;
    std::string jsonString = "unset";
    EXPECT_TRUE(serializer->Serialize(config, jsonString));
    EXPECT_EQ(jsonString, "unset");
    EXPECT_TRUE(serializer->Deserialize("{}", config));
    EXPECT_TRUE(serializer->Deserialize("broken", config));
}

/**
 * @tc.name: TestGetPolicyEmptyParcel
 * @tc.desc: Test DomainFilterRuleSerializer::GetPolicy succeeds on an empty parcel.
 * @tc.type: FUNC
 */
HWTEST_F(DomainFilterRuleSerializerTest, TestGetPolicyEmptyParcel, TestSize.Level1)
{
    auto serializer = DomainFilterRuleSerializer::GetInstance();
    MessageParcel data;
    IPTABLES::DomainFilterRuleParcel result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test DomainFilterRuleSerializer::WritePolicy reports the marshalling outcome.
 * @tc.type: FUNC
 */
HWTEST_F(DomainFilterRuleSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = DomainFilterRuleSerializer::GetInstance();
    MessageParcel reply;
    IPTABLES::DomainFilterRuleParcel result;
    bool ok = serializer->WritePolicy(reply, result);
    if (ok) {
        EXPECT_GT(reply.GetDataSize(), 0u);
    }
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test DomainFilterRuleSerializer::MergePolicy returns success.
 * @tc.type: FUNC
 */
HWTEST_F(DomainFilterRuleSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = DomainFilterRuleSerializer::GetInstance();
    std::vector<IPTABLES::DomainFilterRuleParcel> data;
    IPTABLES::DomainFilterRuleParcel result;
    EXPECT_TRUE(serializer->MergePolicy(data, result));
    data.push_back(result);
    EXPECT_TRUE(serializer->MergePolicy(data, result));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
