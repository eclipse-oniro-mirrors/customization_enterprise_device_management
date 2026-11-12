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

#include "update_policy_serializer.h"

#include <gtest/gtest.h>

#include "int_serializer.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class UpdatePolicySerializerTest : public testing::Test {};

/**
 * @tc.name: TestDeserializeInRange
 * @tc.desc: Test UpdatePolicySerializer::Deserialize maps an in-range number to the policy type.
 * @tc.type: FUNC
 */
HWTEST_F(UpdatePolicySerializerTest, TestDeserializeInRange, TestSize.Level1)
{
    auto serializer = UpdatePolicySerializer::GetInstance();
    UpdatePolicy policy;
    EXPECT_TRUE(serializer->Deserialize("4", policy));
    EXPECT_EQ(policy.type, UpdatePolicyType::POSTPONE);

    UpdatePolicy defaultPolicy;
    defaultPolicy.type = UpdatePolicyType::PROHIBIT;
    EXPECT_TRUE(serializer->Deserialize("0", defaultPolicy));
    EXPECT_EQ(defaultPolicy.type, UpdatePolicyType::DEFAULT);
}

/**
 * @tc.name: TestDeserializeOutOfRange
 * @tc.desc: Test UpdatePolicySerializer::Deserialize keeps the type when the number is out of range.
 * @tc.type: FUNC
 */
HWTEST_F(UpdatePolicySerializerTest, TestDeserializeOutOfRange, TestSize.Level1)
{
    auto serializer = UpdatePolicySerializer::GetInstance();
    UpdatePolicy policy;
    policy.type = UpdatePolicyType::WINDOWS;
    EXPECT_TRUE(serializer->Deserialize("99", policy));
    EXPECT_EQ(policy.type, UpdatePolicyType::WINDOWS);
}

/**
 * @tc.name: TestSerialize
 * @tc.desc: Test UpdatePolicySerializer::Serialize writes the numeric policy type.
 * @tc.type: FUNC
 */
HWTEST_F(UpdatePolicySerializerTest, TestSerialize, TestSize.Level1)
{
    auto serializer = UpdatePolicySerializer::GetInstance();
    UpdatePolicy policy;
    policy.type = UpdatePolicyType::UPDATE_TO_SPECIFIC_VERSION;
    std::string jsonString;
    EXPECT_TRUE(serializer->Serialize(policy, jsonString));
    EXPECT_EQ(jsonString, "2");

    int32_t back = -1;
    EXPECT_TRUE(IntSerializer::GetInstance()->Deserialize(jsonString, back));
    EXPECT_EQ(back, 2);
}

/**
 * @tc.name: TestGetPolicyAndWritePolicy
 * @tc.desc: Test UpdatePolicySerializer round-trips a policy through the parcel.
 * @tc.type: FUNC
 */
HWTEST_F(UpdatePolicySerializerTest, TestGetPolicyAndWritePolicy, TestSize.Level1)
{
    auto serializer = UpdatePolicySerializer::GetInstance();
    UpdatePolicy input;
    input.type = UpdatePolicyType::PROHIBIT;
    input.version = "5.0.0.100";
    input.installTime.latestUpdateTime = 1000;
    input.installTime.delayUpdateTime = 2000;
    input.installTime.installWindowStart = 3000;
    input.installTime.installWindowEnd = 4000;
    input.otaPolicyType = OtaPolicyType::DEFAULT;

    MessageParcel reply;
    EXPECT_TRUE(serializer->WritePolicy(reply, input));
    reply.RewindRead(0);

    UpdatePolicy output;
    EXPECT_TRUE(serializer->GetPolicy(reply, output));
    EXPECT_EQ(output.type, UpdatePolicyType::PROHIBIT);
    EXPECT_EQ(output.version, "5.0.0.100");
    EXPECT_EQ(output.installTime.latestUpdateTime, 1000);
    EXPECT_EQ(output.installTime.delayUpdateTime, 2000);
    EXPECT_EQ(output.installTime.installWindowStart, 3000);
    EXPECT_EQ(output.installTime.installWindowEnd, 4000);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test UpdatePolicySerializer::MergePolicy applies the DEFAULT item.
 * @tc.type: FUNC
 */
HWTEST_F(UpdatePolicySerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = UpdatePolicySerializer::GetInstance();
    UpdatePolicy prohibit;
    prohibit.type = UpdatePolicyType::PROHIBIT;
    UpdatePolicy defaultPolicy;
    std::vector<UpdatePolicy> data = { prohibit, defaultPolicy };
    UpdatePolicy result = prohibit;
    EXPECT_TRUE(serializer->MergePolicy(data, result));
    EXPECT_EQ(result.type, UpdatePolicyType::DEFAULT);

    std::vector<UpdatePolicy> onlyProhibit = { prohibit };
    UpdatePolicy result2 = defaultPolicy;
    EXPECT_TRUE(serializer->MergePolicy(onlyProhibit, result2));
    EXPECT_EQ(result2.type, UpdatePolicyType::DEFAULT);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
