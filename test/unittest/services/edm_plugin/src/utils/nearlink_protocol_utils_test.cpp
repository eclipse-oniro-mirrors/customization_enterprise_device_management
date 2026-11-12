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

#include "nearlink_protocol_utils.h"

#include <gtest/gtest.h>


using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class NearlinkProtocolUtilsTest : public testing::Test {};

/**
 * @tc.name: TestIntToProtocolStrKnownValues
 * @tc.desc: Test NearlinkProtocolUtils::IntToProtocolStr maps each protocol to its name.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkProtocolUtilsTest, TestIntToProtocolStrKnownValues, TestSize.Level1)
{
    std::string ssap;
    EXPECT_TRUE(NearlinkProtocolUtils::IntToProtocolStr(
        static_cast<int32_t>(NearlinkProtocol::SSAP), ssap));
    EXPECT_EQ(ssap, "SSAP");

    std::string transfer;
    EXPECT_TRUE(NearlinkProtocolUtils::IntToProtocolStr(
        static_cast<int32_t>(NearlinkProtocol::DATA_TRANSFER), transfer));
    EXPECT_EQ(transfer, "DATA_TRANSFER");
}

/**
 * @tc.name: TestIntToProtocolStrOutOfRange
 * @tc.desc: Test NearlinkProtocolUtils::IntToProtocolStr rejects values outside the enum range.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkProtocolUtilsTest, TestIntToProtocolStrOutOfRange, TestSize.Level1)
{
    std::string value = "keep";
    EXPECT_FALSE(NearlinkProtocolUtils::IntToProtocolStr(-1, value));
    EXPECT_EQ(value, "keep");
    EXPECT_FALSE(NearlinkProtocolUtils::IntToProtocolStr(99, value));
}

/**
 * @tc.name: TestStrToProtocolIntKnownValues
 * @tc.desc: Test NearlinkProtocolUtils::StrToProtocolInt maps names back to their values.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkProtocolUtilsTest, TestStrToProtocolIntKnownValues, TestSize.Level1)
{
    int32_t value = -1;
    EXPECT_TRUE(NearlinkProtocolUtils::StrToProtocolInt("SSAP", value));
    EXPECT_EQ(value, static_cast<int32_t>(NearlinkProtocol::SSAP));

    EXPECT_TRUE(NearlinkProtocolUtils::StrToProtocolInt("DATA_TRANSFER", value));
    EXPECT_EQ(value, static_cast<int32_t>(NearlinkProtocol::DATA_TRANSFER));
}

/**
 * @tc.name: TestStrToProtocolIntUnknown
 * @tc.desc: Test NearlinkProtocolUtils::StrToProtocolInt rejects unknown or empty names.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkProtocolUtilsTest, TestStrToProtocolIntUnknown, TestSize.Level1)
{
    int32_t value = 7;
    EXPECT_FALSE(NearlinkProtocolUtils::StrToProtocolInt("", value));
    EXPECT_FALSE(NearlinkProtocolUtils::StrToProtocolInt("ssap", value));
    EXPECT_FALSE(NearlinkProtocolUtils::StrToProtocolInt("NOT_A_PROTOCOL", value));
    EXPECT_EQ(value, 7);
}

/**
 * @tc.name: TestRoundTrip
 * @tc.desc: Test the two maps stay inverse to each other for every protocol.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkProtocolUtilsTest, TestRoundTrip, TestSize.Level1)
{
    for (int32_t i = static_cast<int32_t>(NearlinkProtocol::SSAP);
         i <= static_cast<int32_t>(NearlinkProtocol::DATA_TRANSFER); i++) {
        std::string name;
        ASSERT_TRUE(NearlinkProtocolUtils::IntToProtocolStr(i, name));
        int32_t back = -1;
        ASSERT_TRUE(NearlinkProtocolUtils::StrToProtocolInt(name, back));
        EXPECT_EQ(back, i);
    }
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
