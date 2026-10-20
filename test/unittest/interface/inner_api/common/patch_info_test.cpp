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

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "edm_constants.h"
#include "message_parcel.h"
#include "patch_info.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int64_t TEST_INSTALL_TIME = 1710000000000;
const std::string TEST_NAME = "patch_20260401";
const std::string TEST_ACCOUNT = "system";
const std::string TEST_HEADER = "Security";
const std::string TEST_TITLE = "Critical Fix";
const std::string TEST_CONTENT = "Fix CVE-2026-0001";
}

class PatchInfoTest : public testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;

    PatchInfo BuildValidPatchInfo() const;
};

void PatchInfoTest::SetUp() {}

void PatchInfoTest::TearDown() {}

PatchInfo PatchInfoTest::BuildValidPatchInfo() const
{
    PatchInfo info;
    info.name = TEST_NAME;
    info.accountName = TEST_ACCOUNT;
    info.installTime = TEST_INSTALL_TIME;
    info.description.headers = {TEST_HEADER};
    PatchDescriptionBody body;
    body.title = TEST_TITLE;
    body.contents = {TEST_CONTENT};
    info.description.bodies = {body};
    return info;
}

/**
 * @tc.name: Marshalling_ValidPatchInfo_Success
 * @tc.desc: Test PatchInfo marshalling and unmarshalling with valid fields.
 * @tc.type: FUNC
 */
HWTEST_F(PatchInfoTest, Marshalling_ValidPatchInfo_Success, TestSize.Level1)
{
    PatchInfo src = BuildValidPatchInfo();
    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));

    PatchInfo dst;
    ASSERT_TRUE(PatchInfo::Unmarshalling(parcel, dst));
    EXPECT_EQ(dst.name, TEST_NAME);
    EXPECT_EQ(dst.accountName, TEST_ACCOUNT);
    EXPECT_EQ(dst.installTime, TEST_INSTALL_TIME);
    ASSERT_EQ(dst.description.headers.size(), 1u);
    EXPECT_EQ(dst.description.headers[0], TEST_HEADER);
    ASSERT_EQ(dst.description.bodies.size(), 1u);
    EXPECT_EQ(dst.description.bodies[0].title, TEST_TITLE);
    ASSERT_EQ(dst.description.bodies[0].contents.size(), 1u);
    EXPECT_EQ(dst.description.bodies[0].contents[0], TEST_CONTENT);
}

/**
 * @tc.name: Marshalling_EmptyFields_Success
 * @tc.desc: Test PatchInfo marshalling with empty strings and empty description vectors.
 * @tc.type: FUNC
 */
HWTEST_F(PatchInfoTest, Marshalling_EmptyFields_Success, TestSize.Level1)
{
    PatchInfo src;
    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));

    PatchInfo dst;
    ASSERT_TRUE(PatchInfo::Unmarshalling(parcel, dst));
    EXPECT_TRUE(dst.name.empty());
    EXPECT_TRUE(dst.accountName.empty());
    EXPECT_EQ(dst.installTime, 0);
    EXPECT_TRUE(dst.description.headers.empty());
    EXPECT_TRUE(dst.description.bodies.empty());
}

/**
 * @tc.name: Unmarshalling_IncompleteParcel_Fail
 * @tc.desc: Test Unmarshalling fails when parcel data is incomplete.
 * @tc.type: FUNC
 */
HWTEST_F(PatchInfoTest, Unmarshalling_IncompleteParcel_Fail, TestSize.Level1)
{
    MessageParcel parcel;
    ASSERT_TRUE(parcel.WriteString(TEST_NAME));

    PatchInfo dst;
    EXPECT_FALSE(PatchInfo::Unmarshalling(parcel, dst));
}

/**
 * @tc.name: Unmarshalling_IncompleteHeaders_Fail
 * @tc.desc: Test Unmarshalling fails when headers size is written without payload.
 * @tc.type: FUNC
 */
HWTEST_F(PatchInfoTest, Unmarshalling_IncompleteHeaders_Fail, TestSize.Level1)
{
    MessageParcel parcel;
    ASSERT_TRUE(parcel.WriteString(TEST_NAME));
    ASSERT_TRUE(parcel.WriteString(TEST_ACCOUNT));
    ASSERT_TRUE(parcel.WriteInt64(TEST_INSTALL_TIME));
    ASSERT_TRUE(parcel.WriteUint32(1));

    PatchInfo dst;
    EXPECT_FALSE(PatchInfo::Unmarshalling(parcel, dst));
}

/**
 * @tc.name: Marshalling_BodiesOverLimit_Fail
 * @tc.desc: Test PatchDescription marshalling fails when bodies exceed DEFAULT_LOOP_MAX_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(PatchInfoTest, Marshalling_BodiesOverLimit_Fail, TestSize.Level1)
{
    PatchInfo info;
    info.description.bodies.assign(EdmConstants::DEFAULT_LOOP_MAX_SIZE + 1, PatchDescriptionBody{});
    MessageParcel parcel;
    EXPECT_FALSE(info.Marshalling(parcel));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
