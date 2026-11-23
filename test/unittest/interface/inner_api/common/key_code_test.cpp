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
#include <vector>

#include "key_code.h"
#include "message_parcel.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class KeyCodeTest : public testing::Test {
protected:
    KeyCustomization BuildItem(KeyCode keyCode, KeyPolicy keyPolicy) const;
    std::vector<KeyCustomization> BuildExtendedKeyCustomizations() const;
};

KeyCustomization KeyCodeTest::BuildItem(KeyCode keyCode, KeyPolicy keyPolicy) const
{
    KeyCustomization item;
    item.keyCode = static_cast<int32_t>(keyCode);
    item.keyPolicy = static_cast<int32_t>(keyPolicy);
    return item;
}

std::vector<KeyCustomization> KeyCodeTest::BuildExtendedKeyCustomizations() const
{
    return {
        BuildItem(KeyCode::FN, KeyPolicy::INTERCEPTION),
        BuildItem(KeyCode::DPAD_UP, KeyPolicy::CUSTOM),
        BuildItem(KeyCode::ESCAPE, KeyPolicy::INTERCEPTION),
        BuildItem(KeyCode::F1, KeyPolicy::CUSTOM),
        BuildItem(KeyCode::F12, KeyPolicy::INTERCEPTION),
        BuildItem(KeyCode::BRIGHTNESS_UP, KeyPolicy::CUSTOM),
    };
}

/**
 * @tc.name: Marshalling_ValidExtendedKeyCode_Success
 * @tc.desc: Test marshalling and unmarshalling with extended KeyCode values.
 * @tc.type: FUNC
 */
HWTEST_F(KeyCodeTest, Marshalling_ValidExtendedKeyCode_Success, TestSize.Level1)
{
    std::vector<KeyCustomization> src = BuildExtendedKeyCustomizations();
    MessageParcel parcel;
    ASSERT_TRUE(KeyEventHandle::WriteKeyCustomizationVector(parcel, src));

    std::vector<KeyCustomization> dst;
    ASSERT_TRUE(KeyEventHandle::ReadKeyCustomizationVector(parcel, dst));
    ASSERT_EQ(dst.size(), src.size());
    for (size_t i = 0; i < src.size(); ++i) {
        EXPECT_EQ(dst[i].keyCode, src[i].keyCode);
        EXPECT_EQ(dst[i].keyPolicy, src[i].keyPolicy);
    }
}

/**
 * @tc.name: Marshalling_EmptyKeyCustomization_Success
 * @tc.desc: Test marshalling and unmarshalling with empty KeyCustomization vector.
 * @tc.type: FUNC
 */
HWTEST_F(KeyCodeTest, Marshalling_EmptyKeyCustomization_Success, TestSize.Level1)
{
    std::vector<KeyCustomization> src;
    MessageParcel parcel;
    ASSERT_TRUE(KeyEventHandle::WriteKeyCustomizationVector(parcel, src));

    std::vector<KeyCustomization> dst;
    ASSERT_TRUE(KeyEventHandle::ReadKeyCustomizationVector(parcel, dst));
    EXPECT_TRUE(dst.empty());
}

/**
 * @tc.name: Unmarshalling_SizeOverLimit_Fail
 * @tc.desc: Test unmarshalling fails when vector size exceeds MAX_KEYEVENT_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(KeyCodeTest, Unmarshalling_SizeOverLimit_Fail, TestSize.Level1)
{
    MessageParcel parcel;
    ASSERT_TRUE(parcel.WriteInt32(28));
    std::vector<KeyCustomization> dst;
    EXPECT_FALSE(KeyEventHandle::ReadKeyCustomizationVector(parcel, dst));
}

/**
 * @tc.name: Unmarshalling_NegativeSize_Fail
 * @tc.desc: Test unmarshalling fails when vector size is negative.
 * @tc.type: FUNC
 */
HWTEST_F(KeyCodeTest, Unmarshalling_NegativeSize_Fail, TestSize.Level1)
{
    MessageParcel parcel;
    ASSERT_TRUE(parcel.WriteInt32(-1));
    std::vector<KeyCustomization> dst;
    EXPECT_FALSE(KeyEventHandle::ReadKeyCustomizationVector(parcel, dst));
}

/**
 * @tc.name: Marshalling_BodiesOverLimit_Fail
 * @tc.desc: Test marshalling fails when item count exceeds MAX_KEYEVENT_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(KeyCodeTest, Marshalling_BodiesOverLimit_Fail, TestSize.Level1)
{
    std::vector<KeyCustomization> src;
    for (int32_t i = 0; i < 28; ++i) {
        src.push_back(BuildItem(KeyCode::F1, KeyPolicy::CUSTOM));
    }
    MessageParcel parcel;
    EXPECT_FALSE(KeyEventHandle::WriteKeyCustomizationVector(parcel, src));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
