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
#include <memory>
#include <string>

#include "message_parcel.h"
#include "notification_received_info.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
const std::string TEST_HASH_CODE = "100_0_com.example.app_1_testLabel_1700000000000";
const std::string TEST_BUNDLE_NAME = "com.example.app";
const std::string TEST_APP_NAME = "testAppName";
const int32_t TEST_APP_INDEX = 2;
const std::string TEST_LONG_STRING(1024, 'a');
}

class NotificationReceivedInfoTest : public testing::Test {
};

/**
 * @tc.name: NotificationReceivedInfoTest001
 * @tc.desc: Test NotificationReceivedInfo with default constructor.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationReceivedInfoTest, NotificationReceivedInfoTest001, TestSize.Level1)
{
    NotificationReceivedInfo info;
    EXPECT_EQ(info.hashCode, "");
    EXPECT_EQ(info.bundleName, "");
    EXPECT_EQ(info.appIndex, 0);
    EXPECT_EQ(info.appName, "");
}

/**
 * @tc.name: NotificationReceivedInfoTest002
 * @tc.desc: Test NotificationReceivedInfo marshalling and unmarshalling.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationReceivedInfoTest, NotificationReceivedInfoTest002, TestSize.Level1)
{
    NotificationReceivedInfo info;
    info.hashCode = TEST_HASH_CODE;
    info.bundleName = TEST_BUNDLE_NAME;
    info.appIndex = TEST_APP_INDEX;
    info.appName = TEST_APP_NAME;

    MessageParcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));
    parcel.RewindRead(0);

    std::unique_ptr<NotificationReceivedInfo> result(NotificationReceivedInfo::Unmarshalling(parcel));
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->hashCode, TEST_HASH_CODE);
    EXPECT_EQ(result->bundleName, TEST_BUNDLE_NAME);
    EXPECT_EQ(result->appIndex, TEST_APP_INDEX);
    EXPECT_EQ(result->appName, TEST_APP_NAME);
}

/**
 * @tc.name: NotificationReceivedInfoTest003
 * @tc.desc: Test NotificationReceivedInfo marshalling and unmarshalling with empty and long fields.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationReceivedInfoTest, NotificationReceivedInfoTest003, TestSize.Level1)
{
    NotificationReceivedInfo info;
    info.hashCode = "";
    info.bundleName = TEST_LONG_STRING;
    info.appIndex = -1;
    info.appName = TEST_LONG_STRING;

    MessageParcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));
    parcel.RewindRead(0);

    std::unique_ptr<NotificationReceivedInfo> result(NotificationReceivedInfo::Unmarshalling(parcel));
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->hashCode, "");
    EXPECT_EQ(result->bundleName, TEST_LONG_STRING);
    EXPECT_EQ(result->appIndex, -1);
    EXPECT_EQ(result->appName, TEST_LONG_STRING);
}

/**
 * @tc.name: NotificationReceivedInfoTest004
 * @tc.desc: Test NotificationReceivedInfo unmarshalling from empty parcel.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationReceivedInfoTest, NotificationReceivedInfoTest004, TestSize.Level1)
{
    MessageParcel parcel;
    std::unique_ptr<NotificationReceivedInfo> result(NotificationReceivedInfo::Unmarshalling(parcel));
    EXPECT_EQ(result, nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
