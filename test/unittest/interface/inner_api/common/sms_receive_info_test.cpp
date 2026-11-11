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

#include "message_parcel.h"
#include "sms_receive_info.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t SLOT_ID = 2;
const std::string TELEPHONE_NUMBER = "13900000000";
const int32_t SMS_COUNT = 3;
const std::string CONTENT = "sms content";

class SmsReceiveInfoTest : public testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<SmsReceiveInfo> smsReceiveInfoTest;
};

void SmsReceiveInfoTest::SetUp()
{
    smsReceiveInfoTest = std::make_shared<SmsReceiveInfo>();
    smsReceiveInfoTest->slotId = SLOT_ID;
    smsReceiveInfoTest->telephoneNumber = TELEPHONE_NUMBER;
    smsReceiveInfoTest->count = SMS_COUNT;
    smsReceiveInfoTest->content = CONTENT;
}

void SmsReceiveInfoTest::TearDown()
{
    if (smsReceiveInfoTest) {
        smsReceiveInfoTest.reset();
    }
}

/**
 * @tc.name: TestMarshalling
 * @tc.desc: Test Marshalling and Unmarshalling func.
 * @tc.type: FUNC
 */
HWTEST_F(SmsReceiveInfoTest, TestMarshalling, TestSize.Level1)
{
    MessageParcel parcel;
    bool ret = smsReceiveInfoTest->Marshalling(parcel);
    EXPECT_TRUE(ret);

    SmsReceiveInfo *info = SmsReceiveInfo::Unmarshalling(parcel);
    EXPECT_TRUE(info != nullptr);
    EXPECT_TRUE(info->slotId == SLOT_ID);
    EXPECT_STREQ(info->telephoneNumber.c_str(), TELEPHONE_NUMBER.c_str());
    EXPECT_TRUE(info->count == SMS_COUNT);
    EXPECT_STREQ(info->content.c_str(), CONTENT.c_str());

    EXPECT_TRUE(info->slotId == smsReceiveInfoTest->slotId);
    EXPECT_STREQ(info->telephoneNumber.c_str(), smsReceiveInfoTest->telephoneNumber.c_str());
    EXPECT_TRUE(info->count == smsReceiveInfoTest->count);
    EXPECT_STREQ(info->content.c_str(), smsReceiveInfoTest->content.c_str());

    delete info;
}

/**
 * @tc.name: TestMarshallingEmptyString
 * @tc.desc: Test Marshalling with empty strings.
 * @tc.type: FUNC
 */
HWTEST_F(SmsReceiveInfoTest, TestMarshallingEmptyString, TestSize.Level1)
{
    SmsReceiveInfo info;
    info.slotId = 0;
    info.telephoneNumber = "";
    info.count = 0;
    info.content = "";

    MessageParcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);

    SmsReceiveInfo *out = SmsReceiveInfo::Unmarshalling(parcel);
    EXPECT_TRUE(out != nullptr);
    EXPECT_TRUE(out->slotId == 0);
    EXPECT_TRUE(out->telephoneNumber.empty());
    EXPECT_TRUE(out->count == 0);
    EXPECT_TRUE(out->content.empty());
    delete out;
}

/**
 * @tc.name: TestDefaultConstructor
 * @tc.desc: Test default constructor default values.
 * @tc.type: FUNC
 */
HWTEST_F(SmsReceiveInfoTest, TestDefaultConstructor, TestSize.Level1)
{
    SmsReceiveInfo info;
    EXPECT_TRUE(info.slotId == 0);
    EXPECT_TRUE(info.telephoneNumber.empty());
    EXPECT_TRUE(info.count == 0);
    EXPECT_TRUE(info.content.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
