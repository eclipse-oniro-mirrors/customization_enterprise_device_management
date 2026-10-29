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
#include "sms_message_info.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t SLOT_ID = 1;
const std::string TELEPHONE_NUMBER = "13800000000";
const std::string CONTENT = "hello world";
const int64_t TIMER = 1722470400;

class SmsMessageInfoTest : public testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<SmsMessageInfo> smsMessageInfoTest;
};

void SmsMessageInfoTest::SetUp()
{
    smsMessageInfoTest = std::make_shared<SmsMessageInfo>();
    smsMessageInfoTest->slotId = SLOT_ID;
    smsMessageInfoTest->telephoneNumber = TELEPHONE_NUMBER;
    smsMessageInfoTest->content = CONTENT;
    smsMessageInfoTest->timer = TIMER;
    smsMessageInfoTest->isSender = true;
}

void SmsMessageInfoTest::TearDown()
{
    if (smsMessageInfoTest) {
        smsMessageInfoTest.reset();
    }
}

/**
 * @tc.name: TestMarshalling
 * @tc.desc: Test Marshalling and Unmarshalling func.
 * @tc.type: FUNC
 */
HWTEST_F(SmsMessageInfoTest, TestMarshalling, TestSize.Level1)
{
    MessageParcel parcel;
    bool ret = smsMessageInfoTest->Marshalling(parcel);
    EXPECT_TRUE(ret);

    SmsMessageInfo *info = SmsMessageInfo::Unmarshalling(parcel);
    EXPECT_TRUE(info != nullptr);
    EXPECT_TRUE(info->slotId == SLOT_ID);
    EXPECT_STREQ(info->telephoneNumber.c_str(), TELEPHONE_NUMBER.c_str());
    EXPECT_STREQ(info->content.c_str(), CONTENT.c_str());
    EXPECT_TRUE(info->timer == TIMER);
    EXPECT_TRUE(info->isSender);

    EXPECT_TRUE(info->slotId == smsMessageInfoTest->slotId);
    EXPECT_STREQ(info->telephoneNumber.c_str(), smsMessageInfoTest->telephoneNumber.c_str());
    EXPECT_STREQ(info->content.c_str(), smsMessageInfoTest->content.c_str());
    EXPECT_TRUE(info->timer == smsMessageInfoTest->timer);
    EXPECT_TRUE(info->isSender == smsMessageInfoTest->isSender);

    delete info;
}

/**
 * @tc.name: TestMarshallingEmptyString
 * @tc.desc: Test Marshalling with empty strings.
 * @tc.type: FUNC
 */
HWTEST_F(SmsMessageInfoTest, TestMarshallingEmptyString, TestSize.Level1)
{
    SmsMessageInfo info;
    info.slotId = 0;
    info.telephoneNumber = "";
    info.content = "";
    info.timer = 0;
    info.isSender = false;

    MessageParcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);

    SmsMessageInfo *out = SmsMessageInfo::Unmarshalling(parcel);
    EXPECT_TRUE(out != nullptr);
    EXPECT_TRUE(out->slotId == 0);
    EXPECT_TRUE(out->telephoneNumber.empty());
    EXPECT_TRUE(out->content.empty());
    EXPECT_TRUE(out->timer == 0);
    EXPECT_FALSE(out->isSender);
    delete out;
}

/**
 * @tc.name: TestDefaultConstructor
 * @tc.desc: Test default constructor default values.
 * @tc.type: FUNC
 */
HWTEST_F(SmsMessageInfoTest, TestDefaultConstructor, TestSize.Level1)
{
    SmsMessageInfo info;
    EXPECT_TRUE(info.slotId == 0);
    EXPECT_TRUE(info.telephoneNumber.empty());
    EXPECT_TRUE(info.content.empty());
    EXPECT_TRUE(info.timer == 0);
    EXPECT_FALSE(info.isSender);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
