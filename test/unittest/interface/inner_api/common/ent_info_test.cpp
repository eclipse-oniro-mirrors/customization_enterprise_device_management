/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "ent_info.h"
#include "message_parcel.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string NAME{"test"};
const std::string DESCRIPTION{"this is test"};
class EntInfoTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<EntInfo> entInfoTest;
};

void EntInfoTest::SetUp()
{
    entInfoTest = std::make_shared<EntInfo>(NAME, DESCRIPTION);
}

void EntInfoTest::TearDown()
{
    if (entInfoTest) {
        entInfoTest.reset();
    }
}

/**
 * @tc.name: TestMarshalling
 * @tc.desc: Test Marshalling func.
 * @tc.type: FUNC
 */
HWTEST_F(EntInfoTest, TestMarshalling, TestSize.Level1)
{
    MessageParcel parcel;
    bool ret = entInfoTest->Marshalling(parcel);
    EXPECT_TRUE(ret);

    EntInfo entinfo;
    EXPECT_TRUE(EntInfo::Unmarshalling(parcel, entinfo));

    EXPECT_STREQ(entinfo.enterpriseName.c_str(), NAME.c_str());
    EXPECT_STREQ(entinfo.description.c_str(), DESCRIPTION.c_str());
    EXPECT_STREQ((entInfoTest->enterpriseName).c_str(), entinfo.enterpriseName.c_str());
    EXPECT_STREQ((entInfoTest->description).c_str(), entinfo.description.c_str());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
