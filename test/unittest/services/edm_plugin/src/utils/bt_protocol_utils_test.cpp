/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "bt_protocol_utils_test.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

void BtProtocolUtilsTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void BtProtocolUtilsTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
* @tc.name: TestIntToProtocolStr
* @tc.desc: Test BtProtocolUtils::IntToProtocolStr
* @tc.type: FUNC
*/
HWTEST_F(BtProtocolUtilsTest, TestIntToProtocolStr, TestSize.Level1)
{
    int32_t gatt = 0;
    std::string str0;
    bool ret = BtProtocolUtils::IntToProtocolStr(gatt, str0);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(str0 == "GATT");

    int32_t spp = 1;
    std::string str1;
    ret = BtProtocolUtils::IntToProtocolStr(spp, str1);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(str1 == "SPP");

    int32_t opp = 2;
    std::string str2;
    ret = BtProtocolUtils::IntToProtocolStr(opp, str2);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(str2 == "OPP");
}

/**
* @tc.name: TestIntToProtocolStrFail
* @tc.desc: Test BtProtocolUtils::IntToProtocolStr
* @tc.type: FUNC
*/
HWTEST_F(BtProtocolUtilsTest, TestIntToProtocolStrFail, TestSize.Level1)
{
    int32_t num = 99;
    std::string str;
    bool ret = BtProtocolUtils::IntToProtocolStr(num, str);
    ASSERT_FALSE(ret);
}

/**
* @tc.name: TestStrToProtocolInt
* @tc.desc: Test BtProtocolUtils::StrToProtocolInt
* @tc.type: FUNC
*/
HWTEST_F(BtProtocolUtilsTest, TestStrToProtocolInt, TestSize.Level1)
{
    int32_t gatt;
    std::string str0 = "GATT";
    bool ret = BtProtocolUtils::StrToProtocolInt(str0, gatt);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(gatt == 0);

    int32_t spp;
    std::string str1 = "SPP";
    ret = BtProtocolUtils::StrToProtocolInt(str1, spp);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(spp == 1);

    int32_t opp;
    std::string str2 = "OPP";
    ret = BtProtocolUtils::StrToProtocolInt(str2, opp);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(opp == 2);
}

/**
* @tc.name: TestStrToProtocolIntFail
* @tc.desc: Test BtProtocolUtils::StrToProtocolInt
* @tc.type: FUNC
*/
HWTEST_F(BtProtocolUtilsTest, TestStrToProtocolIntFail, TestSize.Level1)
{
    int32_t num;
    std::string str = "error";
    bool ret = BtProtocolUtils::StrToProtocolInt(str, num);
    ASSERT_FALSE(ret);
}
}
}
}