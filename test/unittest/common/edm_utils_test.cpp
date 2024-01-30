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

#include "edm_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class EdmUtilsTest : public testing::Test {};
/**
 * @tc.name: Test_ParseStringToInt_SUC
 * @tc.desc: Test ParseStringToInt function when input data is available.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_ParseStringToInt_SUC, TestSize.Level1)
{
    int32_t retNum = 0;
    ErrCode ret = EdmUtils::ParseStringToInt("1", retNum);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(retNum, 1);
}

/**
 * @tc.name: Test_ParseStringToInt_FAIL
 * @tc.desc: Test ParseStringToInt function when input data is unavailable.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_ParseStringToInt_FAIL, TestSize.Level1)
{
    int32_t retNum = 0;
    ErrCode ret = EdmUtils::ParseStringToInt("", retNum);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    ASSERT_EQ(retNum, 0);
}

/**
 * @tc.name: Test_ParseStringToLong_SUC
 * @tc.desc: Test ParseStringToLong function when input data is available.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_ParseStringToLong_SUC, TestSize.Level1)
{
    int64_t retNum = 0;
    ErrCode ret = EdmUtils::ParseStringToLong("2147483647", retNum);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(retNum, 2147483647);
}


/**
 * @tc.name: Test_ParseStringToLong_FAIL
 * @tc.desc: Test Test ParseStringToLong function when input data is unavailable.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_ParseStringToLong_FAIL, TestSize.Level1)
{
    int64_t retNum = 0;
    ErrCode ret = EdmUtils::ParseStringToLong("abc", retNum);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    ASSERT_EQ(retNum, 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
