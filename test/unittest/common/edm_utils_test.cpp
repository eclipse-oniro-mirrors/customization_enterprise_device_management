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

#include "securec.h"

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

/**
 * @tc.name: Test_Utf16ToUtf8_SUC
 * @tc.desc: Test Test Utf16ToUtf8 function when input data is available.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_Utf16ToUtf8_SUC, TestSize.Level1)
{
    std::string ret = EdmUtils::Utf16ToUtf8(u"test");
    ASSERT_EQ(ret, "test");
}

/**
 * @tc.name: Test_Utf16ToUtf8_FAIL
 * @tc.desc: Test Test Utf16ToUtf8 function when input data is unavailable.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_Utf16ToUtf8_FAIL, TestSize.Level1)
{
    std::string ret = EdmUtils::Utf16ToUtf8(u"error");
    ASSERT_EQ(ret, "error");
}

/**
 * @tc.name: Test_ClearString
 * @tc.desc: Test ClearString function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_ClearString, TestSize.Level1)
{
    std::string testStr = "test_string";
    EdmUtils::ClearString(testStr);
    ASSERT_TRUE(testStr.empty());
}

/**
 * @tc.name: Test_ClearString_Empty
 * @tc.desc: Test ClearString function with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_ClearString_Empty, TestSize.Level1)
{
    std::string testStr;
    EdmUtils::ClearString(testStr);
    ASSERT_TRUE(testStr.empty());
}

/**
 * @tc.name: Test_ClearCharArray
 * @tc.desc: Test ClearCharArray function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_ClearCharArray, TestSize.Level1)
{
    size_t len = 10;
    std::string testStr = "test";
    char* testArray = static_cast<char*>(malloc(len));
    strncpy_s(testArray, len, testStr.c_str(), testStr.size());
    EdmUtils::ClearCharArray(testArray, len);
    ASSERT_EQ(testArray, nullptr);
}

/**
 * @tc.name: Test_ClearCharArray_Nullptr
 * @tc.desc: Test ClearCharArray function with nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_ClearCharArray_Nullptr, TestSize.Level1)
{
    char* testArray = nullptr;
    size_t len = 10;
    EdmUtils::ClearCharArray(testArray, len);
    ASSERT_EQ(testArray, nullptr);
}

/**
 * @tc.name: Test_CheckRealPath
 * @tc.desc: Test CheckRealPath function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_CheckRealPath, TestSize.Level1)
{
    std::string path = "/data/test";
    std::string expectPath = "/data";
    bool result = EdmUtils::CheckRealPath(path, expectPath);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: Test_CheckRealPath_Empty
 * @tc.desc: Test CheckRealPath function with empty path.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_CheckRealPath_Empty, TestSize.Level1)
{
    std::string path = "";
    std::string expectPath = "/data";
    bool result = EdmUtils::CheckRealPath(path, expectPath);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: Test_CheckRealPath_TooLong
 * @tc.desc: Test CheckRealPath function with path too long.
 * @tc.type: FUNC
 */
HWTEST_F(EdmUtilsTest, Test_CheckRealPath_TooLong, TestSize.Level1)
{
    std::string path(PATH_MAX + 10, 'a');
    std::string expectPath = "/data";
    bool result = EdmUtils::CheckRealPath(path, expectPath);
    ASSERT_FALSE(result);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
