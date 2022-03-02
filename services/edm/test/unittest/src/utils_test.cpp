/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <ipc_skeleton.h>
#include "edm_log.h"
#include "func_code_utils.h"

using namespace testing::ext;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
class UtilsTest : public testing::Test {};

/**
 * @tc.name: Test_FuncCodeUtils_ConvertSystemFlag
 * @tc.desc: Test FuncCodeUtils::ConvertOperateType.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsTest, Test_FuncCodeUtils_ConvertSystemFlag, TestSize.Level1)
{
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(0);
    ASSERT_EQ(type, FuncOperateType::GET);
    type = FuncCodeUtils::ConvertOperateType(1);
    ASSERT_EQ(type, FuncOperateType::SET);
    type = FuncCodeUtils::ConvertOperateType(2);
    ASSERT_EQ(type, FuncOperateType::REMOVE);
}

/**
 * @tc.name: Test_ArrayPolicyUtils_RemovePolicy
 * @tc.desc: Test ArrayPolicyUtils::RemovePolicy.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsTest, Test_ArrayPolicyUtils_RemovePolicy, TestSize.Level1)
{
    std::vector<std::string> removeData;
    std::vector<std::string> currentData;

    removeData = { "19216811" };
    currentData = { "19216811", "19216812", "19216813" };
    ArrayPolicyUtils::RemovePolicy(removeData, currentData);
    ASSERT_TRUE(currentData.size() == 2);

    removeData = { "19216811" };
    currentData = {};
    ArrayPolicyUtils::RemovePolicy(removeData, currentData);
    ASSERT_TRUE(currentData.empty());

    removeData = {};
    currentData = { "19216811", "19216812", "19216813" };
    ArrayPolicyUtils::RemovePolicy(removeData, currentData);
    ASSERT_TRUE(currentData.size() == 3);

    removeData = { "19216814" };
    currentData = { "19216811", "19216812", "19216813" };
    ArrayPolicyUtils::RemovePolicy(removeData, currentData);
    ASSERT_TRUE(currentData.size() == 3);
}

/**
 * @tc.name: Test_ArrayPolicyUtils_ArrayStringContains
 * @tc.desc: Test ArrayPolicyUtils::ArrayStringContains.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsTest, Test_ArrayPolicyUtils_ArrayStringContains, TestSize.Level1)
{
    std::vector<std::string> data;
    std::string find = "19216812";
    data = { "19216811", "19216812", "19216813" };
    ASSERT_TRUE(ArrayPolicyUtils::ArrayStringContains(data, find));

    find = "19216814";
    data = { "19216811", "19216812", "19216813" };
    ASSERT_FALSE(ArrayPolicyUtils::ArrayStringContains(data, find));

    find = "19216814";
    data = {};
    ASSERT_FALSE(ArrayPolicyUtils::ArrayStringContains(data, find));
}

/**
 * @tc.name: Test_ArrayPolicyUtils_RemovePolicy_002
 * @tc.desc: Test ArrayPolicyUtils::RemovePolicy.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsTest, Test_ArrayPolicyUtils_RemovePolicy_002, TestSize.Level1)
{
    std::vector<std::map<std::string, std::string>> removeData = {
        {
            {"id", "1"},
            {"name", "leon"},
        },
        {
            {"id", "2"},
            {"name", "james"},
        }};
    std::vector<std::map<std::string, std::string>> data = {
        {
            {"id", "3"},
            {"name", "fox"},
        },
        {
            {"id", "1"},
            {"name", "leon"},
        },
    };
    // leon should be remove
    ArrayPolicyUtils::RemovePolicy(removeData, data);
    ASSERT_TRUE(data.size() == 1);

    removeData = {
        {
            {"id", "1"},
            {"name", "leon"},
        },
        {
            {"id", "2"},
            {"name", "james"},
        }
    };
    data = {
        {
            {"id", "3"},
            {"name", "fox"},
        },
        {
            {"id", "4"},
            {"name", "leon"},
        },
    };
    ArrayPolicyUtils::RemovePolicy(removeData, data);
    ASSERT_TRUE(data.size() == 2);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
