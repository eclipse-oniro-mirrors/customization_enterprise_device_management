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

#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "array_string_serializer.h"

using namespace testing::ext;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
class UtilsTest : public testing::Test {};
const std::string TEST_STRING_INDEX_ZORE = "19216811";
const std::string TEST_STRING_INDEX_ONE = "19216812";
const std::string TEST_STRING_INDEX_TWO = "19216813";
const std::string TEST_STRING_INDEX_THREE = "19216814";

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
 * @tc.name: Test_FuncCodeUtils
 * @tc.desc: Test FuncCodeUtils functions
 * @tc.type: FUNC
 */
HWTEST_F(UtilsTest, Test_FuncCodeUtils, TestSize.Level1)
{
    uint32_t code =
        FuncCodeUtils::CreateFuncCode(1, (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_DATETIME);
    ASSERT_TRUE(FuncCodeUtils::IsPolicyFlag(code));
    ASSERT_FALSE(FuncCodeUtils::IsServiceFlag(code));
    ASSERT_TRUE(FuncCodeUtils::GetOperateType(code) == FuncOperateType::SET);
    ASSERT_TRUE(FuncCodeUtils::GetSystemFlag(code) == FuncFlag::POLICY_FLAG);
    ASSERT_TRUE(FuncCodeUtils::GetPolicyCode(code) == EdmInterfaceCode::SET_DATETIME);

    code = EdmInterfaceCode::ADD_DEVICE_ADMIN;
    ASSERT_FALSE(FuncCodeUtils::IsPolicyFlag(code));
    ASSERT_TRUE(FuncCodeUtils::IsServiceFlag(code));
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

    removeData = {TEST_STRING_INDEX_ZORE};
    currentData = {TEST_STRING_INDEX_ZORE, TEST_STRING_INDEX_ONE, TEST_STRING_INDEX_TWO};
    ArrayPolicyUtils::RemovePolicy(removeData, currentData);
    ASSERT_TRUE(currentData.size() == 2);

    removeData = {TEST_STRING_INDEX_ZORE};
    currentData = {};
    ArrayPolicyUtils::RemovePolicy(removeData, currentData);
    ASSERT_TRUE(currentData.empty());

    removeData = {};
    currentData = {TEST_STRING_INDEX_ZORE, TEST_STRING_INDEX_ONE, TEST_STRING_INDEX_TWO};
    ArrayPolicyUtils::RemovePolicy(removeData, currentData);
    ASSERT_TRUE(currentData.size() == 3);

    removeData = {TEST_STRING_INDEX_THREE};
    currentData = {TEST_STRING_INDEX_ZORE, TEST_STRING_INDEX_ONE, TEST_STRING_INDEX_TWO};
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
    std::string find = TEST_STRING_INDEX_ONE;
    data = {TEST_STRING_INDEX_ZORE, TEST_STRING_INDEX_ONE, TEST_STRING_INDEX_TWO};
    ASSERT_TRUE(ArrayPolicyUtils::ArrayStringContains(data, find));

    find = TEST_STRING_INDEX_THREE;
    data = {TEST_STRING_INDEX_ZORE, TEST_STRING_INDEX_ONE, TEST_STRING_INDEX_TWO};
    ASSERT_FALSE(ArrayPolicyUtils::ArrayStringContains(data, find));

    find = TEST_STRING_INDEX_THREE;
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

/**
 * @tc.name: Test_ArrayStringSerializer_SetUnionPolicyData
 * @tc.desc: Test ArrayStringSerializer::SetUnionPolicyData.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsTest, Test_ArrayStringSerializer_SetUnionPolicyData, TestSize.Level1)
{
    std::vector<std::string> data = {"1", "2", "3", "4", "5"};
    std::vector<std::string> currentData = {"3", "4", "5", "6", "7"};
    auto serializer = ArrayStringSerializer::GetInstance();
    std::vector<string> mergeData = serializer->SetUnionPolicyData(data, currentData);
    std::vector<string> resultData;
    size_t i = 0;
    size_t j = 0;
    while (i < data.size() && j < currentData.size()) {
        if (data[i] == currentData[j]) {
            resultData.push_back(data[i]);
            i++;
            j++;
        } else if (data[i] < currentData[j]) {
            resultData.push_back(data[i]);
            i++;
        } else {
            resultData.push_back(currentData[j]);
            j++;
        }
    }
    while (i < data.size()) {
        resultData.push_back(data[i]);
        i++;
    }
    while (j < currentData.size()) {
        resultData.push_back(currentData[j]);
        j++;
    }
    ASSERT_TRUE(resultData.size() == mergeData.size());
}

/**
 * @tc.name: Test_ArrayStringSerializer_SetDifferencePolicyData
 * @tc.desc: Test ArrayStringSerializer::SetDifferencePolicyData.
 * @tc.type: FUNC
 */
HWTEST_F(UtilsTest, Test_ArrayStringSerializer_SetDifferencePolicyData, TestSize.Level1)
{
    std::vector<std::string> data = {"1", "2", "3", "4", "5"};
    std::vector<std::string> currentData = {"3", "4", "5", "6", "7"};
    auto serializer = ArrayStringSerializer::GetInstance();
    std::vector<string> mergeData = serializer->SetDifferencePolicyData(currentData, data);
    size_t len = 0;
    for (size_t i = 0; i < data.size(); i++) {
        bool same = false;
        for (size_t j = 0; j < currentData.size(); j++) {
            if (data[i] == currentData[j]) {
                same = true;
            }
        }
        if (!same) {
            ASSERT_TRUE(len < mergeData.size());
            ASSERT_TRUE(data[i] == mergeData[len]);
            len++;
        }
    }
    ASSERT_TRUE(len == mergeData.size());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
