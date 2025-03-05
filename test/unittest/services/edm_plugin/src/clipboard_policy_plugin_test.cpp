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
#include "clipboard_info.h"
#include "clipboard_policy_plugin.h"
#include "clipboard_policy_serializer.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class ClipboardPolicyPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};
const std::string POLICY_DATA = "[{\"tokenId\":1,\"clipboardPolicy\":1},{\"tokenId\":2,\"clipboardPolicy\":2}]";
void ClipboardPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void ClipboardPolicyPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test ClipboardPolicyPluginTest::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicyPluginTest, TestOnSetPolicyEmpty, TestSize.Level1)
{
    ClipboardPolicyPlugin plugin;
    std::map<int32_t, ClipboardInfo> data;
    std::map<int32_t, ClipboardInfo> currentData;
    std::map<int32_t, ClipboardInfo> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, 0);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test ClipboardPolicyPluginTest::OnSetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicyPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    ClipboardPolicyPlugin plugin;
    std::map<int32_t, ClipboardInfo> data;
    ClipboardInfo info = {ClipboardPolicy::IN_APP, -1, ""};
    data.insert(std::make_pair(1, info));
    std::map<int32_t, ClipboardInfo> currentData;
    std::map<int32_t, ClipboardInfo> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, 0);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(currentData[1].policy == ClipboardPolicy::IN_APP);
}

/**
 * @tc.name: TestOnSetPolicyFail
 * @tc.desc: Test ClipboardPolicyPluginTest::OnSetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicyPluginTest, TestOnSetPolicyFail, TestSize.Level1)
{
    ClipboardPolicyPlugin plugin;
    std::map<int32_t, ClipboardInfo> data;
    ClipboardInfo info1 = {ClipboardPolicy::IN_APP, -1, ""};
    data.insert(std::make_pair(101, info1));
    std::map<int32_t, ClipboardInfo> currentData;
    for (int i = 1; i <= 100; i++) {
        ClipboardInfo info2 = {ClipboardPolicy::IN_APP, -1, ""};
        currentData.insert(std::make_pair(i, info2));
    }
    std::map<int32_t, ClipboardInfo> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, 0);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestHandlePasteboardPolicy
 * @tc.desc: Test ClipboardPolicyPluginTest::TestHandlePasteboardPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicyPluginTest, TestHandlePasteboardPolicy, TestSize.Level1)
{
    ClipboardPolicyPlugin plugin;
    std::map<int32_t, ClipboardInfo> result;
    ClipboardInfo info1 = {ClipboardPolicy::DEFAULT, -1, ""};
    ClipboardInfo info2 = {ClipboardPolicy::IN_APP, -1, ""};
    ClipboardInfo info3 = {ClipboardPolicy::LOCAL_DEVICE, -1, ""};
    ClipboardInfo info4 = {ClipboardPolicy::CROSS_DEVICE, -1, ""};
    result.insert(std::make_pair(1, info1));
    result.insert(std::make_pair(2, info2));
    result.insert(std::make_pair(3, info3));
    result.insert(std::make_pair(4, info4));
    ErrCode ret = plugin.HandlePasteboardPolicy(result);
    ASSERT_TRUE(ret == ERR_OK);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS