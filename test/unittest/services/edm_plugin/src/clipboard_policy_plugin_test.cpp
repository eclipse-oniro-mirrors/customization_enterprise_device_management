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
    std::map<int32_t, ClipboardPolicy> data;
    std::map<int32_t, ClipboardPolicy> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, 0);
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
    std::map<int32_t, ClipboardPolicy> data;
    data.insert(std::make_pair(1, ClipboardPolicy::IN_APP));
    std::map<int32_t, ClipboardPolicy> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, 0);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(currentData[1] == ClipboardPolicy::IN_APP);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test ClipboardPolicyPluginTest::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicyPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    ClipboardPolicyPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = POLICY_DATA;
    plugin.OnGetPolicy(policyData, data, reply, 0);
    int32_t ret = reply.ReadInt32();
    std::string policy = reply.ReadString();
    std::map<int32_t, ClipboardPolicy> policyMap;
    auto serializer_ = ClipboardSerializer::GetInstance();
    serializer_->Deserialize(policy, policyMap);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyMap.size() == 2);
}

/**
 * @tc.name: TestOnGetPolicyWithTokenId
 * @tc.desc: Test ClipboardPolicyPluginTest::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicyPluginTest, TestOnGetPolicyWithTokenId, TestSize.Level1)
{
    ClipboardPolicyPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = POLICY_DATA;
    data.WriteInt32(1);
    plugin.OnGetPolicy(policyData, data, reply, 0);
    int32_t ret = reply.ReadInt32();
    std::string policy = reply.ReadString();
    std::map<int32_t, ClipboardPolicy> policyMap;
    auto serializer_ = ClipboardSerializer::GetInstance();
    serializer_->Deserialize(policy, policyMap);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyMap[1] == ClipboardPolicy::IN_APP);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS