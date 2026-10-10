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

#include "volume_degree_plugin.h"

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "message_parcel.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t STREAM_MUSIC = 1;
constexpr int32_t VOLUME_DEGREE_MIN = 0;
constexpr int32_t VOLUME_DEGREE_MAX = 100;
class VolumeDegreePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
 
    static void TearDownTestSuite(void);
};

void VolumeDegreePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void VolumeDegreePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyUnsupportedOperateType
 * @tc.desc: Test VolumeDegreePlugin::OnHandlePolicy with unsupported operate type.
 * @tc.type: FUNC
 */
HWTEST_F(VolumeDegreePluginTest, TestOnHandlePolicyUnsupportedOperateType, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(STREAM_MUSIC);
    data.WriteInt32(VOLUME_DEGREE_MIN);
    auto plugin = std::make_shared<VolumeDegreePlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET,
        EdmInterfaceCode::VOLUME_DEGREE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyReadVolumeTypeFailed
 * @tc.desc: Test VolumeDegreePlugin::OnHandlePolicy read volumeType failed.
 * @tc.type: FUNC
 */
HWTEST_F(VolumeDegreePluginTest, TestOnHandlePolicyReadVolumeTypeFailed, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<VolumeDegreePlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::VOLUME_DEGREE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyReadDegreeFailed
 * @tc.desc: Test VolumeDegreePlugin::OnHandlePolicy read degree failed.
 * @tc.type: FUNC
 */
HWTEST_F(VolumeDegreePluginTest, TestOnHandlePolicyReadDegreeFailed, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(STREAM_MUSIC);
    auto plugin = std::make_shared<VolumeDegreePlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::VOLUME_DEGREE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyInvalidVolumeType
 * @tc.desc: Test VolumeDegreePlugin::OnHandlePolicy with invalid volumeType.
 * @tc.type: FUNC
 */
HWTEST_F(VolumeDegreePluginTest, TestOnHandlePolicyInvalidVolumeType, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(STREAM_MUSIC + 1);
    data.WriteInt32(VOLUME_DEGREE_MAX);
    auto plugin = std::make_shared<VolumeDegreePlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::VOLUME_DEGREE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyDegreeTooLow
 * @tc.desc: Test VolumeDegreePlugin::OnHandlePolicy with degree below the range.
 * @tc.type: FUNC
 */
HWTEST_F(VolumeDegreePluginTest, TestOnHandlePolicyDegreeTooLow, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(STREAM_MUSIC);
    data.WriteInt32(VOLUME_DEGREE_MIN - 1);
    auto plugin = std::make_shared<VolumeDegreePlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::VOLUME_DEGREE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyDegreeTooHigh
 * @tc.desc: Test VolumeDegreePlugin::OnHandlePolicy with degree above the range.
 * @tc.type: FUNC
 */
HWTEST_F(VolumeDegreePluginTest, TestOnHandlePolicyDegreeTooHigh, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(STREAM_MUSIC);
    data.WriteInt32(VOLUME_DEGREE_MAX + 1);
    auto plugin = std::make_shared<VolumeDegreePlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::VOLUME_DEGREE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicySetVolumeDegree
 * @tc.desc: Test VolumeDegreePlugin::OnHandlePolicy set volume degree.
 * @tc.type: FUNC
 */
HWTEST_F(VolumeDegreePluginTest, TestOnHandlePolicySetVolumeDegree, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(STREAM_MUSIC);
    data.WriteInt32(VOLUME_DEGREE_MAX / 2);
    auto plugin = std::make_shared<VolumeDegreePlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::VOLUME_DEGREE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicyReadVolumeTypeFailed
 * @tc.desc: Test VolumeDegreePlugin::OnGetPolicy read volumeType failed.
 * @tc.type: FUNC
 */
HWTEST_F(VolumeDegreePluginTest, TestOnGetPolicyReadVolumeTypeFailed, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    auto plugin = std::make_shared<VolumeDegreePlugin>();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicyInvalidVolumeType
 * @tc.desc: Test VolumeDegreePlugin::OnGetPolicy with invalid volumeType.
 * @tc.type: FUNC
 */
HWTEST_F(VolumeDegreePluginTest, TestOnGetPolicyInvalidVolumeType, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(STREAM_MUSIC + 1);
    std::string policyData;
    auto plugin = std::make_shared<VolumeDegreePlugin>();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicySuccess
 * @tc.desc: Test VolumeDegreePlugin::OnGetPolicy get volume degree success.
 * @tc.type: FUNC
 */
HWTEST_F(VolumeDegreePluginTest, TestOnGetPolicySuccess, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(STREAM_MUSIC);
    std::string policyData;
    auto plugin = std::make_shared<VolumeDegreePlugin>();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS