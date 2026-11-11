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

#include "security_manager/get_credential_id_plugin_test.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

constexpr uint64_t CREDENTIAL_ID = 1234567890123456789ULL;
constexpr uint64_t ALLOWABLE_DURATION = 60000;

void GetCredentialIdPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetCredentialIdPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

static void WriteRequest(MessageParcel &data, const std::vector<uint8_t> &authToken, uint64_t allowableDuration)
{
    data.WriteUInt8Vector(authToken);
    data.WriteUint64(allowableDuration);
}

/**
 * @tc.name: TestPluginInit
 * @tc.desc: Test GetCredentialIdPlugin init, policy code, policy name and needSave are set correctly.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestPluginInit, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = std::make_shared<GetCredentialIdPlugin>();
    ASSERT_NE(plugin, nullptr);
    ASSERT_TRUE(plugin->GetCode() == (std::uint32_t)EdmInterfaceCode::GET_CREDENTIAL_ID);
    ASSERT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_GET_CREDENTIAL_ID);
    ASSERT_FALSE(plugin->NeedSavePolicy());
}

/**
 * @tc.name: TestOnHandlePolicyInvalidValue
 * @tc.desc: Test OnHandlePolicy always returns ERR_INVALID_VALUE since the interface is read-only.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnHandlePolicyInvalidValue, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    uint32_t code = POLICY_FUNC_CODE(
        (std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::GET_CREDENTIAL_ID);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: TestOnGetPolicySuccess
 * @tc.desc: Test OnGetPolicy returns ERR_OK and replies the plaintext credential id on success.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicySuccess, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    plugin.mockedCredentialId = CREDENTIAL_ID;
    std::vector<uint8_t> authToken{0x01, 0x02, 0x03, 0x04};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, ALLOWABLE_DURATION);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.verifyCallCount, 1);
    ASSERT_EQ(plugin.lastAuthToken, authToken);
    ASSERT_EQ(plugin.lastAllowableDuration, ALLOWABLE_DURATION);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, ERR_OK);
    uint64_t credentialId = reply.ReadUint64();
    ASSERT_EQ(credentialId, CREDENTIAL_ID);
}

/**
 * @tc.name: TestOnGetPolicyEmptyAuthToken
 * @tc.desc: Test OnGetPolicy returns AUTH_TOKEN_INVALID(9201057) and skips the IAM call when the
 *     authToken is empty.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyEmptyAuthToken, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    std::vector<uint8_t> authToken;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, ALLOWABLE_DURATION);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::AUTH_TOKEN_INVALID);
    ASSERT_EQ(plugin.verifyCallCount, 0);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, EdmReturnErrCode::AUTH_TOKEN_INVALID);
}

/**
 * @tc.name: TestOnGetPolicyOversizeAuthToken
 * @tc.desc: Test OnGetPolicy returns AUTH_TOKEN_INVALID(9201057) and skips the IAM call when the
 *     authToken exceeds 1024 bytes.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyOversizeAuthToken, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    std::vector<uint8_t> authToken(EdmConstants::SecurityManager::MAX_AUTH_TOKEN_SIZE + 1, 0xAB);
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, ALLOWABLE_DURATION);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::AUTH_TOKEN_INVALID);
    ASSERT_EQ(plugin.verifyCallCount, 0);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, EdmReturnErrCode::AUTH_TOKEN_INVALID);
}

/**
 * @tc.name: TestOnGetPolicyMaxSizeAuthToken
 * @tc.desc: Test OnGetPolicy accepts the boundary authToken size of 1024 bytes.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyMaxSizeAuthToken, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    plugin.mockedCredentialId = CREDENTIAL_ID;
    std::vector<uint8_t> authToken(EdmConstants::SecurityManager::MAX_AUTH_TOKEN_SIZE, 0xCD);
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, ALLOWABLE_DURATION);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.verifyCallCount, 1);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, ERR_OK);
    uint64_t credentialId = reply.ReadUint64();
    ASSERT_EQ(credentialId, CREDENTIAL_ID);
}

/**
 * @tc.name: TestOnGetPolicyZeroAllowableDuration
 * @tc.desc: Test OnGetPolicy returns AUTH_TOKEN_INVALID_DURATION_INVALID(9201058) and skips the IAM
 *     call when the allowableDuration is zero.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyZeroAllowableDuration, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    std::vector<uint8_t> authToken{0x01, 0x02};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, 0);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::AUTH_TOKEN_INVALID_DURATION_INVALID);
    ASSERT_EQ(plugin.verifyCallCount, 0);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, EdmReturnErrCode::AUTH_TOKEN_INVALID_DURATION_INVALID);
}

/**
 * @tc.name: TestOnGetPolicyOversizeAllowableDuration
 * @tc.desc: Test OnGetPolicy returns AUTH_TOKEN_INVALID_DURATION_INVALID(9201058) and skips the IAM
 *     call when the allowableDuration exceeds 24 hours.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyOversizeAllowableDuration, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    std::vector<uint8_t> authToken{0x01, 0x02};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, EdmConstants::SecurityManager::MAX_ALLOWABLE_DURATION + 1);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::AUTH_TOKEN_INVALID_DURATION_INVALID);
    ASSERT_EQ(plugin.verifyCallCount, 0);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, EdmReturnErrCode::AUTH_TOKEN_INVALID_DURATION_INVALID);
}

/**
 * @tc.name: TestOnGetPolicyMaxAllowableDuration
 * @tc.desc: Test OnGetPolicy accepts the boundary allowableDuration of 24 hours.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyMaxAllowableDuration, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    plugin.mockedCredentialId = CREDENTIAL_ID;
    std::vector<uint8_t> authToken{0x01, 0x02};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, EdmConstants::SecurityManager::MAX_ALLOWABLE_DURATION);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.verifyCallCount, 1);
    ASSERT_EQ(plugin.lastAllowableDuration, EdmConstants::SecurityManager::MAX_ALLOWABLE_DURATION);
}

/**
 * @tc.name: TestOnGetPolicyVerifyFailed
 * @tc.desc: Test OnGetPolicy propagates the error code returned by the identity authentication
 *     service and does not write a credential id into the reply.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyVerifyFailed, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    plugin.verifyResult = EdmReturnErrCode::PARAM_ERROR;
    std::vector<uint8_t> authToken{0x01, 0x02};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, ALLOWABLE_DURATION);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    ASSERT_EQ(plugin.verifyCallCount, 1);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnGetPolicyVerifyTimeout
 * @tc.desc: Test OnGetPolicy propagates EXECUTE_TIME_OUT(9200016) when the identity authentication
 *     service does not respond in time.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyVerifyTimeout, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    plugin.verifyResult = EdmReturnErrCode::EXECUTE_TIME_OUT;
    std::vector<uint8_t> authToken{0x01, 0x02};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, ALLOWABLE_DURATION);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    ASSERT_EQ(plugin.verifyCallCount, 1);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: TestCallVerifyAuthTokenWithoutUseriamService
 * @tc.desc: Test the production CallVerifyAuthToken never reports success for an arbitrary auth
 *     token, and leaves the credential id untouched when the verification does not succeed.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestCallVerifyAuthTokenWithoutUseriamService, TestSize.Level1)
{
    GetCredentialIdPluginPureMock plugin;
    std::vector<uint8_t> authToken{0x01, 0x02, 0x03};
    uint64_t credentialId = CREDENTIAL_ID;
    ErrCode ret = plugin.InvokeCallVerifyAuthToken(authToken, ALLOWABLE_DURATION, credentialId);
    // An arbitrary token is never accepted, so the verification must not succeed.
    EXPECT_NE(ret, ERR_OK);
    EXPECT_EQ(credentialId, CREDENTIAL_ID);
}

/**
 * @tc.name: TestOnGetPolicyRealVerifyFailed
 * @tc.desc: Test OnGetPolicy does not report success when the real identity authentication seam
 *     rejects an arbitrary auth token, and the reply carries the error code instead of a
 *     credential id.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyRealVerifyFailed, TestSize.Level1)
{
    GetCredentialIdPluginRealMock plugin;
    std::vector<uint8_t> authToken{0x01, 0x02, 0x03};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, ALLOWABLE_DURATION);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_NE(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_NE(reply.ReadInt32(), ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicyEmptyParcel
 * @tc.desc: Test OnGetPolicy returns EXECUTE_TIME_OUT(9200016) when the request parcel carries no
 *     authToken and no allowableDuration, because the allowableDuration cannot be deserialized.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyEmptyParcel, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_EQ(plugin.verifyCallCount, 0);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: TestOnGetPolicySingleByteAuthToken
 * @tc.desc: Test OnGetPolicy accepts the smallest valid authToken of one byte.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicySingleByteAuthToken, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    plugin.mockedCredentialId = CREDENTIAL_ID;
    std::vector<uint8_t> authToken{0xFF};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, ALLOWABLE_DURATION);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(plugin.verifyCallCount, 1);
    EXPECT_EQ(plugin.lastAuthToken, authToken);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadUint64(), CREDENTIAL_ID);
}

/**
 * @tc.name: TestOnGetPolicyMinimalAllowableDuration
 * @tc.desc: Test OnGetPolicy accepts the smallest valid allowableDuration of 1 millisecond.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyMinimalAllowableDuration, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    plugin.mockedCredentialId = CREDENTIAL_ID;
    std::vector<uint8_t> authToken{0x01};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, 1);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(plugin.verifyCallCount, 1);
    EXPECT_EQ(plugin.lastAllowableDuration, 1);
}

/**
 * @tc.name: TestOnGetPolicyZeroCredentialId
 * @tc.desc: Test OnGetPolicy replies a zero credential id without failing when the identity
 *     authentication service reports a valid token whose credential id is zero.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyZeroCredentialId, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    plugin.mockedCredentialId = 0;
    std::vector<uint8_t> authToken{0x01, 0x02};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, ALLOWABLE_DURATION);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(plugin.verifyCallCount, 1);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadUint64(), 0);
}

/**
 * @tc.name: TestOnGetPolicyMaxUint64CredentialId
 * @tc.desc: Test OnGetPolicy replies the maximal uint64 credential id without truncation.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyMaxUint64CredentialId, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    plugin.mockedCredentialId = UINT64_MAX;
    std::vector<uint8_t> authToken{0x01, 0x02};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, ALLOWABLE_DURATION);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadUint64(), UINT64_MAX);
}

/**
 * @tc.name: TestOnGetPolicyAuthTokenCheckedBeforeDuration
 * @tc.desc: Test OnGetPolicy validates the authToken before the allowableDuration, so an
 *     oversized authToken combined with a zero duration is reported as an authToken error.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyAuthTokenCheckedBeforeDuration, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    std::vector<uint8_t> authToken(EdmConstants::SecurityManager::MAX_AUTH_TOKEN_SIZE + 1, 0x11);
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, 0);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::AUTH_TOKEN_INVALID);
    EXPECT_EQ(plugin.verifyCallCount, 0);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::AUTH_TOKEN_INVALID);
}

/**
 * @tc.name: TestOnGetPolicyDurationCheckedAfterAuthToken
 * @tc.desc: Test OnGetPolicy validates the allowableDuration after the authToken, so a valid
 *     authToken combined with a zero duration is reported as a duration error.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnGetPolicyDurationCheckedAfterAuthToken, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    std::vector<uint8_t> authToken{0x01, 0x02};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    WriteRequest(data, authToken, 0);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::AUTH_TOKEN_INVALID_DURATION_INVALID);
    EXPECT_EQ(plugin.verifyCallCount, 0);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::AUTH_TOKEN_INVALID_DURATION_INVALID);
}

/**
 * @tc.name: TestOnAdminRemoveReturnsOk
 * @tc.desc: Test OnAdminRemove returns ERR_OK because the interface does not persist any policy.
 * @tc.type: FUNC
 */
HWTEST_F(GetCredentialIdPluginTest, TestOnAdminRemoveReturnsOk, TestSize.Level1)
{
    GetCredentialIdPluginMock plugin;
    EXPECT_EQ(plugin.OnAdminRemove("com.edm.test.demo", "", "", DEFAULT_USER_ID), ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
