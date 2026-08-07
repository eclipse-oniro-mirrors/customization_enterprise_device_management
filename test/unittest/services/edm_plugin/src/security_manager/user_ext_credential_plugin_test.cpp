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

#include "security_manager/user_ext_credential_plugin_test.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "securec.h"
#include "ukey_iam_error_converter.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

void UserExtCredentialPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void UserExtCredentialPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

HWTEST_F(UserExtCredentialPluginTest, TestPluginInit, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = std::make_shared<UserExtCredentialPlugin>();
    ASSERT_NE(plugin, nullptr);
}

HWTEST_F(UserExtCredentialPluginTest, TestOnHandlePolicyInvalidOperateType, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_INVALID_VALUE);
}

// ========== AddCredential tests ==========

HWTEST_F(UserExtCredentialPluginTest, TestAddCredentialSuccess, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.addCredentialResult = 0;
    plugin.addCredentialId = 12345;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("testPluginInfo");
    std::vector<uint8_t> authToken = {0x01, 0x02, 0x03};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.lastAccountId, 100);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, 0);
    std::vector<uint8_t> credIdVec;
    reply.ReadUInt8Vector(&credIdVec);
    ASSERT_EQ(credIdVec.size(), sizeof(uint64_t));
    uint64_t credId = 0;
    memcpy_s(&credId, sizeof(uint64_t), credIdVec.data(), sizeof(uint64_t));
    ASSERT_EQ(credId, static_cast<uint64_t>(12345));
}

HWTEST_F(UserExtCredentialPluginTest, TestAddCredentialInvalidParameterError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.addCredentialResult = UKEY_ERR_IAM_INVALID_PARAMETERS;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("testPluginInfo");
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtCredentialPluginTest, TestAddCredentialAccountNotExistError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.addCredentialResult = UKEY_ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("testPluginInfo");
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(999);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_EQ(plugin.lastAccountId, 999);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtCredentialPluginTest, TestAddCredentialAuthTokenCheckFailedError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.addCredentialResult = UKEY_ERR_IAM_AUTH_TOKEN_CHECK_FAILED;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("testPluginInfo");
    std::vector<uint8_t> authToken = {0xFF};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtCredentialPluginTest, TestAddCredentialTokenTimeoutError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.addCredentialResult = UKEY_ERR_IAM_TOKEN_TIMEOUT;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("testPluginInfo");
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtCredentialPluginTest, TestAddCredentialTimeoutError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.addCredentialResult = UKEY_ERR_IAM_TIMEOUT;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("testPluginInfo");
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

HWTEST_F(UserExtCredentialPluginTest, TestAddCredentialCredentialLimitReachedError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.addCredentialResult = UKEY_ERR_IAM_CREDENTIAL_NUMBER_REACH_LIMIT;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("testPluginInfo");
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtCredentialPluginTest, TestAddCredentialRemoteDiedError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.addCredentialResult = UKEY_ERR_ACCOUNT_COMMON_REMOTE_DIED;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("testPluginInfo");
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

HWTEST_F(UserExtCredentialPluginTest, TestAddCredentialUnknownError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.addCredentialResult = 99999;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("testPluginInfo");
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_NE(replyErrMsg.find("Unknown"), std::string::npos);
}

// ========== RemoveCredential tests ==========

HWTEST_F(UserExtCredentialPluginTest, TestRemoveCredentialInvalidSizeEmpty, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    std::vector<uint8_t> credIdVec = {};
    data.WriteUInt8Vector(credIdVec);
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(UserExtCredentialPluginTest, TestRemoveCredentialInvalidSizeOneByte, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    std::vector<uint8_t> credIdVec = {0xFF};
    data.WriteUInt8Vector(credIdVec);
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(UserExtCredentialPluginTest, TestRemoveCredentialInvalidSizeSevenBytes, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    std::vector<uint8_t> credIdVec(sizeof(uint64_t) - 1, 0xAB);
    data.WriteUInt8Vector(credIdVec);
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

HWTEST_F(UserExtCredentialPluginTest, TestRemoveCredentialOversizedCredId, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.delCredResult = 0;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    std::vector<uint8_t> credIdVec(sizeof(uint64_t) + 1, 0xAB);
    data.WriteUInt8Vector(credIdVec);
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.lastAccountId, 100);
}

HWTEST_F(UserExtCredentialPluginTest, TestRemoveCredentialSuccess, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.delCredResult = 0;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    uint64_t credentialId = 12345;
    std::vector<uint8_t> credIdVec(sizeof(uint64_t));
    memcpy_s(credIdVec.data(), sizeof(uint64_t), &credentialId, sizeof(uint64_t));
    data.WriteUInt8Vector(credIdVec);
    std::vector<uint8_t> authToken = {0x01, 0x02, 0x03};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.lastAccountId, 100);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, 0);
}

HWTEST_F(UserExtCredentialPluginTest, TestRemoveCredentialNotEnrolledError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.delCredResult = UKEY_ERR_IAM_NOT_ENROLLED;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    uint64_t credentialId = 99999;
    std::vector<uint8_t> credIdVec(sizeof(uint64_t));
    memcpy_s(credIdVec.data(), sizeof(uint64_t), &credentialId, sizeof(uint64_t));
    data.WriteUInt8Vector(credIdVec);
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtCredentialPluginTest, TestRemoveCredentialTokenExpiredError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.delCredResult = UKEY_ERR_IAM_AUTH_TOKEN_EXPIRED;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    uint64_t credentialId = 1;
    std::vector<uint8_t> credIdVec(sizeof(uint64_t));
    memcpy_s(credIdVec.data(), sizeof(uint64_t), &credentialId, sizeof(uint64_t));
    data.WriteUInt8Vector(credIdVec);
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtCredentialPluginTest, TestRemoveCredentialSessionTimeoutError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.delCredResult = UKEY_ERR_IAM_SESSION_TIMEOUT;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    uint64_t credentialId = 1;
    std::vector<uint8_t> credIdVec(sizeof(uint64_t));
    memcpy_s(credIdVec.data(), sizeof(uint64_t), &credentialId, sizeof(uint64_t));
    data.WriteUInt8Vector(credIdVec);
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtCredentialPluginTest, TestRemoveCredentialIpcError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.delCredResult = UKEY_ERR_IAM_IPC_ERROR;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    uint64_t credentialId = 1;
    std::vector<uint8_t> credIdVec(sizeof(uint64_t));
    memcpy_s(credIdVec.data(), sizeof(uint64_t), &credentialId, sizeof(uint64_t));
    data.WriteUInt8Vector(credIdVec);
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

HWTEST_F(UserExtCredentialPluginTest, TestRemoveCredentialBusyError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.delCredResult = UKEY_ERR_IAM_BUSY;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::USER_EXT_CREDENTIAL);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    uint64_t credentialId = 1;
    std::vector<uint8_t> credIdVec(sizeof(uint64_t));
    memcpy_s(credIdVec.data(), sizeof(uint64_t), &credentialId, sizeof(uint64_t));
    data.WriteUInt8Vector(credIdVec);
    std::vector<uint8_t> authToken = {0x01};
    data.WriteUInt8Vector(authToken);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

// ========== OnGetPolicy tests ==========

HWTEST_F(UserExtCredentialPluginTest, TestGetCredentialInfoSuccess, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.getCredInfoResult = 0;
    AccountSA::CredentialInfo info1;
    info1.credentialId = 111;
    AccountSA::CredentialInfo info2;
    info2.credentialId = 222;
    plugin.credInfoList = {info1, info2};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.lastAccountId, 100);
    reply.RewindRead(0);
    int32_t replyRet = reply.ReadInt32();
    ASSERT_EQ(replyRet, 0);
    int32_t count = reply.ReadInt32();
    ASSERT_EQ(count, 2);
    std::vector<uint8_t> credIdVec1;
    reply.ReadUInt8Vector(&credIdVec1);
    uint64_t credId1 = 0;
    memcpy_s(&credId1, sizeof(uint64_t), credIdVec1.data(), sizeof(uint64_t));
    ASSERT_EQ(credId1, static_cast<uint64_t>(111));
    std::vector<uint8_t> credIdVec2;
    reply.ReadUInt8Vector(&credIdVec2);
    uint64_t credId2 = 0;
    memcpy_s(&credId2, sizeof(uint64_t), credIdVec2.data(), sizeof(uint64_t));
    ASSERT_EQ(credId2, static_cast<uint64_t>(222));
}

HWTEST_F(UserExtCredentialPluginTest, TestGetCredentialInfoSuccessEmpty, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.getCredInfoResult = 0;
    plugin.credInfoList = {};
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    reply.ReadInt32();
    int32_t count = reply.ReadInt32();
    ASSERT_EQ(count, 0);
}

HWTEST_F(UserExtCredentialPluginTest, TestGetCredentialInfoInvalidParameterError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.getCredInfoResult = UKEY_ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(-1);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtCredentialPluginTest, TestGetCredentialInfoTimeoutError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.getCredInfoResult = UKEY_ERR_IAM_TIMEOUT;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}

HWTEST_F(UserExtCredentialPluginTest, TestGetCredentialInfoNoValidCredentialError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.getCredInfoResult = UKEY_ERR_IAM_NO_VALID_CREDENTIAL;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED));
    std::string replyErrMsg = reply.ReadString();
    ASSERT_FALSE(replyErrMsg.empty());
}

HWTEST_F(UserExtCredentialPluginTest, TestGetCredentialInfoOperationFailError, TestSize.Level1)
{
    UserExtCredentialPluginMock plugin;
    plugin.getCredInfoResult = UKEY_ERR_ACCOUNT_COMMON_OPERATION_FAIL;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    reply.RewindRead(0);
    int32_t replyErrCode = reply.ReadInt32();
    ASSERT_EQ(replyErrCode, static_cast<int32_t>(EdmReturnErrCode::EXECUTE_TIME_OUT));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
