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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ashmem.h"
#include "iplugin_manager.h"
#include "telephony_sms_policy_plugin.h"

#include "core_service_client.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "plugin_singleton.h"
#include "policy_flag.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::string TEST_ADMIN_NAME = "testAdminName";
const std::string PARAM_DISALLOWED_SMS = "persist.edm.sms_disable";

class TelephonySmsPolicyPluginTest : public testing::Test {
   protected:
        static void SetUpTestSuite(void);

        static void TearDownTestSuite(void);
};

class MockPolicyManager : public IPolicyManager {
public:
    MOCK_METHOD4(GetPolicy, ErrCode(const std::string &, const std::string &, std::string &, int32_t));
};

namespace {
bool BuildSmsAshmemPolicyData(MessageParcel &data, const std::string &smsType, int32_t flag,
    const std::vector<std::string> &numbers)
{
    data.WriteString(smsType);
    data.WriteInt32(flag);
    MessageParcel tempParcel;
    (void)tempParcel.SetMaxCapacity(EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM);
    if (!tempParcel.WriteStringVector(numbers)) {
        return false;
    }
    size_t dataSize = tempParcel.GetDataSize();
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem("TestSmsPolicyNumberList", dataSize);
    if (ashmem == nullptr || !ashmem->MapReadAndWriteAshmem()) {
        return false;
    }
    int32_t offset = 0;
    if (!ashmem->WriteToAshmem(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize, offset)) {
        return false;
    }
    data.WriteInt32(static_cast<int32_t>(dataSize));
    return data.WriteAshmem(ashmem);
}
} // namespace

void TelephonySmsPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void TelephonySmsPolicyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestAddSmsPolicyNumbersSuccess
 * @tc.desc: Test TelephonySmsPolicyPlugin::OnHandlePolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonySmsPolicyPluginTest, TestAddSmsPolicyNumbersSuccess, TestSize.Level1)
{
    std::shared_ptr<TelephonySmsPolicyPlugin> plugin = std::make_shared<TelephonySmsPolicyPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::TELEPHONY_SMS_POLICY);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    std::vector<std::string> numbers;
    numbers.push_back("11111111");
    ASSERT_TRUE(BuildSmsAshmemPolicyData(data, "incoming", 0, numbers));
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::ENTERPRISE_POLICES_DENIED);
    std::string policyData;
    int32_t userId100 = 100;
    ret = plugin->GetOthersMergePolicyData(TEST_ADMIN_NAME, userId100, policyData);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddSmsPolicyNumbersViaAshmemSuccess
 * @tc.desc: Test TelephonySmsPolicyPlugin::OnHandlePolicy reads number list from ashmem format.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonySmsPolicyPluginTest, TestAddSmsPolicyNumbersViaAshmemSuccess, TestSize.Level1)
{
    std::shared_ptr<TelephonySmsPolicyPlugin> plugin = std::make_shared<TelephonySmsPolicyPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::TELEPHONY_SMS_POLICY);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    std::vector<std::string> numbers;
    numbers.push_back("11111111");
    ASSERT_TRUE(BuildSmsAshmemPolicyData(data, "incoming", 0, numbers));
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || EdmReturnErrCode::ENTERPRISE_POLICES_DENIED);
}

/**
 * @tc.name: TestRemoveSmsPolicyNumbersSuccess
 * @tc.desc: Test TelephonySmsPolicyPlugin::OnHandlePolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonySmsPolicyPluginTest, TestRemoveSmsPolicyNumbersSuccess, TestSize.Level1)
{
    std::shared_ptr<TelephonySmsPolicyPlugin> plugin = std::make_shared<TelephonySmsPolicyPlugin>();
    std::string policyData = R"({"incoming":{"policyFlag":0,"numberList":["11111111"]}})";
    HandlePolicyData handlePolicyData{policyData, "", false};
    MessageParcel data;
    MessageParcel reply;
    std::vector<std::string> numbers;
    numbers.push_back("11111111");
    ASSERT_TRUE(BuildSmsAshmemPolicyData(data, "incoming", 0, numbers));
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::TELEPHONY_SMS_POLICY);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::ENTERPRISE_POLICES_DENIED);
}

/**
 * @tc.name: TestGetSmsPolicyNumbersSuccess
 * @tc.desc: Test TelephonySmsPolicyPlugin::GetSmsPolicyNumbers function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonySmsPolicyPluginTest, TestGetSmsPolicyNumbersSuccess, TestSize.Level1)
{
    MessageParcel data;
    data.WriteString("incoming");
    data.WriteInt32(1);
    MessageParcel reply;
    std::shared_ptr<TelephonySmsPolicyPlugin> plugin = std::make_shared<TelephonySmsPolicyPlugin>();
    std::string policyData{""};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
}

/**
 * @tc.name: TestAddSmsPolicyTrustBlockConflict
 * @tc.desc: Adding BLOCK_LIST while TRUST_LIST already exists for the same sms type returns conflict.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonySmsPolicyPluginTest, TestAddSmsPolicyTrustBlockConflict, TestSize.Level1)
{
    system::SetParameter(PARAM_DISALLOWED_SMS, "false");
    MockPolicyManager mockPolicyManager;
    IPolicyManager::policyManagerInstance_ = &mockPolicyManager;
    std::string mergedPolicy = R"({"incoming":{"policyFlag":1,"numberList":["11111111"]}})";
    EXPECT_CALL(mockPolicyManager, GetPolicy(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(mergedPolicy), Return(ERR_OK)));

    std::shared_ptr<TelephonySmsPolicyPlugin> plugin = std::make_shared<TelephonySmsPolicyPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::TELEPHONY_SMS_POLICY);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    std::vector<std::string> numbers;
    numbers.push_back("22222222");
    ASSERT_TRUE(BuildSmsAshmemPolicyData(data, "incoming",
        static_cast<int32_t>(PolicyFlag::BLOCK_LIST), numbers));

    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    IPolicyManager::policyManagerInstance_ = nullptr;
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
