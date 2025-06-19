/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "iplugin_manager.h"
#include "telephony_call_policy_plugin.h"

#include "core_service_client.h"
#include "edm_ipc_interface_code.h"
#include "plugin_singleton.h"
#include "utils.h"
   
using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::string TEST_ADMIN_NAME = "testAdminName";

class TelephonyCallPolicyPluginTest : public testing::Test {
   protected:
        static void SetUpTestSuite(void);

        static void TearDownTestSuite(void);
};

void TelephonyCallPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void TelephonyCallPolicyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestAddCallPolicyNumbersSuccess
 * @tc.desc: Test TelephonyCallPolicyPlugin::OnHandlePolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyCallPolicyPluginTest, TestAddCallPolicyNumbersSuccess, TestSize.Level1)
{
    std::shared_ptr<TelephonyCallPolicyPlugin> plugin = std::make_shared<TelephonyCallPolicyPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::TELEPHONY_CALL_POLICY);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("incoming");
    data.WriteInt32(0);
    std::vector<std::string> numbers;
    numbers.push_back("11111111");
    data.WriteStringVector(numbers);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || EdmReturnErrCode::ENTERPRISE_POLICES_DENIED);
    std::string policyData;
    ret = plugin->GetOthersMergePolicyData(TEST_ADMIN_NAME, policyData);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveCallPolicyNumbersSuccess
 * @tc.desc: Test TelephonyCallPolicyPlugin::OnHandlePolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyCallPolicyPluginTest, TestRemoveCallPolicyNumbersSuccess, TestSize.Level1)
{
    std::shared_ptr<TelephonyCallPolicyPlugin> plugin = std::make_shared<TelephonyCallPolicyPlugin>();
    std::string policyData = R"({"incoming":{"policyFlag":0,"numberList":["11111111"]}})";
    HandlePolicyData handlePolicyData{policyData, "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("incoming");
    data.WriteInt32(0);
    std::vector<std::string> numbers;
    numbers.push_back("11111111");
    data.WriteStringVector(numbers);
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::TELEPHONY_CALL_POLICY);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::ENTERPRISE_POLICES_DENIED);
}

/**
 * @tc.name: TestGetCallPolicyNumbersSuccess
 * @tc.desc: Test TelephonyCallPolicyPlugin::GetCallPolicyNumbers function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyCallPolicyPluginTest, TestGetCallPolicyNumbersSuccess, TestSize.Level1)
{
    MessageParcel data;
    data.WriteString("incoming");
    data.WriteInt32(1);
    MessageParcel reply;
    std::shared_ptr<TelephonyCallPolicyPlugin> plugin = std::make_shared<TelephonyCallPolicyPlugin>();
    std::string policyData{""};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS