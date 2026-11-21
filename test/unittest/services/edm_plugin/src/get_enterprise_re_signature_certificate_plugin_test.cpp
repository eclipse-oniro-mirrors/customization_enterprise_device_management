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

#include "get_enterprise_re_signature_certificate_plugin_test.h"

#include <gtest/gtest.h>
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code.h"
#include "handle_policy_data.h"
#include "parameters.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
static constexpr int32_t ACCOUNTID_VALID_VALUE = 100;
static constexpr int32_t ACCOUNTID_INVALID_VALUE = 99;
static constexpr int32_t ACCOUNTID_NOT_EXIST_VALUE = 200;

static bool NotEnterpriseDevice()
{
    return !OHOS::system::GetBoolParameter("const.edm.is_enterprise_device", false);
}

void GetEnterpriseReSignatureCertificatePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetEnterpriseReSignatureCertificatePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicyInvalidAccount
 * @tc.desc: Test GetEnterpriseReSignatureCertificatePlugin::OnGetPolicy when accountId < 100.
 * @tc.type: FUNC
 */
HWTEST_F(GetEnterpriseReSignatureCertificatePluginTest, TestOnGetPolicyInvalidAccount, TestSize.Level1)
{
    std::shared_ptr<GetEnterpriseReSignatureCertificatePlugin> plugin =
        std::make_shared<GetEnterpriseReSignatureCertificatePlugin>();
    std::string policyData;
    MessageParcel data;
    data.WriteInt32(ACCOUNTID_INVALID_VALUE);
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::UID_INVALID);
    ASSERT_EQ(reply.ReadInt32(), EdmReturnErrCode::UID_INVALID);
}

/**
 * @tc.name: TestOnGetPolicyAccountNotExist
 * @tc.desc: Test GetEnterpriseReSignatureCertificatePlugin::OnGetPolicy when account is not exist.
 * @tc.type: FUNC
 */
HWTEST_F(GetEnterpriseReSignatureCertificatePluginTest, TestOnGetPolicyAccountNotExist, TestSize.Level1)
{
    std::shared_ptr<GetEnterpriseReSignatureCertificatePlugin> plugin =
        std::make_shared<GetEnterpriseReSignatureCertificatePlugin>();
    std::string policyData;
    MessageParcel data;
    data.WriteInt32(ACCOUNTID_NOT_EXIST_VALUE);
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::UID_INVALID);
    ASSERT_EQ(reply.ReadInt32(), EdmReturnErrCode::UID_INVALID);
}

/**
 * @tc.name: TestOnGetPolicySuccess
 * @tc.desc: Test GetEnterpriseReSignatureCertificatePlugin::OnGetPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(GetEnterpriseReSignatureCertificatePluginTest, TestOnGetPolicySuccess, TestSize.Level1)
{
    std::shared_ptr<GetEnterpriseReSignatureCertificatePlugin> plugin =
        std::make_shared<GetEnterpriseReSignatureCertificatePlugin>();
    std::string policyData;
    MessageParcel data;
    data.WriteInt32(ACCOUNTID_VALID_VALUE);
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    if (NotEnterpriseDevice()) {
        ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
        ASSERT_EQ(reply.ReadInt32(), EdmReturnErrCode::EXECUTE_TIME_OUT);
        return;
    }
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(reply.ReadInt32(), ERR_OK);
    int32_t size = reply.ReadInt32();
    ASSERT_GE(size, 0);
    for (int32_t i = 0; i < size; ++i) {
        ASSERT_FALSE(reply.ReadString().empty());
        ASSERT_FALSE(reply.ReadString().empty());
        reply.ReadInt64();
    }
}

/**
 * @tc.name: TestOnHandlePolicyUnsupported
 * @tc.desc: Test GetEnterpriseReSignatureCertificatePlugin::OnHandlePolicy returns empty policy data.
 * @tc.type: FUNC
 */
HWTEST_F(GetEnterpriseReSignatureCertificatePluginTest, TestOnHandlePolicyUnsupported, TestSize.Level1)
{
    std::shared_ptr<GetEnterpriseReSignatureCertificatePlugin> plugin =
        std::make_shared<GetEnterpriseReSignatureCertificatePlugin>();
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"testString", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET,
        EdmInterfaceCode::GET_ENTERPRISE_RE_SIGNATURE_CERTIFICATE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
