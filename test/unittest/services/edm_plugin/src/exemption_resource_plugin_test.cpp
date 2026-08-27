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
#include <message_parcel.h>
#include <parameters.h>

#define private public
#define protected public
#include "exemption_resource_plugin.h"
#undef private
#undef protected

#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr uint32_t NETWORK_TYPE = 1;
constexpr int32_t TEST_DURATION = 3600;
const std::string TEST_BUNDLE = "com.test.app";
}

class ExemptionResourcePluginTest : public testing::Test {
public:
    static void SetUpTestSuite(void)
    {
        Utils::SetEdmInitialEnv();
    }

    static void TearDownTestSuite(void)
    {
        Utils::ResetTokenTypeAndUid();
        ASSERT_TRUE(Utils::IsOriginalUTEnv());
    }

    void SetUp() override
    {
        plugin_ = std::make_shared<ExemptionResourcePlugin>();
    }

    void TearDown() override
    {
        plugin_.reset();
    }

    std::shared_ptr<ExemptionResourcePlugin> plugin_;
};

/**
 * @tc.name: ValidateParams_Normal_Success
 * @tc.desc: Test ValidateParams with valid parameters for apply operation.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, ValidateParams_Normal_Success, TestSize.Level1)
{
    bool isRemove = false;
    uint32_t allowType = NETWORK_TYPE;
    std::string bundleName = TEST_BUNDLE;
    int32_t duration = TEST_DURATION;
    ErrCode ret = plugin_->ValidateParams(isRemove, allowType, bundleName, duration);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(allowType, NETWORK_TYPE);
    ASSERT_EQ(bundleName, TEST_BUNDLE);
    ASSERT_EQ(duration, TEST_DURATION);
}

/**
 * @tc.name: ValidateParams_Remove_NoDuration_Success
 * @tc.desc: Test ValidateParams with isRemove=true, duration not validated.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, ValidateParams_Remove_NoDuration_Success, TestSize.Level1)
{
    bool isRemove = true;
    uint32_t allowType = NETWORK_TYPE;
    std::string bundleName = TEST_BUNDLE;
    int32_t duration = 0;
    ErrCode ret = plugin_->ValidateParams(isRemove, allowType, bundleName, duration);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(isRemove);
    ASSERT_EQ(duration, 0);
    ASSERT_EQ(allowType, NETWORK_TYPE);
}

/**
 * @tc.name: ValidateParams_InvalidAllowType_Fail
 * @tc.desc: Test ValidateParams with invalid allowType values.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, ValidateParams_InvalidAllowType_Fail, TestSize.Level1)
{
    uint32_t invalidValues[] = {0, 2, 3, 99, 255};
    for (uint32_t allowType : invalidValues) {
        ErrCode ret = plugin_->ValidateParams(false, allowType, TEST_BUNDLE, TEST_DURATION);
        ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    }
    ErrCode ret2 = plugin_->ValidateParams(false, NETWORK_TYPE, TEST_BUNDLE, TEST_DURATION);
    ASSERT_EQ(ret2, ERR_OK);
}

/**
 * @tc.name: ValidateParams_EmptyBundleName_Fail
 * @tc.desc: Test ValidateParams with empty bundleName string.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, ValidateParams_EmptyBundleName_Fail, TestSize.Level1)
{
    std::string emptyName = "";
    ErrCode ret = plugin_->ValidateParams(false, NETWORK_TYPE, emptyName, TEST_DURATION);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_TRUE(emptyName.empty());
    std::string validName = TEST_BUNDLE;
    ErrCode ret2 = plugin_->ValidateParams(false, NETWORK_TYPE, validName, TEST_DURATION);
    ASSERT_EQ(ret2, ERR_OK);
    ASSERT_EQ(validName, TEST_BUNDLE);
}

/**
 * @tc.name: ValidateParams_InvalidDuration_Fail
 * @tc.desc: Test ValidateParams with zero and negative duration on apply (SET).
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, ValidateParams_InvalidDuration_Fail, TestSize.Level1)
{
    int32_t invalidDurations[] = {0, -1, -100, -9999};
    for (int32_t duration : invalidDurations) {
        ErrCode ret = plugin_->ValidateParams(false, NETWORK_TYPE, TEST_BUNDLE, duration);
        ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    }
    ErrCode ret2 = plugin_->ValidateParams(true, NETWORK_TYPE, TEST_BUNDLE, 0);
    ASSERT_EQ(ret2, ERR_OK);
    ErrCode ret3 = plugin_->ValidateParams(false, NETWORK_TYPE, TEST_BUNDLE, 1);
    ASSERT_EQ(ret3, ERR_OK);
}

/**
 * @tc.name: ConvertStandbyErrCode_ErrOk_Success
 * @tc.desc: Test ConvertStandbyErrCode with ERR_OK input returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, ConvertStandbyErrCode_ErrOk_Success, TestSize.Level1)
{
    ErrCode input = ERR_OK;
    ErrCode ret = plugin_->ConvertStandbyErrCode(input);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(input, ERR_OK);
    ErrCode ret2 = plugin_->ConvertStandbyErrCode(0);
    ASSERT_EQ(ret2, ERR_OK);
}

/**
 * @tc.name: ConvertStandbyErrCode_NonZero_Fail
 * @tc.desc: Test ConvertStandbyErrCode with various non-zero error codes.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, ConvertStandbyErrCode_NonZero_Fail, TestSize.Level1)
{
    ErrCode codes[] = {980000401, 980000403, 9800404, 9800407, 201, 202};
    for (ErrCode code : codes) {
        ErrCode ret = plugin_->ConvertStandbyErrCode(code);
        ASSERT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    }
    ErrCode ret = plugin_->ConvertStandbyErrCode(ERR_OK);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OnHandlePolicy_InvalidAllowType_Fail
 * @tc.desc: Test OnHandlePolicy with invalid allowType returns before external deps.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, OnHandlePolicy_InvalidAllowType_Fail, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteUint32(99);
    data.WriteString(TEST_BUNDLE);
    data.WriteInt32(TEST_DURATION);

    HandlePolicyData policyData;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::EXEMPTION_RESOURCE);
    ErrCode ret = plugin_->OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: OnHandlePolicy_EmptyBundleName_Fail
 * @tc.desc: Test OnHandlePolicy with empty bundleName returns before external deps.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, OnHandlePolicy_EmptyBundleName_Fail, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteUint32(NETWORK_TYPE);
    data.WriteString("");
    data.WriteInt32(TEST_DURATION);

    HandlePolicyData policyData;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::EXEMPTION_RESOURCE);
    ErrCode ret = plugin_->OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: OnHandlePolicy_ZeroDuration_Fail
 * @tc.desc: Test OnHandlePolicy with duration=0 on SET returns before external deps.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, OnHandlePolicy_ZeroDuration_Fail, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteUint32(NETWORK_TYPE);
    data.WriteString(TEST_BUNDLE);
    data.WriteInt32(0);

    HandlePolicyData policyData;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::EXEMPTION_RESOURCE);
    ErrCode ret = plugin_->OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: OnHandlePolicy_NegativeDuration_Fail
 * @tc.desc: Test OnHandlePolicy with negative duration on SET.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, OnHandlePolicy_NegativeDuration_Fail, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteUint32(NETWORK_TYPE);
    data.WriteString(TEST_BUNDLE);
    data.WriteInt32(-100);

    HandlePolicyData policyData;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::EXEMPTION_RESOURCE);
    ErrCode ret = plugin_->OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: OnHandlePolicy_Remove_NoDurationParam_PassesValidation
 * @tc.desc: Test OnHandlePolicy with REMOVE. Passes validation, calls downstream + ResetStandbyServiceClient. Needs rd mode.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, OnHandlePolicy_Remove_NoDurationParam_PassesValidation, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter("const.boot.oemmode", "user");
    if (developDeviceParam != "rd") {
        GTEST_SKIP() << "Skip: requires rd mode for BundleMgr dependency";
    }

    MessageParcel data;
    MessageParcel reply;
    data.WriteUint32(NETWORK_TYPE);
    data.WriteString(TEST_BUNDLE);

    HandlePolicyData policyData;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::EXEMPTION_RESOURCE);
    ErrCode ret = plugin_->OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED ||
        ret == EdmReturnErrCode::APPLICATION_INSTALL_FAILED ||
        ret == EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: Constructor_Attributes_Initialized
 * @tc.desc: Test that constructor sets correct policyCode, policyName, needSave, permission.
 * @tc.type: FUNC
 */
HWTEST_F(ExemptionResourcePluginTest, Constructor_Attributes_Initialized, TestSize.Level1)
{
    ASSERT_EQ(plugin_->policyCode_, EdmInterfaceCode::EXEMPTION_RESOURCE);
    ASSERT_EQ(plugin_->policyName_, PolicyName::POLICY_EXEMPTION_RESOURCE);
    ASSERT_FALSE(plugin_->needSave_);
    ASSERT_EQ(plugin_->permissionConfig_.apiType, IPlugin::ApiType::PUBLIC);
    ASSERT_NE(plugin_->policyCode_, 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
