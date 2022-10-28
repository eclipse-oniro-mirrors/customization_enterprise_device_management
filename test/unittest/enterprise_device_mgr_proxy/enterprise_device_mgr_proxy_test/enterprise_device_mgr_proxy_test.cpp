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
#include <string>
#include <vector>
#include "cmd_utils.h"
#include "enterprise_device_mgr_proxy.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "edm_sys_manager_mock.h"
#include "func_code.h"
#include "policy_info.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Mock;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t DEFAULT_USERID = 100;
constexpr int32_t FUNC_CODE_ERR = -222;
}
class EnterpriseDeviceMgrProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<EnterpriseDeviceMgrProxy> enterpriseDeviceMgrProxyTest = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void EnterpriseDeviceMgrProxyTest::SetUp()
{
    enterpriseDeviceMgrProxyTest = EnterpriseDeviceMgrProxy::GetInstance();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
}

void EnterpriseDeviceMgrProxyTest::TearDown()
{
    EnterpriseDeviceMgrProxy::DestroyInstance();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
}

/**
 * @tc.name: TestEnableAdminSuc
 * @tc.desc: Test EnableAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestEnableAdminSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    EntInfo entInfo("test", "this is test");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequest));
    ErrCode errVal = enterpriseDeviceMgrProxyTest->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USERID);
    EXPECT_TRUE(errVal == ERR_OK);
}

/**
 * @tc.name: TestEnableAdminFail
 * @tc.desc: Test EnableAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestEnableAdminFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    EntInfo entInfo("test", "this is test");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    ErrCode errVal = enterpriseDeviceMgrProxyTest->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USERID);
    EXPECT_TRUE(errVal != ERR_OK);
}

/**
 * @tc.name: TestSetEnterpriseInfoSuc
 * @tc.desc: Test SetEnterpriseInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestSetEnterpriseInfoSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    EntInfo entInfo("test", "this is test");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequest));
    ErrCode errVal = enterpriseDeviceMgrProxyTest->SetEnterpriseInfo(admin, entInfo);
    EXPECT_TRUE(errVal == ERR_OK);
}

/**
 * @tc.name: TestSetEnterpriseInfoFail
 * @tc.desc: Test SetEnterpriseInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestSetEnterpriseInfoFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    EntInfo entInfo("test", "this is test");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    ErrCode errVal = enterpriseDeviceMgrProxyTest->SetEnterpriseInfo(admin, entInfo);
    EXPECT_TRUE(errVal != ERR_OK);
}

/**
 * @tc.name: TestGetEnterpriseInfoEntInfo
 * @tc.desc: Test GetEnterpriseInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetEnterpriseInfoEntInfo, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetEnterpriseInfo));
    EntInfo entInfo1;
    ErrCode errVal = enterpriseDeviceMgrProxyTest->GetEnterpriseInfo(admin, entInfo1);
    EXPECT_TRUE(errVal == ERR_OK);
}

/**
 * @tc.name: TestGetEnterpriseInfoFail
 * @tc.desc: Test GetEnterpriseInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetEnterpriseInfoFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    EntInfo entInfo1;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    enterpriseDeviceMgrProxyTest->GetEnterpriseInfo(admin, entInfo1);
    EXPECT_TRUE(entInfo1.enterpriseName.size() == 0);
    EXPECT_TRUE(entInfo1.description.size() == 0);
}

/**
 * @tc.name: TestIsAdminEnabledFail
 * @tc.desc: Test IsAdminEnabled func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestIsAdminEnabledFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    bool ret = enterpriseDeviceMgrProxyTest->IsAdminEnabled(admin, DEFAULT_USERID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestGetEnabledAdminReplyFail
 * @tc.desc: Test GetEnabledAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetEnabledAdminReplyFail, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestReplyFail));
    std::vector<std::u16string> enabledAdminList1;
    ErrCode errVal = enterpriseDeviceMgrProxyTest->GetEnabledAdmin(AdminType::NORMAL, enabledAdminList1);
    EXPECT_TRUE(errVal != ERR_OK);
}

/**
 * @tc.name: TestGetEnabledAdminFail
 * @tc.desc: Test GetEnabledAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetEnabledAdminFail, TestSize.Level1)
{
    std::vector<std::u16string> enabledAdminList1;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    ErrCode errVal = enterpriseDeviceMgrProxyTest->GetEnabledAdmin(AdminType::NORMAL, enabledAdminList1);
    EXPECT_TRUE(errVal != ERR_OK);
}

/**
 * @tc.name: TestIsPolicyDisableSuc
 * @tc.desc: Test IsPolicyDisable func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestIsPolicyDisableSuc, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequest));
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    bool isDisabled = false;
    bool ret = enterpriseDeviceMgrProxyTest->IsPolicyDisable(funcCode, isDisabled);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(!isDisabled);
}

/**
 * @tc.name: TestIsPolicyDisableFail
 * @tc.desc: Test IsPolicyDisable func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestIsPolicyDisableFail, TestSize.Level1)
{
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    bool isDisabled = false;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    bool ret = enterpriseDeviceMgrProxyTest->IsPolicyDisable(funcCode, isDisabled);
    EXPECT_TRUE(!ret);
    EXPECT_TRUE(!isDisabled);
}

/**
 * @tc.name: TestIsPolicyDisableFuncCodeFail
 * @tc.desc: Test IsPolicyDisable func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestIsPolicyDisableFuncCodeFail, TestSize.Level1)
{
    bool isDisabled = false;
    bool ret = enterpriseDeviceMgrProxyTest->IsPolicyDisable(FUNC_CODE_ERR, isDisabled);
    EXPECT_TRUE(!ret);
    EXPECT_TRUE(!isDisabled);
}

/**
 * @tc.name: TestGetPolicyValueSuc
 * @tc.desc: Test GetPolicyValue func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetPolicyValueSuc, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequest));
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    std::string policyData;
    bool ret = enterpriseDeviceMgrProxyTest->GetPolicyValue(funcCode, policyData);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TestGetPolicyValueReplyFail
 * @tc.desc: Test GetPolicyValue func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetPolicyValueReplyFail, TestSize.Level1)
{
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    std::string policyData;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestReplyFail));
    bool ret = enterpriseDeviceMgrProxyTest->GetPolicyValue(funcCode, policyData);
    EXPECT_TRUE(!ret);
}

/**
 * @tc.name: TestHandleDevicePolicyFuncCodeFail
 * @tc.desc: Test HandleDevicePolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestHandleDevicePolicyFuncCodeFail, TestSize.Level1)
{
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    MessageParcel data;
    ErrCode errVal = enterpriseDeviceMgrProxyTest->HandleDevicePolicy(funcCode, data);
    EXPECT_TRUE(errVal != ERR_OK);
}

/**
 * @tc.name: TestDisableAdminSuc
 * @tc.desc: Test DisableAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestDisableAdminSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequest));
    ErrCode errVal = enterpriseDeviceMgrProxyTest->DisableAdmin(admin, DEFAULT_USERID);
    EXPECT_TRUE(errVal == ERR_OK);
}

/**
 * @tc.name: TestDisableAdminFail
 * @tc.desc: Test DisableAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestDisableAdminFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    ErrCode errVal = enterpriseDeviceMgrProxyTest->DisableAdmin(admin, DEFAULT_USERID);
    EXPECT_TRUE(errVal != ERR_OK);
}

/**
 * @tc.name: TestGetPolicyArrayEnableAdmin
 * @tc.desc: Test GetPolicyArray func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetPolicyArrayEnableAdmin, TestSize.Level1)
{
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestEnableAdmin));
    std::vector<std::string> policyArrayData;
    enterpriseDeviceMgrProxyTest->GetPolicyArray(funcCode, policyArrayData);
    EXPECT_TRUE(policyArrayData.size() == 1);
}

/**
 * @tc.name: TestGetPolicyArrayFail
 * @tc.desc: Test GetPolicyArray func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetPolicyArrayFail, TestSize.Level1)
{
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    std::vector<std::string> policyArrayData;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    bool ret = enterpriseDeviceMgrProxyTest->GetPolicyArray(funcCode, policyArrayData);
    EXPECT_TRUE(!ret);
}

/**
 * @tc.name: TestGetPolicyArraySuc
 * @tc.desc: Test GetPolicyArray func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetPolicyArraySuc, TestSize.Level1)
{
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    std::vector<std::string> policyArrayData;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequest));
    bool ret = enterpriseDeviceMgrProxyTest->GetPolicyArray(funcCode, policyArrayData);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TestGetPolicyConfigSuc
 * @tc.desc: Test GetPolicyConfig func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetPolicyConfigSuc, TestSize.Level1)
{
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    std::map<std::string, std::string> policyMapData;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequest));
    bool ret = enterpriseDeviceMgrProxyTest->GetPolicyConfig(funcCode, policyMapData);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TestGetPolicyConfigReplyFail
 * @tc.desc: Test GetPolicyConfig func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetPolicyConfigReplyFail, TestSize.Level1)
{
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    std::map<std::string, std::string> policyMapData;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestReplyFail));
    bool ret = enterpriseDeviceMgrProxyTest->GetPolicyConfig(funcCode, policyMapData);
    EXPECT_TRUE(!ret);
}

/**
 * @tc.name: TestGetPolicyConfigEnableAdminNotEqual
 * @tc.desc: Test GetPolicyConfig func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetPolicyConfigEnableAdminNotEqual, TestSize.Level1)
{
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    std::map<std::string, std::string> policyMapData;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestEnableAdmin));
    bool ret = enterpriseDeviceMgrProxyTest->GetPolicyConfig(funcCode, policyMapData);
    EXPECT_TRUE(!ret);
}

/**
 * @tc.name: TestGetPolicyConfigEnableAdminSizeEqual
 * @tc.desc: Test GetPolicyConfig func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetPolicyConfigEnableAdminSizeEqual, TestSize.Level1)
{
    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    std::map<std::string, std::string> policyMapData;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestMapEnableAdminTwoSuc));
    bool ret = enterpriseDeviceMgrProxyTest->GetPolicyConfig(funcCode, policyMapData);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TestIsSuperAdminReturnFail
 * @tc.desc: Test IsSuperAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestIsSuperAdminReturnFail, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    bool ret = enterpriseDeviceMgrProxyTest->IsSuperAdmin("com.edm.test.demo");
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestGetEnabledSuperAdminReturnFail
 * @tc.desc: Test GetEnabledSuperAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetEnabledSuperAdminReturnFail, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    std::string enabledAdmin;
    enterpriseDeviceMgrProxyTest->GetEnabledSuperAdmin(enabledAdmin);
    EXPECT_TRUE(enabledAdmin.size() == 0);
}

/**
 * @tc.name: TestGetEnabledSuperAdminReturnReplyFail
 * @tc.desc: Test GetEnabledSuperAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetEnabledSuperAdminReturnReplyFail, TestSize.Level1)
{
    std::string enabledAdmin;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestReplyFail));
    enterpriseDeviceMgrProxyTest->GetEnabledSuperAdmin(enabledAdmin);
    EXPECT_TRUE(enabledAdmin.size() == 0);
}

/**
 * @tc.name: TestGetEnabledSuperAdminReturnEnableAdmin
 * @tc.desc: Test GetEnabledSuperAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestGetEnabledSuperAdminReturnEnableAdmin, TestSize.Level1)
{
    std::string enabledAdmin;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestEnableAdmin));
    enterpriseDeviceMgrProxyTest->GetEnabledSuperAdmin(enabledAdmin);
    GTEST_LOG_(INFO) << "mock enabledAdmin enabledAdmin item :" << enabledAdmin;
    EXPECT_TRUE(enabledAdmin.size() > 0);
}

/**
 * @tc.name: TestDisableSuperAdminReturnSuc
 * @tc.desc: Test DisableSuperAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestDisableSuperAdminReturnSuc, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequest));
    ErrCode errVal = enterpriseDeviceMgrProxyTest->DisableSuperAdmin("com.edm.test.demo");
    EXPECT_TRUE(errVal == ERR_OK);
}

/**
 * @tc.name: TestDisableSuperAdminReturnFail
 * @tc.desc: Test DisableSuperAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestDisableSuperAdminReturnFail, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    ErrCode errVal = enterpriseDeviceMgrProxyTest->DisableSuperAdmin("com.edm.test.demo");
    EXPECT_TRUE(errVal != ERR_OK);
}

/**
 * @tc.name: TestHandleManagedEventReturnFail
 * @tc.desc: Test HandleManagedEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestHandleManagedEventReturnFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    const std::vector<uint32_t> events;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));
    ErrCode errVal = enterpriseDeviceMgrProxyTest->HandleManagedEvent(admin, events, false);
    EXPECT_TRUE(errVal != ERR_OK);
}

/**
 * @tc.name: TestHandleManagedEventSuc
 * @tc.desc: Test HandleManagedEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestHandleManagedEventSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    const std::vector<uint32_t> events;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequest));
    ErrCode errVal = enterpriseDeviceMgrProxyTest->HandleManagedEvent(admin, events, true);
    EXPECT_TRUE(errVal == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
