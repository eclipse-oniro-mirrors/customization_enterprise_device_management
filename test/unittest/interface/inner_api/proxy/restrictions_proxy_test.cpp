/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <system_ability_definition.h>

#include "restrictions_proxy.h"
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
const std::string FEATURE_SNAPSHOT_SKIP = "snapshotSkip";
class RestrictionsProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<RestrictionsProxy> proxy_ = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void RestrictionsProxyTest::SetUp()
{
    proxy_ = RestrictionsProxy::GetRestrictionsProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void RestrictionsProxyTest::TearDown()
{
    proxy_.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void RestrictionsProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestSetDisallowedPolicySuc
 * @tc.desc: Test SetDisallowedPolicy success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetDisallowedPolicySuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetDisallowedPolicy(admin, true, EdmInterfaceCode::DISABLED_HDC);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetDisallowedPolicySuc_01
 * @tc.desc: Test SetDisallowedPolicy success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetDisallowedPolicySuc_01, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetDisallowedPolicy(data,  EdmInterfaceCode::DISABLED_HDC);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetDisallowedPolicyFail
 * @tc.desc: Test SetDisallowedPolicy without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetDisallowedPolicyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = proxy_->SetDisallowedPolicy(admin, true, EdmInterfaceCode::DISABLED_HDC);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetDisallowedPolicyFail_01
 * @tc.desc: Test SetDisallowedPolicy without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetDisallowedPolicyFail_01, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    data.WriteParcelable(&admin);
    int32_t ret = proxy_->SetDisallowedPolicy(data, EdmInterfaceCode::DISABLED_HDC);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedPolicySuc
 * @tc.desc: Test GetDisallowedPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedPolicySuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool result = false;
    int32_t ret = proxy_->GetDisallowedPolicy(&admin, EdmInterfaceCode::DISABLED_HDC, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestGetDisallowedPolicySuc_01
 * @tc.desc: Test GetDisallowedPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedPolicySuc_01, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool result = false;
    int32_t ret = proxy_->GetDisallowedPolicy(data, EdmInterfaceCode::DISABLED_HDC, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestGetDisallowedPolicyFail
 * @tc.desc: Test GetDisallowedPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedPolicyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    bool result = false;
    int32_t ret = proxy_->GetDisallowedPolicy(&admin, EdmInterfaceCode::DISABLED_HDC, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedPolicyFail_01
 * @tc.desc: Test GetDisallowedPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedPolicyFail_01, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    MessageParcel data;
    data.WriteParcelable(&admin);
    bool result = false;
    int32_t ret = proxy_->GetDisallowedPolicy(data, EdmInterfaceCode::DISABLED_HDC, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedPolicyNullptr
 * @tc.desc: Test GetDisallowedPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedPolicyNullptr, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    bool result = false;
    int32_t ret = proxy_->GetDisallowedPolicy(nullptr, EdmInterfaceCode::DISABLED_HDC, result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetFingerprintAuthDisabledSuc
 * @tc.desc: Test SetFingerprintAuthDisabled success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetFingerprintAuthDisabledSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetFingerprintAuthDisabled(admin, false);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetFingerprintAuthDisabledFail
 * @tc.desc: Test SetFingerprintAuthDisabled without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetFingerprintAuthDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = proxy_->SetFingerprintAuthDisabled(admin, false);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsFingerprintAuthDisabledSuc
 * @tc.desc: Test IsFingerprintAuthDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsFingerprintAuthDisabledSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool result = false;
    int32_t ret = proxy_->IsFingerprintAuthDisabled(&admin, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestIsFingerprintAuthDisabledFail
 * @tc.desc: Test IsFingerprintAuthDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsFingerprintAuthDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    bool result = false;
    int32_t ret = proxy_->IsFingerprintAuthDisabled(&admin, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsFingerprintAuthDisabledNullptr
 * @tc.desc: Test IsFingerprintAuthDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsFingerprintAuthDisabledNullptr, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool result = false;
    int32_t ret = proxy_->IsFingerprintAuthDisabled(nullptr, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestSetFingerprintAuthDisallowedPolicyForAccountSuc
 * @tc.desc: Test SetFingerprintAuthDisallowedPolicyForAccount success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetFingerprintAuthDisallowedPolicyForAccountSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetFingerprintAuthDisallowedPolicyForAccount(admin,
        EdmInterfaceCode::FINGERPRINT_AUTH, false, WITHOUT_PERMISSION_TAG, 100);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetFingerprintAuthDisallowedPolicyForAccountFail
 * @tc.desc: Test SetFingerprintAuthDisallowedPolicyForAccount without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetFingerprintAuthDisallowedPolicyForAccountFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = proxy_->SetFingerprintAuthDisallowedPolicyForAccount(admin,
        EdmInterfaceCode::FINGERPRINT_AUTH, false, WITHOUT_PERMISSION_TAG, 100);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetDisallowedPolicyForAccountSuc
 * @tc.desc: Test SetDisallowedPolicyForAccount success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetDisallowedPolicyForAccountSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetDisallowedPolicyForAccount(admin,
        EdmInterfaceCode::DISABLE_USER_MTP_CLIENT, false, WITHOUT_PERMISSION_TAG, 100);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetDisallowedPolicyForAccountFail
 * @tc.desc: Test SetDisallowedPolicyForAccount without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetDisallowedPolicyForAccountFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = proxy_->SetDisallowedPolicyForAccount(admin,
        EdmInterfaceCode::DISABLE_USER_MTP_CLIENT, false, WITHOUT_PERMISSION_TAG, 100);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetFingerprintAuthDisallowedPolicyForAccountSuc
 * @tc.desc: Test GetFingerprintAuthDisallowedPolicyForAccount func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetFingerprintAuthDisallowedPolicyForAccountSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool result = true;
    int32_t ret = proxy_->GetFingerprintAuthDisallowedPolicyForAccount(admin,
        EdmInterfaceCode::FINGERPRINT_AUTH, result, WITHOUT_PERMISSION_TAG, 100);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestGetFingerprintAuthDisallowedPolicyForAccountFail
 * @tc.desc: Test GetFingerprintAuthDisallowedPolicyForAccount func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetFingerprintAuthDisallowedPolicyForAccountFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    bool result = false;
    int32_t ret = proxy_->GetFingerprintAuthDisallowedPolicyForAccount(admin,
        EdmInterfaceCode::FINGERPRINT_AUTH, result, WITHOUT_PERMISSION_TAG, 100);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedPolicyForAccountSuc
 * @tc.desc: Test GetDisallowedPolicyForAccount func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedPolicyForAccountSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool result = true;
    int32_t ret = proxy_->GetDisallowedPolicyForAccount(admin,
        EdmInterfaceCode::DISABLE_USER_MTP_CLIENT, result, WITHOUT_PERMISSION_TAG, 100);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestGetDisallowedPolicyForAccountFail
 * @tc.desc: Test GetDisallowedPolicyForAccount func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedPolicyForAccountFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    bool result = false;
    int32_t ret = proxy_->GetDisallowedPolicyForAccount(admin,
        EdmInterfaceCode::DISABLE_USER_MTP_CLIENT, result, WITHOUT_PERMISSION_TAG, 100);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddDisallowedListForAccountSuc
 * @tc.desc: Test AddDisallowedListForAccount success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestAddDisallowedListForAccountSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    std::vector<std::string> bundles;
    bundles.emplace_back("aaaa");
    bundles.emplace_back("bbbb");
    int32_t ret = proxy_->AddOrRemoveDisallowedListForAccount(admin, FEATURE_SNAPSHOT_SKIP, bundles, 100, true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveDisallowedListForAccountSucc
 * @tc.desc: Test RemoveDisallowedListForAccount success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestRemoveDisallowedListForAccountSucc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    std::vector<std::string> bundles;
    bundles.emplace_back("aaaa");
    bundles.emplace_back("bbbb");
    int32_t ret = proxy_->AddOrRemoveDisallowedListForAccount(admin, FEATURE_SNAPSHOT_SKIP, bundles, 100, false);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddDisallowedListForAccountFail
 * @tc.desc: Test AddDisallowedListForAccount without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestAddDisallowedListForAccountFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> bundles;
    bundles.emplace_back("aaaa");
    bundles.emplace_back("bbbb");
    int32_t ret = proxy_->AddOrRemoveDisallowedListForAccount(admin, FEATURE_SNAPSHOT_SKIP, bundles, 100, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveDisallowedListForAccountFail
 * @tc.desc: Test RemoveDisallowedListForAccount without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestRemoveDisallowedListForAccountFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> bundles;
    bundles.emplace_back("aaaa");
    bundles.emplace_back("bbbb");
    int32_t ret = proxy_->AddOrRemoveDisallowedListForAccount(admin, FEATURE_SNAPSHOT_SKIP, bundles, 100, false);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedListForAccountSuc
 * @tc.desc: Test GetDisallowedListForAccount func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedListForAccountSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));
    std::vector<std::string> bundles;
    int32_t ret = proxy_->GetDisallowedListForAccount(admin, FEATURE_SNAPSHOT_SKIP, 100, bundles);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(bundles.size() == 1);
    ASSERT_TRUE(bundles[0] == RETURN_STRING);
}

/**
 * @tc.name: TestGetDisallowedListForAccountFail
 * @tc.desc: Test GetDisallowedListForAccount func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestGetDisallowedListForAccountFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> bundles;
    int32_t ret = proxy_->GetDisallowedListForAccount(admin, FEATURE_SNAPSHOT_SKIP, 100, bundles);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetUserRestrictionSuc
 * @tc.desc: Test SetUserRestriction success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetUserRestrictionSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetUserRestriction(admin, true, EdmInterfaceCode::DISALLOW_MODIFY_APN);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetUserRestrictionSuc_01
 * @tc.desc: Test SetUserRestriction success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetUserRestrictionSuc_01, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetUserRestriction(admin, false, EdmInterfaceCode::DISALLOW_MODIFY_APN);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetUserRestrictionFail
 * @tc.desc: Test SetUserRestriction without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetUserRestrictionFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = proxy_->SetUserRestriction(admin, true, EdmInterfaceCode::DISALLOW_MODIFY_APN);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
