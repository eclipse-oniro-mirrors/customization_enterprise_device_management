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

#include "telephony_manager_proxy.h"

#include <gtest/gtest.h>
#include <system_ability_definition.h>

#include <string>
#include <vector>

#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class TelephonyManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<TelephonyManagerProxy> telephonyManagerProxy = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void TelephonyManagerProxyTest::SetUp()
{
    telephonyManagerProxy = TelephonyManagerProxy::GetTelephonyManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void TelephonyManagerProxyTest::TearDown()
{
    telephonyManagerProxy.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void TelephonyManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestSetSimDisabledSuc
 * @tc.desc: Test SetSimDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestSetSimDisabledSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = telephonyManagerProxy->SetSimDisabled(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetSimDisabledFail
 * @tc.desc: Test SetSimDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestSetSimDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    int32_t ret = telephonyManagerProxy->SetSimDisabled(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetSimEnabledSuc
 * @tc.desc: Test SetSimEnabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestSetSimEnabledSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = telephonyManagerProxy->SetSimEnabled(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetSimEnabledFail
 * @tc.desc: Test SetSimEnabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestSetSimEnabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    int32_t ret = telephonyManagerProxy->SetSimEnabled(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsSimDisabledSuc
 * @tc.desc: Test IsSimDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestIsSimDisabledSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    bool result = false;
    int32_t ret = telephonyManagerProxy->IsSimDisabled(data, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestIsSimDisabledFail
 * @tc.desc: Test IsSimDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestIsSimDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    bool result = false;
    int32_t ret = telephonyManagerProxy->IsSimDisabled(data, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestAddCallPolicyNumbersSuc
 * @tc.desc: Test AddCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestAddCallPolicyNumbersSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string callType = "incoming";
    int32_t policyFlag = 0;
    std::vector<std::string> numbers;
    numbers.push_back("1111111");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = telephonyManagerProxy->AddCallPolicyNumbers(admin, callType, policyFlag, numbers);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddCallPolicyNumbersFail
 * @tc.desc: Test AddCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestAddCallPolicyNumbersFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string callType = "incoming";
    int32_t policyFlag = 0;
    std::vector<std::string> numbers;
    numbers.push_back("1111111");
    int32_t ret = telephonyManagerProxy->AddCallPolicyNumbers(admin, callType, policyFlag, numbers);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveCallPolicyNumbersSuc
 * @tc.desc: Test RemoveCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestRemoveCallPolicyNumbersSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string callType = "incoming";
    int32_t policyFlag = 0;
    std::vector<std::string> numbers;
    numbers.push_back("1111111");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = telephonyManagerProxy->RemoveCallPolicyNumbers(admin, callType, policyFlag, numbers);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveCallPolicyNumbersFail
 * @tc.desc: Test RemoveCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestRemoveCallPolicyNumbersFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string callType = "incoming";
    int32_t policyFlag = 0;
    std::vector<std::string> numbers;
    numbers.push_back("1111111");
    int32_t ret = telephonyManagerProxy->RemoveCallPolicyNumbers(admin, callType, policyFlag, numbers);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetCallPolicyNumbersSuc
 * @tc.desc: Test GetCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetCallPolicyNumbersSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string callType = "incoming";
    int32_t policyFlag = 0;
    std::vector<std::string> numbers;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = telephonyManagerProxy->GetCallPolicyNumbers(admin, callType, policyFlag, numbers);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetCallPolicyNumbersFail
 * @tc.desc: Test GetCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetCallPolicyNumbersFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string callType = "incoming";
    int32_t policyFlag = 0;
    std::vector<std::string> numbers;
    int32_t ret = telephonyManagerProxy->GetCallPolicyNumbers(admin, callType, policyFlag, numbers);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
