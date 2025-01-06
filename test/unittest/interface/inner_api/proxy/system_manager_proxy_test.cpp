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

#include "system_manager_proxy.h"
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "update_policy_utils.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class SystemManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<SystemManagerProxy> systemmanagerProxy = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void SystemManagerProxyTest::SetUp()
{
    systemmanagerProxy = SystemManagerProxy::GetSystemManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void SystemManagerProxyTest::TearDown()
{
    systemmanagerProxy.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void SystemManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
}

/**
 * @tc.name: TestSetNTPServerSuc
 * @tc.desc: Test SetNTPServer func.
 * @tc.type: FUNC
 */
HWTEST_F(SystemManagerProxyTest, TestSetNTPServerSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteString("ntp.aliyun.com");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = systemmanagerProxy->SetNTPServer(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetNTPServerFail
 * @tc.desc: Test SetNTPServer func.
 * @tc.type: FUNC
 */
HWTEST_F(SystemManagerProxyTest, TestSetNTPServerFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteString("ntp.aliyun.com");

    int32_t ret = systemmanagerProxy->SetNTPServer(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetNTPServerSuc
 * @tc.desc: Test GetNTPServer func.
 * @tc.type: FUNC
 */
HWTEST_F(SystemManagerProxyTest, TestGetNTPServerSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetPolicy));

    std::string server = "";
    int32_t ret = systemmanagerProxy->GetNTPServer(data, server);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(server == RETURN_STRING);
}

/**
 * @tc.name: TestGetNTPServerFail
 * @tc.desc: Test GetNTPServer func.
 * @tc.type: FUNC
 */
HWTEST_F(SystemManagerProxyTest, TestGetNTPServerFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    std::string server = "";
    int32_t ret = systemmanagerProxy->GetNTPServer(data, server);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetOTAUpdatePolicySuc
 * @tc.desc: Test SetOTAUpdatePolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(SystemManagerProxyTest, TestSetOTAUpdatePolicySuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    UpdatePolicy updatePolicy;
    UpdatePolicyUtils::WriteUpdatePolicy(data, updatePolicy);

    std::string message;
    int32_t ret = systemmanagerProxy->SetOTAUpdatePolicy(data, message);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetOTAUpdatePolicyParamError
 * @tc.desc: Test SetOTAUpdatePolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(SystemManagerProxyTest, TestSetOTAUpdatePolicyParamError, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestParamError));
    UpdatePolicy updatePolicy;
    UpdatePolicyUtils::WriteUpdatePolicy(data, updatePolicy);

    std::string message;
    int32_t ret = systemmanagerProxy->SetOTAUpdatePolicy(data, message);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
    ASSERT_EQ(message, RETURN_STRING);
}

/**
 * @tc.name: TestGetOTAUpdatePolicyFail
 * @tc.desc: Test GetOTAUpdatePolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(SystemManagerProxyTest, TestGetOTAUpdatePolicyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    UpdatePolicy updatePolicy;
    int32_t ret = systemmanagerProxy->GetOTAUpdatePolicy(data, updatePolicy);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetOTAUpdatePolicySuc
 * @tc.desc: Test GetOTAUpdatePolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(SystemManagerProxyTest, TestGetOTAUpdatePolicySuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetOTAUpdatePolicy));

    UpdatePolicy updatePolicy;
    int32_t ret = systemmanagerProxy->GetOTAUpdatePolicy(data, updatePolicy);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_EQ(updatePolicy.type, UpdatePolicyType::PROHIBIT);
    ASSERT_EQ(updatePolicy.version, UPGRADE_VERSION);
}

/**
 * @tc.name: TestNotifyUpdatePackagesSuc
 * @tc.desc: Test NotifyUpdatePackages func.
 * @tc.type: FUNC
 */
HWTEST_F(SystemManagerProxyTest, TestNotifyUpdatePackagesSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    UpgradePackageInfo packageInfo;
    std::string errMsg;
    int32_t ret = systemmanagerProxy->NotifyUpdatePackages(admin, packageInfo, errMsg);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetUpgradeResultFail
 * @tc.desc: Test GetUpgradeResult func.
 * @tc.type: FUNC
 */
HWTEST_F(SystemManagerProxyTest, TestGetUpgradeResultFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    UpgradeResult upgradeResult;
    int32_t ret = systemmanagerProxy->GetUpgradeResult(admin, UPGRADE_VERSION, upgradeResult);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetUpgradeResultSuc
 * @tc.desc: Test GetUpgradeResult func.
 * @tc.type: FUNC
 */
HWTEST_F(SystemManagerProxyTest, TestGetUpgradeResultSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetUpgradeResult));
    UpgradeResult upgradeResult;
    int32_t ret = systemmanagerProxy->GetUpgradeResult(admin, UPGRADE_VERSION, upgradeResult);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(upgradeResult.status == UpgradeStatus::UPGRADE_FAILURE);
    ASSERT_EQ(upgradeResult.version, UPGRADE_VERSION);
    ASSERT_EQ(upgradeResult.errorCode, UPGRADE_FAILED_CODE);
    ASSERT_EQ(upgradeResult.errorMessage, UPGRADE_FAILED_MESSAGE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
