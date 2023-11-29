/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 * @tc.name: TestSetHdcDisabledSuc
 * @tc.desc: Test setHdcDisabled success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetHdcDisabledSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetHdcDisabled(admin, true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetPrinterDisabledSuc
 * @tc.desc: Test setPrinterDisabled success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetPrinterDisabledSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetPrinterDisabled(admin, true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetHdcDisabledFail
 * @tc.desc: Test setHdcDisabled without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetHdcDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = proxy_->SetHdcDisabled(admin, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetPrinterDisabledFail
 * @tc.desc: Test setPrinterDisabled without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestSetPrinterDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = proxy_->SetPrinterDisabled(admin, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsHdcDisabledSuc
 * @tc.desc: Test IsHdcDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsHdcDisabledSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool result = false;
    int32_t ret = proxy_->IsHdcDisabled(&admin, result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestIsPrinterDisabledSuc
 * @tc.desc: Test IsPrinterDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsPrinterDisabledSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool result = false;
    int32_t ret = proxy_->IsPrinterDisabled(&admin, result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestIsHdcDisabledFail
 * @tc.desc: Test IsHdcDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsHdcDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    bool result = false;
    int32_t ret = proxy_->IsHdcDisabled(&admin, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsPrinterDisabledFail
 * @tc.desc: Test IsPrinterDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsPrinterDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    bool result = false;
    int32_t ret = proxy_->IsPrinterDisabled(&admin, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestDisallowScreenShotSucc
 * @tc.desc: Test DisallowScreenShot success func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestDisallowScreenShotSucc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->DisallowScreenShot(admin, true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowScreenShotFail
 * @tc.desc: Test DisallowScreenShot without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestDisallowScreenShotFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = proxy_->DisallowScreenShot(admin, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsScreenShotDisallowedSuc
 * @tc.desc: Test IsScreenShotDisallowed func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsScreenShotDisallowedSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool result = false;
    int32_t ret = proxy_->IsScreenShotDisallowed(&admin, result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestIsScreenShotDisallowedFail
 * @tc.desc: Test IsScreenShotDisallowed func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsScreenShotDisallowedFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    bool result = false;
    int32_t ret = proxy_->IsScreenShotDisallowed(&admin, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsScreenShotDisallowedNullptr
 * @tc.desc: Test IsScreenShotDisallowed func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsScreenShotDisallowedNullptr, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    bool result = false;
    int32_t ret = proxy_->IsScreenShotDisallowed(nullptr, result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowMicrophoneFail
 * @tc.desc: Test DisallowMicrophone without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestDisallowMicrophoneFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = proxy_->DisallowMicrophone(admin, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsMicrophoneDisallowedSuc
 * @tc.desc: Test IsMicrophoneDisallowed func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsMicrophoneDisallowedSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool result = false;
    int32_t ret = proxy_->IsMicrophoneDisallowed(&admin, result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestIsMicrophoneDisallowedFail
 * @tc.desc: Test IsMicrophoneDisallowed func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsMicrophoneDisallowedFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    bool result = false;
    int32_t ret = proxy_->IsMicrophoneDisallowed(&admin, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsMicrophoneDisallowedNullptr
 * @tc.desc: Test IsMicrophoneDisallowed func.
 * @tc.type: FUNC
 */
HWTEST_F(RestrictionsProxyTest, TestIsMicrophoneDisallowedNullptr, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    bool result = false;
    int32_t ret = proxy_->IsMicrophoneDisallowed(nullptr, result);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
