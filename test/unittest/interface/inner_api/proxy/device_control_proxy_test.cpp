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

#include "device_control_proxy.h"
#include "edm_constants.h"
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "utils.h"
#include "os_account_manager.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class DeviceControlProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<DeviceControlProxy> deviceControlProxy = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void DeviceControlProxyTest::SetUp()
{
    deviceControlProxy = DeviceControlProxy::GetDeviceControlProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void DeviceControlProxyTest::TearDown()
{
    deviceControlProxy.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void DeviceControlProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestResetFactorySuc
 * @tc.desc: Test ResetFactory success func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlProxyTest, TestResetFactorySuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = deviceControlProxy->ResetFactory(admin);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestResetFactoryFail
 * @tc.desc: Test ResetFactory without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlProxyTest, TestResetFactoryFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = deviceControlProxy->ResetFactory(admin);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestTestLockScreenSuc
 * @tc.desc: Test LockScreen success func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlProxyTest, TestLockScreenSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t userId = 0;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    int32_t ret = deviceControlProxy->LockScreen(admin, userId);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestLockScreenFail
 * @tc.desc: Test LockScreen without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlProxyTest, TestLockScreenFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t userId = 0;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    int32_t ret = deviceControlProxy->LockScreen(admin, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestShutdownSuc
 * @tc.desc: Test Shutdown success func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlProxyTest, TestShutdownSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = deviceControlProxy->Shutdown(admin);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestShutdownFail
 * @tc.desc: Test Shutdown without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlProxyTest, TestShutdownFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = deviceControlProxy->Shutdown(admin);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRebootSuc
 * @tc.desc: Test Reboot success func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlProxyTest, TestRebootSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = deviceControlProxy->Reboot(admin);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRebootFail
 * @tc.desc: Test Reboot without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlProxyTest, TestRebootFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = deviceControlProxy->Reboot(admin);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestOperateDeviceFail
 * @tc.desc: Test OperateDevice without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlProxyTest, TestOperateDeviceFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    OperateDeviceParam param{EdmConstants::DeviceControl::RESET_FACTORY, "", 0};
    int32_t ret = deviceControlProxy->OperateDevice(admin, param);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestOperateDeviceSuc
 * @tc.desc: Test OperateDevice success func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlProxyTest, TestOperateDeviceSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    OperateDeviceParam param{EdmConstants::DeviceControl::RESET_FACTORY, "", 0};
    int32_t ret = deviceControlProxy->OperateDevice(admin, param);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
