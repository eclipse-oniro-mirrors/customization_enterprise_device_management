/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <vector>

#include "device_info_proxy.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "edm_sys_manager_mock.h"
#include "policy_info.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
const std::string EDM_MANAGE_DATETIME_PERMISSION = "ohos.permission.ENTERPRISE_SET_DATETIME";
class DeviceInfoProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<DeviceInfoProxy> deviceInfoProxy = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void DeviceInfoProxyTest::SetUp()
{
    deviceInfoProxy = DeviceInfoProxy::GetDeviceInfoProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void DeviceInfoProxyTest::TearDown()
{
    deviceInfoProxy.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

/**
 * @tc.name: TestGetDeviceInfoSuc
 * @tc.desc: Test GetDeviceInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceInfoProxyTest, TestGetDeviceInfoSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetPolicy));
    std::string info;
    int32_t ret = deviceInfoProxy->GetDeviceInfo(admin, info, GET_DEVICE_SERIAL);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetDeviceInfoFail
 * @tc.desc: Test GetDeviceInfo func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceInfoProxyTest, TestGetDeviceInfoFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string info;
    int32_t ret = deviceInfoProxy->GetDeviceInfo(admin, info, GET_DEVICE_SERIAL);
    ASSERT_TRUE(ret != ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
