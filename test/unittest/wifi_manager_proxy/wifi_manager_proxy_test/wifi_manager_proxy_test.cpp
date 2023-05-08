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
#include <vector>

#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "utils.h"
#include "wifi_manager_proxy.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class WifiManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<WifiManagerProxy> wifiManagerProxy = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void WifiManagerProxyTest::SetUp()
{
    wifiManagerProxy = WifiManagerProxy::GetWifiManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void WifiManagerProxyTest::TearDown()
{
    wifiManagerProxy.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

/**
 * @tc.name: TestIsWifiActiveSuc
 * @tc.desc: Test IsWifiActive func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestIsWifiActiveSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool isActive = false;
    int32_t ret = wifiManagerProxy->IsWifiActive(admin, isActive);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(isActive);
}

/**
 * @tc.name: TestIsWifiActiveFail
 * @tc.desc: Test IsWifiActive func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestIsWifiActiveFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    bool isActive = false;
    int32_t ret = wifiManagerProxy->IsWifiActive(admin, isActive);
    ASSERT_TRUE(ret != ERR_OK);
    ASSERT_FALSE(isActive);
}

/**
 * @tc.name: TestSetWifiProfileFail
 * @tc.desc: Test SetWifiProfile func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestSetWifiProfileFail, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    Wifi::WifiDeviceConfig config;
    config.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6 = { 0x01 };
    int32_t ret = wifiManagerProxy->SetWifiProfile(admin, config);
    ASSERT_TRUE(ret == ERR_INVALID_VALUE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
