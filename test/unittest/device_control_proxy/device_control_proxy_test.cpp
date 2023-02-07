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

#include "device_control_proxy.h"
#include "policy_info.h"

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

    std::shared_ptr<DeviceControlProxy> deviceControlProxy = nullptr;
};

void DeviceControlProxyTest::SetUp()
{
    deviceControlProxy = DeviceControlProxy::GetDeviceControlProxy();
}

void DeviceControlProxyTest::TearDown()
{
    deviceControlProxy.reset();
}

/**
 * @tc.name: TestResetFactoryFail
 * @tc.desc: Test ResetFactory func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlProxyTest, TestGetDeviceInfoFail, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    int32_t ret = deviceControlProxy->ResetFactory(admin);
    ASSERT_TRUE(ret != ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
