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
#include "device_settings_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class DeviceSettingsManagerTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<DeviceSettingsManager> deviceSettingsManager;
};

void DeviceSettingsManagerTest::SetUp()
{
    deviceSettingsManager = DeviceSettingsManager::GetDeviceSettingsManager();
}
void DeviceSettingsManagerTest::TearDown()
{
    if (deviceSettingsManager) {
        deviceSettingsManager.reset();
    }
}

/**
 * @tc.name: TestSetDateTime
 * @tc.desc: Test SetDateTime func.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceSettingsManagerTest, TestSetDateTime, TestSize.Level1)
{
    bool ret;
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    int64_t time = 1674365400000;
    ret = deviceSettingsManager->SetDateTime(admin, time);
    EXPECT_TRUE(ret);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
