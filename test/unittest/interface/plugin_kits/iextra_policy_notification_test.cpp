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

#include <gtest/gtest.h>
#include <string>
#include "iextra_policy_notification.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_ADMIN_NAME = "com.edm.test.demo";
class IExtraPolicyNotificationTest : public testing::Test {};

/**
 * @tc.name: TestNotify
 * @tc.desc: Test Notify func.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestNotify, TestSize.Level1)
{
    ErrCode res;
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    res = iExtraPolicyNotification->Notify(TEST_ADMIN_NAME, 100, true);
    ASSERT_TRUE(res == ERR_OK);
    res = iExtraPolicyNotification->Notify("", 100, true);
    ASSERT_TRUE(res == ERR_OK);
    res = iExtraPolicyNotification->Notify(TEST_ADMIN_NAME, 101, true);
    ASSERT_TRUE(res == ERR_OK);
    res = iExtraPolicyNotification->Notify(TEST_ADMIN_NAME, 100, false);
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestReportKeyEvent
 * @tc.desc: Test ReportKeyEvent func.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestReportKeyEvent, TestSize.Level1)
{
    ErrCode res;
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    std::string keyEventStr = "{\"actionTime\": 344510, \"keyCode\": 1, \"keyAction\": 2,"
        "\"keyItems\": [{\"pressed\": 1, \"keyCode\": 1, \"downTime\": 344510}]}";
    res = iExtraPolicyNotification->ReportKeyEvent(TEST_ADMIN_NAME, 100, keyEventStr);
    ASSERT_TRUE(res == ERR_OK);
    res = iExtraPolicyNotification->ReportKeyEvent("", 100, keyEventStr);
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestReportKeyEvent_EmptyKeyEvent
 * @tc.desc: Test ReportKeyEvent func with empty key event.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestReportKeyEvent_EmptyKeyEvent, TestSize.Level1)
{
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    ErrCode res = iExtraPolicyNotification->ReportKeyEvent(TEST_ADMIN_NAME, 100, "");
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestNotifyPolicyChanged
 * @tc.desc: Test NotifyPolicyChanged func.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestNotifyPolicyChanged, TestSize.Level1)
{
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    std::string interfaceName = "setPasswordPolicy";
    std::string parameters = "{}";
    bool res = iExtraPolicyNotification->NotifyPolicyChanged(interfaceName, parameters);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: TestNotifyPolicyChanged_EmptyInterfaceName
 * @tc.desc: Test NotifyPolicyChanged func with empty interface name.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestNotifyPolicyChanged_EmptyInterfaceName, TestSize.Level1)
{
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    std::string interfaceName = "";
    std::string parameters = "{}";
    bool res = iExtraPolicyNotification->NotifyPolicyChanged(interfaceName, parameters);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: TestNotifyPolicyChanged_EmptyParameters
 * @tc.desc: Test NotifyPolicyChanged func with empty parameters.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestNotifyPolicyChanged_EmptyParameters, TestSize.Level1)
{
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    std::string interfaceName = "setPasswordPolicy";
    std::string parameters = "";
    bool res = iExtraPolicyNotification->NotifyPolicyChanged(interfaceName, parameters);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: TestNotifyPolicyChanged_JsonParameters
 * @tc.desc: Test NotifyPolicyChanged func with JSON parameters.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestNotifyPolicyChanged_JsonParameters, TestSize.Level1)
{
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    std::string interfaceName = "setPasswordPolicy";
    std::string jsonParams = "{\"key\":\"value\",\"number\":123}";
    bool res = iExtraPolicyNotification->NotifyPolicyChanged(interfaceName, jsonParams);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: TestNotifyPolicyChanged_ComplexJsonParameters
 * @tc.desc: Test NotifyPolicyChanged func with complex JSON parameters.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestNotifyPolicyChanged_ComplexJsonParameters, TestSize.Level1)
{
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    std::string interfaceName = "setPasswordPolicy";
    std::string complexJsonParams = "{\"nested\":{\"key\":\"value\"},\"array\":[1,2,3]}";
    bool res = iExtraPolicyNotification->NotifyPolicyChanged(interfaceName, complexJsonParams);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: TestNotifyPolicyChanged_DifferentInterfaceName
 * @tc.desc: Test NotifyPolicyChanged func with different interface names.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestNotifyPolicyChanged_DifferentInterfaceName, TestSize.Level1)
{
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    std::vector<std::string> interfaceNames = {
        "setDomainAccountPolicy",
        "setAllowedKioskApps",
        "setPolicySync",
        "setValue",
        "setHomeWallpaper",
        "setUnlockWallpaper",
        "addFirewallRule",
        "removeFirewallRule",
        "addDomainFilterRule",
        "removeDomainFilterRule",
        "setGlobalProxySync",
        "setGlobalProxyForAccount",
        "addApn",
        "deleteApn",
        "updateApn",
        "setPreferredApn",
        "setEthernetConfig",
        "setPasswordPolicy",
        "uninstallEnterpriseReSignatureCertificate",
        "setNTPServer",
        "setWifiProfileSync",
        "setManagedBrowserPolicy"
    };
    std::string parameters = "{}";
    for (const auto &interfaceName : interfaceNames) {
        bool res = iExtraPolicyNotification->NotifyPolicyChanged(interfaceName, parameters);
        ASSERT_TRUE(res);
    }
}

/**
 * @tc.name: TestNotifyPolicyChanged_LongInterfaceName
 * @tc.desc: Test NotifyPolicyChanged func with long interface name.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestNotifyPolicyChanged_LongInterfaceName, TestSize.Level1)
{
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    std::string longInterfaceName = "this_is_a_very_long_interface_name_for_testing_purpose";
    std::string parameters = "{}";
    bool res = iExtraPolicyNotification->NotifyPolicyChanged(longInterfaceName, parameters);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: TestNotifyPolicyChanged_LongParameters
 * @tc.desc: Test NotifyPolicyChanged func with long parameters.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestNotifyPolicyChanged_LongParameters, TestSize.Level1)
{
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    std::string interfaceName = "setPasswordPolicy";
    std::string longParameters = "{\"key\":\"this_is_a_very_long_parameters_value_for_testing\"}";
    bool res = iExtraPolicyNotification->NotifyPolicyChanged(interfaceName, longParameters);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: TestNotifyControlPanelRestrictedChanged
 * @tc.desc: Test NotifyControlPanelRestrictedChanged default implementation.
 * @tc.type: FUNC
 */
HWTEST_F(IExtraPolicyNotificationTest, TestNotifyControlPanelRestrictedChanged, TestSize.Level1)
{
    auto iExtraPolicyNotification = IExtraPolicyNotification::GetInstance();
    bool res = iExtraPolicyNotification->NotifyControlPanelRestrictedChanged();
    ASSERT_TRUE(res);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS