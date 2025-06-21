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

#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "kiosk_feature.h"
#define private public
#include "kiosk_feature_plugin.h"
#undef private
#include "parameters.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class KioskFeaturePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void KioskFeaturePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void KioskFeaturePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestPluginBasicInfo
 * @tc.desc: Test TestPluginBasicInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(KioskFeaturePluginTest, TestPluginBasicInfo, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = KioskFeaturePlugin::GetPlugin();
    std::uint32_t code = plugin->GetCode();
    EXPECT_TRUE(code == EdmInterfaceCode::SET_KIOSK_FEATURE);
    std::string policyName = plugin->GetPolicyName();
    EXPECT_TRUE(policyName == PolicyName::POLICY_SET_KIOSK_FEATURE);
    std::string permissionName =
        plugin->GetPermission(FuncOperateType::SET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    EXPECT_TRUE(permissionName == EdmPermission::PERMISSION_ENTERPRISE_SET_KIOSK);
}

/**
 * @tc.name: TestOnSetPolicyInputNull
 * @tc.desc: Test TestOnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(KioskFeaturePluginTest, TestOnSetPolicyInputNull, TestSize.Level1)
{
    std::shared_ptr<KioskFeaturePlugin> plugin = std::make_shared<KioskFeaturePlugin>();
    std::vector<int32_t> data;
    std::vector<int32_t> currentData;
    std::vector<int32_t> mergeData;
    ErrCode errCode = plugin->OnSetPolicy(data, currentData, mergeData, EdmConstants::DEFAULT_USER_ID);
    EXPECT_TRUE(errCode == ERR_OK);
    ASSERT_FALSE(OHOS::system::GetBoolParameter(
        EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_NOTIFICATION_CENTER, false));
    ASSERT_FALSE(OHOS::system::GetBoolParameter(EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_CONTROL_CENTER,
        false));
}

/**
 * @tc.name: TestOnSetPolicyAllowNotifyCenter
 * @tc.desc: Test TestOnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(KioskFeaturePluginTest, TestOnSetPolicyAllowNotifyCenter, TestSize.Level1)
{
    std::shared_ptr<KioskFeaturePlugin> plugin = std::make_shared<KioskFeaturePlugin>();
    std::vector<int32_t> data;
    data.push_back(static_cast<int32_t>(KioskFeature::ALLOW_NOTIFICATION_CENTER));
    data.push_back(static_cast<int32_t>(KioskFeature::ALLOW_CONTROL_CENTER));
    std::vector<int32_t> currentData;
    std::vector<int32_t> mergeData;
    ErrCode errCode = plugin->OnSetPolicy(data, currentData, mergeData, EdmConstants::DEFAULT_USER_ID);
    EXPECT_TRUE(errCode == ERR_OK);
    ASSERT_TRUE(OHOS::system::GetBoolParameter(
        EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_NOTIFICATION_CENTER, false));
        ASSERT_TRUE(OHOS::system::GetBoolParameter(
        EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_CONTROL_CENTER, false));
}

/**
 * @tc.name: TestSetDefaultKioskFeaturesTrue
 * @tc.desc: Test SetDefaultKioskFeatures function.
 * @tc.type: FUNC
 */
HWTEST_F(KioskFeaturePluginTest, TestSetDefaultKioskFeaturesTrue, TestSize.Level1)
{
    std::shared_ptr<KioskFeaturePlugin> plugin = std::make_shared<KioskFeaturePlugin>();
    plugin->SetDefaultKioskFeatures(true);
    ASSERT_TRUE(OHOS::system::GetBoolParameter(
        EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_NOTIFICATION_CENTER, false));
    ASSERT_TRUE(OHOS::system::GetBoolParameter(EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_CONTROL_CENTER,
        false));
}

/**
 * @tc.name: TestSetDefaultKioskFeaturesFalse
 * @tc.desc: Test SetDefaultKioskFeatures function.
 * @tc.type: FUNC
 */
HWTEST_F(KioskFeaturePluginTest, TestSetDefaultKioskFeaturesFalse, TestSize.Level1)
{
    std::shared_ptr<KioskFeaturePlugin> plugin = std::make_shared<KioskFeaturePlugin>();
    plugin->SetDefaultKioskFeatures(false);
    ASSERT_FALSE(OHOS::system::GetBoolParameter(
        EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_NOTIFICATION_CENTER, false));
    ASSERT_FALSE(OHOS::system::GetBoolParameter(
        EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_CONTROL_CENTER, false));
}

/**
 * @tc.name: TestSetSpecifiedKioskFeaturesNormal
 * @tc.desc: Test SetSpecifiedKioskFeatures function.
 * @tc.type: FUNC
 */
HWTEST_F(KioskFeaturePluginTest, TestSetSpecifiedKioskFeaturesNormal, TestSize.Level1)
{
    std::shared_ptr<KioskFeaturePlugin> plugin = std::make_shared<KioskFeaturePlugin>();
    ErrCode retOne = plugin->SetSpecifiedKioskFeatures(static_cast<int32_t>(KioskFeature::ALLOW_NOTIFICATION_CENTER));
    EXPECT_TRUE(retOne == ERR_OK);
    ASSERT_TRUE(OHOS::system::GetBoolParameter(
        EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_NOTIFICATION_CENTER, false));
    ErrCode retTwo = plugin->SetSpecifiedKioskFeatures(static_cast<int32_t>(KioskFeature::ALLOW_CONTROL_CENTER));
    EXPECT_TRUE(retTwo == ERR_OK);
    ASSERT_TRUE(OHOS::system::GetBoolParameter(
        EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_CONTROL_CENTER, false));
    ErrCode retInvalidCode = plugin->SetSpecifiedKioskFeatures(100);
    EXPECT_TRUE(retInvalidCode == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnAdminRemove
 * @tc.desc: Test TestOnAdminRemove function.
 * @tc.type: FUNC
 */
HWTEST_F(KioskFeaturePluginTest, TestOnAdminRemove, TestSize.Level1)
{
    std::shared_ptr<KioskFeaturePlugin> plugin = std::make_shared<KioskFeaturePlugin>();
    std::vector<int32_t> data;
    std::vector<int32_t> mergeData;
    ErrCode retOne = plugin->OnAdminRemove("", data, mergeData, EdmConstants::DEFAULT_USER_ID);
    EXPECT_TRUE(retOne == ERR_OK);
    ASSERT_FALSE(OHOS::system::GetBoolParameter(
        EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_NOTIFICATION_CENTER, false));
    ASSERT_FALSE(OHOS::system::GetBoolParameter(
        EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_CONTROL_CENTER, false));
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS