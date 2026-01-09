/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include <vector>

#define private public
#include "ability_controller.h"
#undef private
#include "edm_bundle_manager_impl_mock.h"
#include "external_manager_factory_mock.h"
 
using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t INDEX_THREE = 3;
const std::string BUNDLE_NAME = "com.edm.test";
const std::string UI_ABILITY_NAME = "com.edm.test.MainAbility";
const std::string APP_SERVICE_EXTENSION_NAME = "com.edm.test.AppServiceExtension";
const std::string NOT_EXIST_ABILITY_NAME = "com.edm.test.NotExistAbility";
const std::string TEST_PERMISSION = "ohos.permission.test";
class AbilityControllerTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
};

/**
 * @tc.name: StartAbilityByAdminWithDafultController
 * @tc.desc: Test AbilityControllerTest::StartAbilityByAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityControllerTest, StartAbilityByAdminToUIAbility, TestSize.Level1)
{
    AAFwk::Want want;
    uiWant.SetElementName(BUNDLE_NAME, NOT_EXIST_ABILITY_NAME);

    EdmAbilityInfo abilityInfo(BUNDLE_NAME);
    AbilityController controller = std::make_shared<AbilityController>(abilityInfo);
    auto ret = controller->StartAbilityByAdmin(want, TEST_USER_ID);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: StartAbilityByAdminToUIAbility
 * @tc.desc: Test AbilityControllerTest::StartAbilityByAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityControllerTest, StartAbilityByAdminToUIAbility, TestSize.Level1)
{
    AAFwk::Want want;
    uiWant.SetElementName(BUNDLE_NAME, NOT_EXIST_ABILITY_NAME);

    EdmAbilityInfo abilityInfo(BUNDLE_NAME);
    AbilityController controller = std::make_shared<UIAbilityController>(abilityInfo);
    auto ret = controller->StartAbilityByAdmin(want, TEST_USER_ID);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: StartAbilityByAdminToAppService
 * @tc.desc: Test AbilityControllerTest::StartAbilityByAdmin function.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityControllerTest, StartAbilityByAdminToAppService, TestSize.Level1)
{
    AAFwk::Want want;
    uiWant.SetElementName(BUNDLE_NAME, NOT_EXIST_ABILITY_NAME);

    EdmAbilityInfo abilityInfo(BUNDLE_NAME);
    AbilityController controller = std::make_shared<AppServiceExtensionController>(abilityInfo);
    auto ret = controller->StartAbilityByAdmin(want, TEST_USER_ID);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: VerifyPermissionFail
 * @tc.desc: Test AbilityControllerTest::VerifyPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityControllerTest, VerifyPermissionFail, TestSize.Level1)
{
    EdmAbilityInfo abilityInfo(BUNDLE_NAME);
    abilityInfo.permissions = {TEST_PERMISSION};
    AbilityController controller = std::make_shared<UIAbilityController>(abilityInfo);
    bool ret = controller->VerifyPermission(BUNDLE_NAME);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: VerifyPermissionSuccess
 * @tc.desc: Test AbilityControllerTest::VerifyPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityControllerTest, VerifyPermissionSuccess, TestSize.Level1)
{
    EdmAbilityInfo abilityInfo(BUNDLE_NAME);
    AbilityController controller = std::make_shared<UIAbilityController>(abilityInfo);
    bool ret = controller->VerifyPermission(BUNDLE_NAME);
    ASSERT_FALSE(ret);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS