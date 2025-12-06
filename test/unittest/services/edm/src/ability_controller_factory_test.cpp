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
#include "ability_controller_factory.h"
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
class AbilityControllerFactoryTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<EdmBundleManagerImplMock> bundleMgrMock_ = nullptr;
    std::shared_ptr<ExternalManagerFactoryMock> factoryMock_ = nullptr;
};

void AbilityControllerFactoryTest::SetUp()
{
    factoryMock_ = std::make_shared<ExternalManagerFactoryMock>();
    AbilityControllerFactory::factory_ = factoryMock_;
    bundleMgrMock_ = std::make_shared<EdmBundleManagerImplMock>();
    EXPECT_CALL(*factoryMock_, CreateBundleManager).WillRepeatedly(DoAll(Return(bundleMgrMock_)));
}

void AbilityControllerFactoryTest::TearDown()
{
    bundleMgrMock_.reset();
    factoryMock_.reset();
}

/**
 * @tc.name: CreateAbilityControllerWithEmptyWant
 * @tc.desc: Test AbilityControllerFactoryTest::CreateAbilityControllerTest function.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityControllerFactoryTest, CreateAbilityControllerWithEmptyWant, TestSize.Level1)
{
    AAFwk::Want emptyWant;
    emptyWant.SetElementName("", "");
    
    auto controller = AbilityControllerFactory::CreateAbilityController(emptyWant, TEST_USER_ID);
    
    ASSERT_TRUE(controller == nullptr);
}

/**
 * @tc.name: CreateAbilityControllerWithNotExistAbility
 * @tc.desc: Test AbilityControllerFactoryTest::CreateAbilityControllerTest function.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityControllerFactoryTest, CreateAbilityControllerWithNotExistAbility, TestSize.Level1)
{
    AAFwk::Want notExistWant;
    notExistWant.SetElementName(BUNDLE_NAME, NOT_EXIST_ABILITY_NAME);
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    
    EXPECT_CALL(*bundleMgrMock_, QueryAbilityInfo)
        .Times(testing::AtLeast(1))
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_THREE>(abilityInfo), Return(false)));
    EXPECT_CALL(*bundleMgrMock_, QueryExtensionAbilityInfos(_, _, _, _))
        .Times(testing::AtLeast(1))
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_THREE>(extensionInfos), Return(false)));
    auto controller = AbilityControllerFactory::CreateAbilityController(notExistWant, TEST_USER_ID);
    
    ASSERT_TRUE(controller == nullptr);
}

/**
 * @tc.name: CreateAbilityControllerReturnUIController
 * @tc.desc: Test AbilityControllerFactoryTest::CreateAbilityControllerTest function.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityControllerFactoryTest, CreateAbilityControllerReturnUIController, TestSize.Level1)
{
    AAFwk::Want uiWant;
    uiWant.SetElementName(BUNDLE_NAME, UI_ABILITY_NAME);
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::PAGE;
    
    EXPECT_CALL(*bundleMgrMock_, QueryAbilityInfo)
        .Times(testing::AtLeast(1))
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_THREE>(abilityInfo), Return(true)));
    auto controller = AbilityControllerFactory::CreateAbilityController(uiWant, TEST_USER_ID);
    
    ASSERT_TRUE(controller != nullptr);
}


#ifdef FEATURE_PC_ONLY
/**
 * @tc.name: CreateAbilityControllerReturnAppServiceController
 * @tc.desc: Test AbilityControllerFactoryTest::CreateAbilityControllerTest function.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityControllerFactoryTest, CreateAbilityControllerReturnAppServiceController, TestSize.Level1)
{
    AAFwk::Want appServiceWant;
    appServiceWant.SetElementName(BUNDLE_NAME, APP_SERVICE_EXTENSION_NAME);
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::UNKNOWN;
    AppExecFwk::ExtensionAbilityInfo extension;
    extension.type = AppExecFwk::ExtensionAbilityType::APP_SERVICE;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos = {extension};
    
    EXPECT_CALL(*bundleMgrMock_, QueryAbilityInfo)
        .Times(testing::AtLeast(1))
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_THREE>(abilityInfo), Return(false)));
    EXPECT_CALL(*bundleMgrMock_, QueryExtensionAbilityInfos(_, _, _, _))
        .Times(testing::AtLeast(1))
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_THREE>(extensionInfos), Return(true)));
    auto controller = AbilityControllerFactory::CreateAbilityController(appServiceWant, TEST_USER_ID);
    
    ASSERT_TRUE(controller != nullptr);
}
#endif

/**
 * @tc.name: CreateAbilityControllerReturnDefaultController
 * @tc.desc: Test AbilityControllerFactoryTest::CreateAbilityControllerTest function.
 * @tc.type: FUNC
 */
HWTEST_F(AbilityControllerFactoryTest, CreateAbilityControllerReturnDefaultController, TestSize.Level1)
{
    AAFwk::Want appServiceWant;
    appServiceWant.SetElementName(BUNDLE_NAME, APP_SERVICE_EXTENSION_NAME);
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.type = AppExecFwk::AbilityType::UNKNOWN;
    AppExecFwk::ExtensionAbilityInfo extension;
    extension.type = AppExecFwk::ExtensionAbilityType::FORM;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos = {extension};
    
    EXPECT_CALL(*bundleMgrMock_, QueryAbilityInfo)
        .Times(testing::AtLeast(1))
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_THREE>(abilityInfo), Return(false)));
    EXPECT_CALL(*bundleMgrMock_, QueryExtensionAbilityInfos(_, _, _, _))
        .Times(testing::AtLeast(1))
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_THREE>(extensionInfos), Return(true)));
    auto controller = AbilityControllerFactory::CreateAbilityController(appServiceWant, TEST_USER_ID);
    
    ASSERT_TRUE(controller != nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS