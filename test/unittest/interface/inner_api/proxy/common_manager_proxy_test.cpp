/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "common_manager_proxy.h"
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_proxy.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "managed_feature.h"
#include "system_ability_definition.h"
#include "utils.h"

using namespace testing::ext;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;

namespace OHOS {
namespace EDM {
namespace TEST {
class CommonManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void CommonManagerProxyTest::SetUp()
{
    EnterpriseDeviceMgrProxy::GetInstance();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void CommonManagerProxyTest::TearDown()
{
    EnterpriseDeviceMgrProxy::DestroyInstance();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

/**
 * @tc.name: TestIsFeatureSupportedSuc
 * @tc.desc: Test IsFeatureSupported returns true when service reports supported.
 * @tc.type: FUNC
 */
HWTEST_F(CommonManagerProxyTest, TestIsFeatureSupportedSuc, TestSize.Level1)
{
    EXPECT_CALL(*object_, IsFeatureSupported(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    bool ret = CommonManagerProxy::GetCommonManagerProxy()->IsFeatureSupported(
        static_cast<int32_t>(ManagedFeature::LOCAL_HOTA_DOMAIN));
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TestIsFeatureSupportedUnsupported
 * @tc.desc: Test IsFeatureSupported returns false when service reports not supported.
 * @tc.type: FUNC
 */
HWTEST_F(CommonManagerProxyTest, TestIsFeatureSupportedUnsupported, TestSize.Level1)
{
    EXPECT_CALL(*object_, IsFeatureSupported(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(false), Return(ERR_OK)));
    bool ret = CommonManagerProxy::GetCommonManagerProxy()->IsFeatureSupported(
        static_cast<int32_t>(ManagedFeature::DEVICE_SECURITY_LEVEL));
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestIsFeatureSupportedFail
 * @tc.desc: Test IsFeatureSupported returns false when service call fails.
 * @tc.type: FUNC
 */
HWTEST_F(CommonManagerProxyTest, TestIsFeatureSupportedFail, TestSize.Level1)
{
    EXPECT_CALL(*object_, IsFeatureSupported(_, _))
        .Times(1)
        .WillOnce(Return(ERR_PROXY_SENDREQUEST_FAIL));
    bool ret = CommonManagerProxy::GetCommonManagerProxy()->IsFeatureSupported(
        static_cast<int32_t>(ManagedFeature::USER_EXTEND_CREDENTIAL));
    EXPECT_FALSE(ret);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
