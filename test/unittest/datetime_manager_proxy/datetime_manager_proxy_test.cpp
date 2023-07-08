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

#include "datetime_manager_proxy.h"
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DatetimeManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<DatetimeManagerProxy> dateTimeManagerProxy;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void DatetimeManagerProxyTest::SetUp()
{
    dateTimeManagerProxy = DatetimeManagerProxy::GetDatetimeManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void DatetimeManagerProxyTest::TearDown()
{
    if (dateTimeManagerProxy) {
        dateTimeManagerProxy.reset();
    }
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void DatetimeManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestSetDateTimeSuc
 * @tc.desc: Test SetDateTime success func.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestSetDateTimeSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    int64_t time = 1674365400000;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = dateTimeManagerProxy->SetDateTime(admin, time);
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetDateTimeFail
 * @tc.desc: Test SetDateTime without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestSetDateTimeFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    int64_t time = 1674365400000;
    int32_t ret = dateTimeManagerProxy->SetDateTime(admin, time);
    EXPECT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestDisallowModifyDateTimeSuc
 * @tc.desc: Test DisallowModifyDateTime success func.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestDisallowModifyDateTimeSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = dateTimeManagerProxy->DisallowModifyDateTime(admin, true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowModifyDateTimeFail
 * @tc.desc: Test DisallowModifyDateTime without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestDisallowModifyDateTimeFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    ErrCode ret = dateTimeManagerProxy->DisallowModifyDateTime(admin, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsModifyDateTimeDisallowed
 * @tc.desc: Test IsModifyDateTimeDisallowed success func if have Admin parameter.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestIsModifyDateTimeDisallowed001, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    bool result = true;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetPolicy));
    ErrCode ret = dateTimeManagerProxy->IsModifyDateTimeDisallowed(&admin, result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestIsModifyDateTimeDisallowed
 * @tc.desc: Test IsModifyDateTimeDisallowed func if have Admin parameter without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestIsModifyDateTimeDisallowed002, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    bool result = true;
    ErrCode ret = dateTimeManagerProxy->IsModifyDateTimeDisallowed(&admin, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsModifyDateTimeDisallowed
 * @tc.desc: Test IsModifyDateTimeDisallowed success func if does not have Admin parameter.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestIsModifyDateTimeDisallowed003, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    bool result = false;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    ErrCode ret = dateTimeManagerProxy->IsModifyDateTimeDisallowed(nullptr, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestIsModifyDateTimeDisallowed
 * @tc.desc: Test IsModifyDateTimeDisallowed func if does not have Admin parameter without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestIsModifyDateTimeDisallowed004, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    bool result = false;
    ErrCode ret = dateTimeManagerProxy->IsModifyDateTimeDisallowed(nullptr, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
