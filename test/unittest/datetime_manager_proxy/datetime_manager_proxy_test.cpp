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
#include <vector>
#include "datetime_manager_proxy.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class DatetimeManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<DatetimeManagerProxy> dateTimeManagerProxy;
};

void DatetimeManagerProxyTest::SetUp()
{
    dateTimeManagerProxy = DatetimeManagerProxy::GetDatetimeManagerProxy();
    Utils::SetEdmServiceEnable();
}

void DatetimeManagerProxyTest::TearDown()
{
    if (dateTimeManagerProxy) {
        dateTimeManagerProxy.reset();
    }
    Utils::SetEdmServiceDisable();
}

/**
 * @tc.name: TestSetDateTime
 * @tc.desc: Test SetDateTime func.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestSetDateTime, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");
    int64_t time = 1674365400000;
    int32_t ret = dateTimeManagerProxy->SetDateTime(admin, time);
    EXPECT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: TestDisallowModifyDateTime
 * @tc.desc: Test DisallowModifyDateTime func.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestDisallowModifyDateTime, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    ErrCode ret = dateTimeManagerProxy->DisallowModifyDateTime(admin, true);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: TestIsModifyDateTimeDisallowed
 * @tc.desc: Test IsModifyDateTimeDisallowed func if have Admin.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestIsModifyDateTimeDisallowed001, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    bool result = true;
    ErrCode ret = dateTimeManagerProxy->IsModifyDateTimeDisallowed(admin, true, result);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: TestIsModifyDateTimeDisallowed
 * @tc.desc: Test IsModifyDateTimeDisallowed func if does not have Admin.
 * @tc.type: FUNC
 */
HWTEST_F(DatetimeManagerProxyTest, TestIsModifyDateTimeDisallowed002, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    bool result = true;
    ErrCode ret = dateTimeManagerProxy->IsModifyDateTimeDisallowed(admin, false, result);
    ASSERT_TRUE(ret != ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
