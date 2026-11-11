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

#include "bms_utils.h"

#include <gtest/gtest.h>
#include "utils.h"

#include "edm_constants.h"
#include "edm_errors.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class BmsUtilsTest : public testing::Test {};

/**
 * @tc.name: TestDealAppRunningRulesEmptyList
 * @tc.desc: Test BmsUtils::DealAppRunningRules with no app id still reaches the bundle manager.
 * @tc.type: FUNC
 */
HWTEST_F(BmsUtilsTest, TestDealAppRunningRulesEmptyList, TestSize.Level1)
{
    std::vector<std::string> data;
    ErrCode ret = BmsUtils::DealAppRunningRules(data, DEFAULT_USER_ID, true, true);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);

    ret = BmsUtils::DealAppRunningRules(data, DEFAULT_USER_ID, false, false);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestDealAppRunningRulesWithAppIds
 * @tc.desc: Test BmsUtils::DealAppRunningRules accepts a list and reports the service outcome.
 * @tc.type: FUNC
 */
HWTEST_F(BmsUtilsTest, TestDealAppRunningRulesWithAppIds, TestSize.Level1)
{
    std::vector<std::string> data = { "com.test.a#entry" };
    ErrCode ret = BmsUtils::DealAppRunningRules(data, DEFAULT_USER_ID, true, true);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);

    ret = BmsUtils::DealAppRunningRules(data, DEFAULT_USER_ID, true, false);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
