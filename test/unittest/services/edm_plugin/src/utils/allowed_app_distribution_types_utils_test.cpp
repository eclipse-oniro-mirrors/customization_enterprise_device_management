/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "allowed_app_distribution_types_utils.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class AllowedAppDistributionTypesUtilsTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};
void AllowedAppDistributionTypesUtilsTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AllowedAppDistributionTypesUtilsTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
* @tc.name: TestSetAppDistributionTypes001
* @tc.desc: Test AllowedAppDistributionTypesUtils::SetAppDistributionTypes
* @tc.type: FUNC
*/
HWTEST_F(AllowedAppDistributionTypesUtilsTest, TestSetAppDistributionTypes001, TestSize.Level1)
{
    AllowedAppDistributionTypesUtils allowedAppDistributionTypesUtils;
    std::vector<int32_t> policyData;
    policyData.push_back(1);
    policyData.push_back(2);
    ErrCode ret = allowedAppDistributionTypesUtils.SetAppDistributionTypes(policyData);
    ASSERT_TRUE(ret == ERR_OK);
}
}
}
}