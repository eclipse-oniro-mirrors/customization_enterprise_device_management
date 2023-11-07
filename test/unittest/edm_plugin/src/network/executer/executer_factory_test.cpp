/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "executer_factory.h"
#include "rule_utils.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::EDM::IPTABLES;

namespace OHOS {
namespace EDM {
namespace IPTABLES {
namespace TEST {

class ExecuterFactoryTest : public testing::Test {};

/**
 * @tc.name: TestGetAllExecuter
 * @tc.desc: Test GetAllExecuter func.
 * @tc.type: FUNC
 */
HWTEST_F(ExecuterFactoryTest, TestGetAllExecuter, TestSize.Level1)
{
    EXPECT_TRUE(!ExecuterFactory::GetInstance()->GetAllExecuter().empty());
}

/**
 * @tc.name: TestGetExecuter
 * @tc.desc: Test GetExecuter func.
 * @tc.type: FUNC
 */
HWTEST_F(ExecuterFactoryTest, TestGetExecuter, TestSize.Level1)
{
    EXPECT_TRUE(ExecuterFactory::GetInstance()->GetExecuter(EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME) != nullptr);
    EXPECT_TRUE(ExecuterFactory::GetInstance()->GetExecuter("EDM_DEFAULT_DENY_OUTPUT_CHAIN_NAME") == nullptr);
}

/**
 * @tc.name: TestGetInstance
 * @tc.desc: Test GetInstance func.
 * @tc.type: FUNC
 */
HWTEST_F(ExecuterFactoryTest, TestGetInstance, TestSize.Level1)
{
    EXPECT_TRUE(ExecuterFactory::GetInstance() != nullptr);
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS