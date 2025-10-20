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
#include <memory>

#include "iptables_factory.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::EDM::IPTABLES;

namespace OHOS {
namespace EDM {
namespace IPTABLES {
namespace TEST {

class IptablesFactoryTest : public testing::Test {};

/**
 * @tc.name: TestGetInstance
 * @tc.desc: Test GetInstance func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesFactoryTest, TestGetInstance, TestSize.Level1)
{
    EXPECT_TRUE(IptablesFactory::GetInstance() != nullptr);
}

/**
 * @tc.name: TestCreateIptablesManagerForFamily
 * @tc.desc: Test CreateIptablesManagerForFamily func.
 * @tc.type: FUNC
 */
HWTEST_F(IptablesFactoryTest, TestCreateIptablesManagerForFamily, TestSize.Level1)
{
    std::shared_ptr<IptablesFactory> iptablesFactory = IptablesFactory::GetInstance();
    std::shared_ptr<IptablesManager> ipv4tablesManager = iptablesFactory->CreateIptablesManagerForFamily(Family::IPV4);
    EXPECT_TRUE(ipv4tablesManager != nullptr);

    std::shared_ptr<IptablesManager> ipv6tablesManager = iptablesFactory->CreateIptablesManagerForFamily(Family::IPV4);
    EXPECT_TRUE(ipv6tablesManager != nullptr);
}
} // namespace TEST
} // namespace IPTABLES
} // namespace EDM
} // namespace OHOS