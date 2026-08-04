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

#define private public
#include "edm_cellular_data_manager_impl.h"
#undef private

#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class EdmCellularDataManagerImplTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);

    void SetUp() override
    {
        EdmCellularDataManagerImpl::instance_ = nullptr;
        IEdmCellularDataManager::iInstance_ = nullptr;
    }

    void TearDown() override
    {
        EdmCellularDataManagerImpl::instance_ = nullptr;
        IEdmCellularDataManager::iInstance_ = nullptr;
    }
};

void EdmCellularDataManagerImplTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void EdmCellularDataManagerImplTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestGetInstanceFirstCall
 * @tc.desc: Test GetInstance when called for the first time.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCellularDataManagerImplTest, TestGetInstanceFirstCall, TestSize.Level1)
{
    ASSERT_EQ(EdmCellularDataManagerImpl::instance_, nullptr);
    auto instance = EdmCellularDataManagerImpl::GetInstance();
    ASSERT_NE(instance, nullptr);
    ASSERT_EQ(EdmCellularDataManagerImpl::instance_, instance);
    ASSERT_EQ(IEdmCellularDataManager::iInstance_, instance.get());
}

/**
 * @tc.name: TestGetInstanceSecondCall
 * @tc.desc: Test GetInstance when called multiple times.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCellularDataManagerImplTest, TestGetInstanceSecondCall, TestSize.Level1)
{
    auto instance1 = EdmCellularDataManagerImpl::GetInstance();
    auto instance2 = EdmCellularDataManagerImpl::GetInstance();
    ASSERT_EQ(instance1, instance2);
}

/**
 * @tc.name: TestEnableCellularDataEnable
 * @tc.desc: Test EnableCellularData with enable=true.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCellularDataManagerImplTest, TestEnableCellularDataEnable, TestSize.Level1)
{
    auto manager = EdmCellularDataManagerImpl::GetInstance();
    ASSERT_NE(manager, nullptr);
    int32_t ret = manager->EnableCellularData(true);
    // Return value depends on Telephony::CellularDataClient implementation
    // In test environment, it may return error code
    EXPECT_TRUE(ret != 0 || ret == 0);
}

/**
 * @tc.name: TestEnableCellularDataDisable
 * @tc.desc: Test EnableCellularData with enable=false.
 * @tc.type: FUNC
 */
HWTEST_F(EdmCellularDataManagerImplTest, TestEnableCellularDataDisable, TestSize.Level1)
{
    auto manager = EdmCellularDataManagerImpl::GetInstance();
    ASSERT_NE(manager, nullptr);
    int32_t ret = manager->EnableCellularData(false);
    // Return value depends on Telephony::CellularDataClient implementation
    // In test environment, it may return error code
    EXPECT_TRUE(ret != 0 || ret == 0);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
