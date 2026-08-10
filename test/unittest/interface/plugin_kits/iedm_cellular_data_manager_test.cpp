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
#include "iedm_cellular_data_manager.h"
#undef private

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class IEdmCellularDataManagerTest : public testing::Test {
protected:
    void SetUp() override
    {
        IEdmCellularDataManager::iInstance_ = nullptr;
    }

    void TearDown() override
    {
        if (IEdmCellularDataManager::iInstance_ != nullptr) {
            delete IEdmCellularDataManager::iInstance_;
            IEdmCellularDataManager::iInstance_ = nullptr;
        }
    }
};

/**
 * @tc.name: TestGetInstanceFirstCall
 * @tc.desc: Test GetInstance when called for the first time.
 * @tc.type: FUNC
 */
HWTEST_F(IEdmCellularDataManagerTest, TestGetInstanceFirstCall, TestSize.Level1)
{
    ASSERT_EQ(IEdmCellularDataManager::iInstance_, nullptr);
    IEdmCellularDataManager* instance = IEdmCellularDataManager::GetInstance();
    ASSERT_NE(instance, nullptr);
    ASSERT_EQ(IEdmCellularDataManager::iInstance_, instance);
}

/**
 * @tc.name: TestGetInstanceSecondCall
 * @tc.desc: Test GetInstance when called multiple times.
 * @tc.type: FUNC
 */
HWTEST_F(IEdmCellularDataManagerTest, TestGetInstanceSecondCall, TestSize.Level1)
{
    IEdmCellularDataManager* instance1 = IEdmCellularDataManager::GetInstance();
    IEdmCellularDataManager* instance2 = IEdmCellularDataManager::GetInstance();
    ASSERT_EQ(instance1, instance2);
}

/**
 * @tc.name: TestEnableCellularDataDefault
 * @tc.desc: Test EnableCellularData default implementation.
 * @tc.type: FUNC
 */
HWTEST_F(IEdmCellularDataManagerTest, TestEnableCellularDataDefault, TestSize.Level1)
{
    IEdmCellularDataManager* instance = IEdmCellularDataManager::GetInstance();
    ASSERT_NE(instance, nullptr);
    int32_t ret = instance->EnableCellularData(true);
    ASSERT_EQ(ret, 0);
    ret = instance->EnableCellularData(false);
    ASSERT_EQ(ret, 0);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
