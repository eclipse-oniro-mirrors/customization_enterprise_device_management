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

#define private public
#define protected public
#include "plugin_manager.h"
#undef protected
#undef private

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include "edm_ipc_interface_code.h"
#include "func_code_utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {

class PluginManagerConcurrencyTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ParallelSetDifferentPolicies
 * @tc.desc: Two threads SET different non-conflicting policies; both should proceed in parallel.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ParallelSetDifferentPolicies, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    uint32_t code1 = EdmInterfaceCode::DISABLE_CAMERA;
    uint32_t code2 = EdmInterfaceCode::SCREEN_OFF_TIME;
    auto lock1 = pm->GetPolicyLock(code1);
    auto lock2 = pm->GetPolicyLock(code2);
    ASSERT_NE(lock1, nullptr);
    ASSERT_NE(lock2, nullptr);
    ASSERT_NE(lock1.get(), lock2.get());

    std::atomic<int> runningCount(0);
    std::atomic<bool> bothConcurrent(false);

    auto setFunc = [&](std::shared_ptr<std::shared_mutex> lock) {
        std::unique_lock<std::shared_mutex> guard(*lock);
        runningCount++;
        if (runningCount.load() == 2) {
            bothConcurrent.store(true);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        runningCount--;
    };

    std::thread t1(setFunc, lock1);
    std::thread t2(setFunc, lock2);
    t1.join();
    t2.join();
    EXPECT_TRUE(bothConcurrent.load());
}

/**
 * @tc.name: ParallelSetSamePolicy
 * @tc.desc: Two threads SET the same policy; second must wait for first.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ParallelSetSamePolicy, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    uint32_t code = EdmInterfaceCode::DISABLE_CAMERA;
    auto lock = pm->GetPolicyLock(code);
    ASSERT_NE(lock, nullptr);

    std::atomic<bool> firstStarted(false);
    std::atomic<bool> secondStartedTooEarly(false);

    auto setFunc = [&](bool isFirst) {
        std::unique_lock<std::shared_mutex> guard(*lock);
        if (isFirst) {
            firstStarted.store(true);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        } else {
            if (!firstStarted.load()) {
                secondStartedTooEarly.store(true);
            }
        }
    };

    std::thread t1(setFunc, true);
    std::thread t2(setFunc, false);
    t1.join();
    t2.join();
    EXPECT_FALSE(secondStartedTooEarly.load());
}

/**
 * @tc.name: ParallelGetSamePolicy
 * @tc.desc: Multiple threads GET the same policy; all should proceed in parallel.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ParallelGetSamePolicy, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    uint32_t code = EdmInterfaceCode::DISABLE_CAMERA;
    auto lock = pm->GetPolicyLock(code);
    ASSERT_NE(lock, nullptr);

    std::atomic<int> runningCount(0);
    std::atomic<bool> allConcurrent(false);

    auto getFunc = [&]() {
        std::shared_lock<std::shared_mutex> guard(*lock);
        runningCount++;
        if (runningCount.load() == 3) {
            allConcurrent.store(true);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        runningCount--;
    };

    std::thread t1(getFunc);
    std::thread t2(getFunc);
    std::thread t3(getFunc);
    t1.join();
    t2.join();
    t3.join();
    EXPECT_TRUE(allConcurrent.load());
}

/**
 * @tc.name: SetBlocksGetSamePolicy
 * @tc.desc: SET blocks GET for the same policy.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, SetBlocksGetSamePolicy, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    uint32_t code = EdmInterfaceCode::DISABLE_CAMERA;
    auto lock = pm->GetPolicyLock(code);
    ASSERT_NE(lock, nullptr);

    std::atomic<bool> setStarted(false);
    std::atomic<bool> getStartedDuringSet(false);

    auto setFunc = [&]() {
        std::unique_lock<std::shared_mutex> guard(*lock);
        setStarted.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        setStarted.store(false);
    };

    auto getFunc = [&]() {
        std::shared_lock<std::shared_mutex> guard(*lock);
        if (setStarted.load()) {
            getStartedDuringSet.store(true);
        }
    };

    std::thread setThread(setFunc);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    std::thread getThread(getFunc);
    setThread.join();
    getThread.join();
    EXPECT_FALSE(getStartedDuringSet.load());
}

/**
 * @tc.name: SetDoesNotBlockGetDifferentPolicy
 * @tc.desc: SET on policy X does NOT block GET on policy Y.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, SetDoesNotBlockGetDifferentPolicy, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    uint32_t code1 = EdmInterfaceCode::DISABLE_CAMERA;
    uint32_t code2 = EdmInterfaceCode::SCREEN_OFF_TIME;
    auto lock1 = pm->GetPolicyLock(code1);
    auto lock2 = pm->GetPolicyLock(code2);
    ASSERT_NE(lock1.get(), lock2.get());

    std::atomic<bool> setStarted(false);
    std::atomic<bool> getSucceededDuringSet(false);

    auto setFunc = [&]() {
        std::unique_lock<std::shared_mutex> guard(*lock1);
        setStarted.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    };

    auto getFunc = [&]() {
        std::shared_lock<std::shared_mutex> guard(*lock2);
        if (setStarted.load()) {
            getSucceededDuringSet.store(true);
        }
    };

    std::thread setThread(setFunc);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    std::thread getThread(getFunc);
    setThread.join();
    getThread.join();
    EXPECT_TRUE(getSucceededDuringSet.load());
}

/**
 * @tc.name: ConflictGroupSetSerialized
 * @tc.desc: SETs of conflicting policies (same conflict group) are serialized.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ConflictGroupSetSerialized, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    pm->InitConflictGroupMap();
    uint32_t code1 = EdmInterfaceCode::DISABLE_USB;
    uint32_t code2 = EdmInterfaceCode::ALLOWED_USB_DEVICES;
    auto conflictLock1 = pm->GetConflictSetLock(code1);
    auto conflictLock2 = pm->GetConflictSetLock(code2);
    ASSERT_NE(conflictLock1, nullptr);
    ASSERT_NE(conflictLock2, nullptr);
    ASSERT_EQ(conflictLock1.get(), conflictLock2.get());

    std::atomic<bool> firstStarted(false);
    std::atomic<bool> secondStartedTooEarly(false);

    auto setFunc = [&](bool isFirst) {
        std::unique_lock<std::shared_mutex> guard(*conflictLock1);
        if (isFirst) {
            firstStarted.store(true);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        } else {
            if (!firstStarted.load()) {
                secondStartedTooEarly.store(true);
            }
        }
    };

    std::thread t1(setFunc, true);
    std::thread t2(setFunc, false);
    t1.join();
    t2.join();
    EXPECT_FALSE(secondStartedTooEarly.load());
}

/**
 * @tc.name: ConflictGroupGetParallel
 * @tc.desc: GET of a conflict-group policy does NOT use the conflict SET lock.
 *          SET on policy X does not block GET on policy Y (same conflict group).
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ConflictGroupGetParallel, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    pm->InitConflictGroupMap();
    uint32_t code1 = EdmInterfaceCode::DISABLE_USB;
    uint32_t code2 = EdmInterfaceCode::ALLOWED_USB_DEVICES;
    auto conflictLock = pm->GetConflictSetLock(code1);
    auto policyLock2 = pm->GetPolicyLock(code2);
    ASSERT_NE(conflictLock, nullptr);
    ASSERT_NE(policyLock2, nullptr);
    ASSERT_NE(conflictLock.get(), policyLock2.get());

    std::atomic<bool> setStarted(false);
    std::atomic<bool> getSucceededDuringSet(false);

    auto setFunc = [&]() {
        std::unique_lock<std::shared_mutex> guard(*conflictLock);
        setStarted.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    };

    auto getFunc = [&]() {
        std::shared_lock<std::shared_mutex> guard(*policyLock2);
        if (setStarted.load()) {
            getSucceededDuringSet.store(true);
        }
    };

    std::thread setThread(setFunc);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    std::thread getThread(getFunc);
    setThread.join();
    getThread.join();
    EXPECT_TRUE(getSucceededDuringSet.load());
}

/**
 * @tc.name: ConflictGroupMapInitialized
 * @tc.desc: Verify conflict group map is correctly initialized.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerConcurrencyTest, ConflictGroupMapInitialized, TestSize.Level1)
{
    auto pm = PluginManager::GetInstance();
    ASSERT_NE(pm, nullptr);
    pm->InitConflictGroupMap();
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISABLE_USB], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::ALLOWED_USB_DEVICES], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_USB_DEVICES], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::USB_READ_ONLY], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOW_USB_SERIAL], 1u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISABLE_BLUETOOTH], 2u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES], 2u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES], 2u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISABLE_WIFI], 3u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::ALLOWED_WIFI_LIST], 3u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_WIFI_LIST], 3u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISABLE_MTP_CLIENT], 4u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISABLE_USER_MTP_CLIENT], 4u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION], 5u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL], 5u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_SUDO], 6u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_DEVICE_SUDO], 6u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOWED_NOTIFICATION], 7u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::ALLOWED_NOTIFICATION_BUNDLES], 7u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::ALLOW_RUNNING_BUNDLES], 8u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES], 8u);
    EXPECT_EQ(pm->conflictGroupMap_[EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS], 8u);
    EXPECT_EQ(pm->conflictGroupMap_.count(EdmInterfaceCode::DISABLE_CAMERA), 0u);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
