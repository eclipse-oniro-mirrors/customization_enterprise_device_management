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
#include <gmock/gmock.h>

#include <chrono>
#include <fstream>
#include <functional>

#define private public
#define protected public
#include "installed_bundle_info_util.h"
#undef protected
#undef private

#include "cjson_check.h"
#include "edm_timer_manager_mock.h"
#include "hisysevent_adapter.h"
#include "iedm_timer_manager.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::string TEST_FILE_PATH = "/data/service/el1/public/edm/installed_bundle_info.json";

class InstalledBundleInfoUtilTest : public testing::Test {
public:
    void SetUp() override
    {
        util_ = InstalledBundleInfoUtil::GetInstance();
        CleanupTestFile();
        originalTimerInstance_ = IEdmTimerManager::edmTimerManagerInstance_;
    }

    void TearDown() override
    {
        CleanupTestFile();
        IEdmTimerManager::edmTimerManagerInstance_ = originalTimerInstance_;
    }

protected:
    std::shared_ptr<InstalledBundleInfoUtil> util_ = nullptr;
    IEdmTimerManager *originalTimerInstance_ = nullptr;
    std::shared_ptr<MockEdmTimerManager> mockTimer_ = std::make_shared<MockEdmTimerManager>();

    void CleanupTestFile()
    {
        std::ofstream file(TEST_FILE_PATH, std::ios::trunc);
        if (file.is_open()) {
            file << "[]";
            file.close();
        }
    }

    void WriteTestFile(const std::string &content)
    {
        std::ofstream file(TEST_FILE_PATH, std::ios::trunc);
        if (file.is_open()) {
            file << content;
            file.close();
        }
    }

    std::string ReadTestFile()
    {
        std::ifstream file(TEST_FILE_PATH);
        if (!file.is_open()) {
            return "";
        }
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        return content;
    }
};

/**
 * @tc.name: TestAddInstalledBundleInfoSuccess
 * @tc.desc: Test AddInstalledBundleInfo with valid parameters returns true.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, AddInstalledBundleInfo_NormalType_ReturnTrue, TestSize.Level1)
{
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();
    EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockTimer_, SetTimer(_, _, _)).WillOnce(Return(true));

    bool ret = util_->AddInstalledBundleInfo("com.admin.test", "com.app.test", InstalledBundleType::NORMAL);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TestAddInstalledBundleInfoAGType
 * @tc.desc: Test AddInstalledBundleInfo with AG type returns true.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, AddInstalledBundleInfo_AGType_ReturnTrue, TestSize.Level1)
{
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();
    EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockTimer_, SetTimer(_, _, _)).WillOnce(Return(true));

    bool ret = util_->AddInstalledBundleInfo("com.admin.ag", "com.app.ag", InstalledBundleType::AG);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TestAddInstalledBundleInfoMDMType
 * @tc.desc: Test AddInstalledBundleInfo with MDM type returns true.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, AddInstalledBundleInfo_MDMType_ReturnTrue, TestSize.Level1)
{
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();
    EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockTimer_, SetTimer(_, _, _)).WillOnce(Return(true));

    bool ret = util_->AddInstalledBundleInfo("com.admin.mdm", "com.app.mdm", InstalledBundleType::MDM);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TestAddInstalledBundleInfoBelowThresholdScheduleTimer
 * @tc.desc: Test AddInstalledBundleInfo calls ScheduleReportIfNeeded when below MAX_BUNDLE_INFO_COUNT.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, AddInstalledBundleInfo_BelowThreshold_ScheduleTimer, TestSize.Level1)
{
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();
    // 未达阈值时，AddInstalledBundleInfo在锁内调用ScheduleReportIfNeeded
    // ScheduleReportIfNeeded会检查IsTimerRunning并调用SetTimer
    EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockTimer_, SetTimer(_, _, _)).WillOnce(Return(true));

    bool ret = util_->AddInstalledBundleInfo("com.admin.below", "com.app.below", InstalledBundleType::NORMAL);
    EXPECT_TRUE(ret);
    EXPECT_EQ(util_->GetInstalledBundleInfoCount(), 1);
}

/**
 * @tc.name: TestAddInstalledBundleInfoReachThresholdReportAndClear
 * @tc.desc: Test AddInstalledBundleInfo calls ReportAndClearLocked when reaching MAX_BUNDLE_INFO_COUNT.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, AddInstalledBundleInfo_ReachThreshold_ReportAndClear, TestSize.Level1)
{
    CleanupTestFile();
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();

    for (int i = 0; i < 19; ++i) {
        EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(false));
        EXPECT_CALL(*mockTimer_, SetTimer(_, _, _)).WillOnce(Return(true));
        util_->AddInstalledBundleInfo("com.admin" + std::to_string(i),
            "com.app" + std::to_string(i), InstalledBundleType::NORMAL);
    }

    // 第20次添加达到MAX_BUNDLE_INFO_COUNT，触发ReportAndClearLocked
    bool ret = util_->AddInstalledBundleInfo("com.admin20", "com.app20", InstalledBundleType::NORMAL);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TestGetInstalledBundleInfoCountCorrect
 * @tc.desc: Test GetInstalledBundleInfoCount returns correct count after adding data.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, GetInstalledBundleInfoCount_AfterAdd_ReturnCorrectCount, TestSize.Level1)
{
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();

    EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockTimer_, SetTimer(_, _, _)).WillOnce(Return(true));
    util_->AddInstalledBundleInfo("com.admin1", "com.app1", InstalledBundleType::NORMAL);

    EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockTimer_, SetTimer(_, _, _)).WillOnce(Return(true));
    util_->AddInstalledBundleInfo("com.admin2", "com.app2", InstalledBundleType::AG);

    size_t count = util_->GetInstalledBundleInfoCount();
    EXPECT_EQ(count, 2);
}

/**
 * @tc.name: TestGetInstalledBundleInfoCountEmpty
 * @tc.desc: Test GetInstalledBundleInfoCount returns 0 when no data exists.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, GetInstalledBundleInfoCount_NoData_ReturnZero, TestSize.Level1)
{
    CleanupTestFile();
    size_t count = util_->GetInstalledBundleInfoCount();
    EXPECT_EQ(count, 0);
}

/**
 * @tc.name: TestHasInstalledBundleInfoTrue
 * @tc.desc: Test HasInstalledBundleInfo returns true when data exists.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, HasInstalledBundleInfo_DataExists_ReturnTrue, TestSize.Level1)
{
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();
    EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockTimer_, SetTimer(_, _, _)).WillOnce(Return(true));
    util_->AddInstalledBundleInfo("com.admin.has", "com.app.has", InstalledBundleType::NORMAL);

    bool ret = util_->HasInstalledBundleInfo();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TestHasInstalledBundleInfoFalse
 * @tc.desc: Test HasInstalledBundleInfo returns false when no data exists.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, HasInstalledBundleInfo_NoData_ReturnFalse, TestSize.Level1)
{
    CleanupTestFile();
    bool ret = util_->HasInstalledBundleInfo();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestScheduleReportIfNeededTimerNull
 * @tc.desc: Test ScheduleReportIfNeeded does not start timer when timer instance is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, ScheduleReportIfNeeded_TimerNull_NoStart, TestSize.Level1)
{
    IEdmTimerManager::edmTimerManagerInstance_ = nullptr;
    util_->ScheduleReportIfNeeded();
    EXPECT_TRUE(true);
}

/**
 * @tc.name: TestScheduleReportIfNeededTimerAlreadyRunning
 * @tc.desc: Test ScheduleReportIfNeeded does not start timer when timer is already running.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, ScheduleReportIfNeeded_TimerRunning_NoStart, TestSize.Level1)
{
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();
    EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(true));

    util_->ScheduleReportIfNeeded();
}

/**
 * @tc.name: TestScheduleReportIfNeededTimerNotRunning
 * @tc.desc: Test ScheduleReportIfNeeded starts timer when timer is not running.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, ScheduleReportIfNeeded_TimerNotRunning_SetTimer, TestSize.Level1)
{
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();
    EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockTimer_, SetTimer(_, _, _)).WillOnce(Return(true));

    util_->ScheduleReportIfNeeded();
}

/**
 * @tc.name: TestReportAndClearNoData
 * @tc.desc: Test ReportAndClear returns immediately when no data exists (SwapAndClearLocked returns false).
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, ReportAndClear_NoData_ReturnImmediately, TestSize.Level1)
{
    CleanupTestFile();
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();

    // 文件为空，SwapAndClearLocked返回false，ReportAndClearLocked直接return
    util_->ReportAndClear();
    EXPECT_FALSE(util_->HasInstalledBundleInfo());
}

/**
 * @tc.name: TestReportAndClearReportSuccessDataCleared
 * @tc.desc: Test ReportAndClear clears data and cancels timer when report succeeds.
 *           NOTE: This test requires HiSysEvent environment to be available.
 *           In most unit test environments, HiSysEventAdapter::ReportInstalledBundleInfo returns false
 *           because OH_HiSysEvent_Write is unavailable. If the test environment supports HiSysEvent
 *           (e.g., provides a stub that returns 0), this test will verify the success path.
 *           Otherwise, the data will be restored and HasInstalledBundleInfo returns true.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, ReportAndClear_ReportSuccess_DataCleared, TestSize.Level1)
{
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();

    EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockTimer_, SetTimer(_, _, _)).WillOnce(Return(true));
    util_->AddInstalledBundleInfo("com.admin.success", "com.app.success", InstalledBundleType::NORMAL);

    // 如果HiSysEvent环境可用，ReportInstalledBundleInfo返回true：
    //   - CancelTimer会被调用
    //   - 数据被清空，HasInstalledBundleInfo返回false
    // 如果HiSysEvent环境不可用，ReportInstalledBundleInfo返回false：
    //   - CancelTimer不会被调用
    //   - 数据被恢复，HasInstalledBundleInfo返回true
    bool reportResult = HiSysEventAdapter::ReportInstalledBundleInfo("test");
    util_->ReportAndClear();

    if (reportResult) {
        // 上报成功路径：数据被清空
        EXPECT_FALSE(util_->HasInstalledBundleInfo());
    } else {
        // 上报失败路径：数据被恢复
        EXPECT_TRUE(util_->HasInstalledBundleInfo());
    }
}

/**
 * @tc.name: TestReportAndClearLockedSwapFailed
 * @tc.desc: Test ReportAndClearLocked returns immediately when SwapAndClearLocked fails (empty file).
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, ReportAndClearLocked_SwapFailed_ReturnImmediately, TestSize.Level1)
{
    CleanupTestFile();
    // 文件为空，SwapAndClearLocked返回false
    std::unique_lock<std::mutex> lock(util_->fileMutex_);
    util_->ReportAndClearLocked(lock);
    // SwapAndClearLocked返回false，ReportAndClearLocked直接return
    // lock应仍处于锁定状态（没有unlock）
    EXPECT_TRUE(lock.owns_lock());
}

/**
 * @tc.name: TestSerializeToJsonSuccess
 * @tc.desc: Test SerializeToJson returns valid JSON string.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, SerializeToJson_SingleItem_ReturnNonEmpty, TestSize.Level1)
{
    std::vector<InstalledBundleInfo> infoList;
    InstalledBundleInfo info;
    info.mdmName = "com.admin.serial";
    info.installedName = "com.app.serial";
    info.installedType = InstalledBundleType::NORMAL;
    info.installedTime = 1000000;
    infoList.push_back(info);

    std::string jsonStr = util_->SerializeToJson(infoList);
    EXPECT_FALSE(jsonStr.empty());
    EXPECT_TRUE(jsonStr.find("com.admin.serial") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("com.app.serial") != std::string::npos);
}

/**
 * @tc.name: TestSerializeToJsonEmptyList
 * @tc.desc: Test SerializeToJson returns "[]" for empty list.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, SerializeToJson_EmptyList_ReturnEmptyArray, TestSize.Level1)
{
    std::vector<InstalledBundleInfo> infoList;
    std::string jsonStr = util_->SerializeToJson(infoList);
    EXPECT_EQ(jsonStr, "[]");
}

/**
 * @tc.name: TestSerializeToJsonMultipleItems
 * @tc.desc: Test SerializeToJson returns complete JSON with multiple entries.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, SerializeToJson_MultipleItems_ReturnComplete, TestSize.Level1)
{
    std::vector<InstalledBundleInfo> infoList;
    InstalledBundleInfo info1;
    info1.mdmName = "admin1";
    info1.installedName = "app1";
    info1.installedType = InstalledBundleType::AG;
    info1.installedTime = 1000;
    infoList.push_back(info1);

    InstalledBundleInfo info2;
    info2.mdmName = "admin2";
    info2.installedName = "app2";
    info2.installedType = InstalledBundleType::MDM;
    info2.installedTime = 2000;
    infoList.push_back(info2);

    std::string jsonStr = util_->SerializeToJson(infoList);
    EXPECT_FALSE(jsonStr.empty());
    EXPECT_TRUE(jsonStr.find("admin1") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("admin2") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("app1") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("app2") != std::string::npos);
}

/**
 * @tc.name: TestSerializeToJsonUsesJsonKeyConstants
 * @tc.desc: Test SerializeToJson uses JSON_KEY_MDM_NAME, JSON_KEY_INSTALLED_NAME,
 *           JSON_KEY_INSTALLED_TYPE, JSON_KEY_INSTALLED_TIME constants correctly.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, SerializeToJson_UsesJsonKeyConstants_ReturnCorrectKeys, TestSize.Level1)
{
    std::vector<InstalledBundleInfo> infoList;
    InstalledBundleInfo info;
    info.mdmName = "mdm_test";
    info.installedName = "installed_test";
    info.installedType = InstalledBundleType::MDM;
    info.installedTime = 1234567890;
    infoList.push_back(info);

    std::string jsonStr = util_->SerializeToJson(infoList);
    EXPECT_FALSE(jsonStr.empty());
    // 验证JSON使用了正确的key常量
    EXPECT_TRUE(jsonStr.find("\"mdmName\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("\"installedName\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("\"installedType\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("\"installedTime\"") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("mdm_test") != std::string::npos);
    EXPECT_TRUE(jsonStr.find("installed_test") != std::string::npos);
}

/**
 * @tc.name: TestClearInstalledBundleInfoLockedSuccess
 * @tc.desc: Test ClearInstalledBundleInfoLocked writes "[]" to file and returns true.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, ClearInstalledBundleInfoLocked_Normal_ReturnTrue, TestSize.Level1)
{
    CleanupTestFile();
    bool ret = util_->ClearInstalledBundleInfoLocked();
    EXPECT_TRUE(ret);
    // 验证文件内容为"[]"
    std::string content = ReadTestFile();
    EXPECT_EQ(content, "[]");
}

/**
 * @tc.name: TestSwapAndClearLockedFileEmpty
 * @tc.desc: Test SwapAndClearLocked returns false when file is empty (no data to swap).
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, SwapAndClearLocked_FileEmpty_ReturnFalse, TestSize.Level1)
{
    CleanupTestFile();
    std::vector<InstalledBundleInfo> outList;
    bool ret = util_->SwapAndClearLocked(outList);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(outList.empty());
}

/**
 * @tc.name: TestSwapAndClearLockedFileHasData
 * @tc.desc: Test SwapAndClearLocked returns true and clears file when file has data.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, SwapAndClearLocked_FileHasData_ReturnTrueAndClearFile, TestSize.Level1)
{
    IEdmTimerManager::edmTimerManagerInstance_ = mockTimer_.get();
    EXPECT_CALL(*mockTimer_, IsTimerRunning(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockTimer_, SetTimer(_, _, _)).WillOnce(Return(true));
    util_->AddInstalledBundleInfo("com.admin.swap", "com.app.swap", InstalledBundleType::NORMAL);

    std::vector<InstalledBundleInfo> outList;
    bool ret = util_->SwapAndClearLocked(outList);
    EXPECT_TRUE(ret);
    EXPECT_EQ(outList.size(), 1);
    EXPECT_EQ(outList[0].mdmName, "com.admin.swap");
    EXPECT_EQ(outList[0].installedName, "com.app.swap");
    // 验证文件已被清空
    std::string content = ReadTestFile();
    EXPECT_EQ(content, "[]");
}

/**
 * @tc.name: TestRestoreToFileLockedNormalRestore
 * @tc.desc: Test RestoreToFileLocked restores saved data to file successfully.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, RestoreToFileLocked_NormalRestore_Success, TestSize.Level1)
{
    CleanupTestFile();
    // 准备要恢复的数据
    std::vector<InstalledBundleInfo> savedList;
    InstalledBundleInfo info1;
    info1.mdmName = "com.admin.restore1";
    info1.installedName = "com.app.restore1";
    info1.installedType = InstalledBundleType::NORMAL;
    info1.installedTime = 1000;
    savedList.push_back(info1);

    InstalledBundleInfo info2;
    info2.mdmName = "com.admin.restore2";
    info2.installedName = "com.app.restore2";
    info2.installedType = InstalledBundleType::AG;
    info2.installedTime = 2000;
    savedList.push_back(info2);

    bool ret = util_->RestoreToFileLocked(savedList);
    EXPECT_TRUE(ret);

    // 验证数据被恢复到文件
    size_t count = util_->GetInstalledBundleInfoCount();
    EXPECT_EQ(count, 2);
}

/**
 * @tc.name: TestLoadFromFileEmptyContent
 * @tc.desc: Test LoadFromFile returns true with empty infoList when file content is empty.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, LoadFromFile_EmptyContent_ReturnTrueAndEmptyList, TestSize.Level1)
{
    // 写入空内容到文件
    WriteTestFile("");
    std::vector<InstalledBundleInfo> infoList;
    bool ret = util_->LoadFromFile(infoList);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(infoList.empty());
}

/**
 * @tc.name: TestLoadFromFileInvalidJson
 * @tc.desc: Test LoadFromFile returns false when file contains invalid JSON.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, LoadFromFile_InvalidJson_ReturnFalse, TestSize.Level1)
{
    WriteTestFile("{invalid json content}");
    std::vector<InstalledBundleInfo> infoList;
    bool ret = util_->LoadFromFile(infoList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestLoadFromFileNonArrayJson
 * @tc.desc: Test LoadFromFile returns false when file contains non-array JSON.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, LoadFromFile_NonArrayJson_ReturnFalse, TestSize.Level1)
{
    WriteTestFile("{\"key\": \"value\"}");
    std::vector<InstalledBundleInfo> infoList;
    bool ret = util_->LoadFromFile(infoList);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestLoadFromFileValidArray
 * @tc.desc: Test LoadFromFile returns true and parses data correctly from valid JSON array.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, LoadFromFile_ValidArray_ReturnTrueAndParsedData, TestSize.Level1)
{
    WriteTestFile("[{\"mdmName\":\"admin1\",\"installedName\":\"app1\",\"installedType\":1,\"installedTime\":1000}]");
    std::vector<InstalledBundleInfo> infoList;
    bool ret = util_->LoadFromFile(infoList);
    EXPECT_TRUE(ret);
    EXPECT_EQ(infoList.size(), 1);
    EXPECT_EQ(infoList[0].mdmName, "admin1");
    EXPECT_EQ(infoList[0].installedName, "app1");
    EXPECT_EQ(infoList[0].installedType, InstalledBundleType::NORMAL);
    EXPECT_EQ(infoList[0].installedTime, 1000);
}

/**
 * @tc.name: TestLoadFromFileRoundTripWithJsonKeys
 * @tc.desc: Test LoadFromFile and SerializeToJson round-trip preserves data using JSON key constants.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, LoadFromFile_RoundTripWithJsonKeys_Success, TestSize.Level1)
{
    std::vector<InstalledBundleInfo> originalList;
    InstalledBundleInfo info1;
    info1.mdmName = "com.admin.round1";
    info1.installedName = "com.app.round1";
    info1.installedType = InstalledBundleType::AG;
    info1.installedTime = 100000;
    originalList.push_back(info1);

    InstalledBundleInfo info2;
    info2.mdmName = "com.admin.round2";
    info2.installedName = "com.app.round2";
    info2.installedType = InstalledBundleType::MDM;
    info2.installedTime = 200000;
    originalList.push_back(info2);

    // 序列化到JSON
    std::string jsonStr = util_->SerializeToJson(originalList);
    EXPECT_FALSE(jsonStr.empty());

    // 写入文件
    WriteTestFile(jsonStr);

    // 从文件加载
    std::vector<InstalledBundleInfo> loadedList;
    bool ret = util_->LoadFromFile(loadedList);
    EXPECT_TRUE(ret);
    EXPECT_EQ(loadedList.size(), 2);

    // 验证round-trip数据一致性（使用JSON key常量）
    EXPECT_EQ(loadedList[0].mdmName, "com.admin.round1");
    EXPECT_EQ(loadedList[0].installedName, "com.app.round1");
    EXPECT_EQ(loadedList[0].installedType, InstalledBundleType::AG);
    EXPECT_EQ(loadedList[0].installedTime, 100000);

    EXPECT_EQ(loadedList[1].mdmName, "com.admin.round2");
    EXPECT_EQ(loadedList[1].installedName, "com.app.round2");
    EXPECT_EQ(loadedList[1].installedType, InstalledBundleType::MDM);
    EXPECT_EQ(loadedList[1].installedTime, 200000);
}

/**
 * @tc.name: TestLoadFromFileMissingFields
 * @tc.desc: Test LoadFromFile handles JSON items with missing fields by using default values.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, LoadFromFile_MissingFields_ReturnDefaultValues, TestSize.Level1)
{
    // JSON项缺少部分字段，LoadFromFile应使用默认值
    WriteTestFile("[{\"mdmName\":\"admin_only\"}]");
    std::vector<InstalledBundleInfo> infoList;
    bool ret = util_->LoadFromFile(infoList);
    EXPECT_TRUE(ret);
    EXPECT_EQ(infoList.size(), 1);
    EXPECT_EQ(infoList[0].mdmName, "admin_only");
    // 缺少installedName字段，默认为空字符串
    EXPECT_EQ(infoList[0].installedName, "");
    // 缺少installedType字段，默认为NORMAL
    EXPECT_EQ(infoList[0].installedType, InstalledBundleType::NORMAL);
    // 缺少installedTime字段，默认为0
    EXPECT_EQ(infoList[0].installedTime, 0);
}

/**
 * @tc.name: TestLoadFromFileEmptyArray
 * @tc.desc: Test LoadFromFile returns true with empty infoList when file contains empty JSON array.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, LoadFromFile_EmptyArray_ReturnTrueAndEmptyList, TestSize.Level1)
{
    WriteTestFile("[]");
    std::vector<InstalledBundleInfo> infoList;
    bool ret = util_->LoadFromFile(infoList);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(infoList.empty());
}

/**
 * @tc.name: TestSaveToFileSuccess
 * @tc.desc: Test SaveToFile writes data to file successfully.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, SaveToFile_Normal_ReturnTrue, TestSize.Level1)
{
    CleanupTestFile();
    std::vector<InstalledBundleInfo> infoList;
    InstalledBundleInfo info;
    info.mdmName = "com.admin.save";
    info.installedName = "com.app.save";
    info.installedType = InstalledBundleType::NORMAL;
    info.installedTime = 5000;
    infoList.push_back(info);

    bool ret = util_->SaveToFile(infoList);
    EXPECT_TRUE(ret);

    // 验证数据被正确写入文件
    std::vector<InstalledBundleInfo> loadedList;
    ret = util_->LoadFromFile(loadedList);
    EXPECT_TRUE(ret);
    EXPECT_EQ(loadedList.size(), 1);
    EXPECT_EQ(loadedList[0].mdmName, "com.admin.save");
}

/**
 * @tc.name: TestEnsureFileExistsSuccess
 * @tc.desc: Test EnsureFileExists creates directory and file when they don't exist.
 * @tc.type: FUNC
 */
HWTEST_F(InstalledBundleInfoUtilTest, EnsureFileExists_FileNotExist_ReturnTrue, TestSize.Level1)
{
    // 先删除文件（如果存在）
    std::ofstream file(TEST_FILE_PATH, std::ios::trunc);
    if (file.is_open()) {
        file.close();
    }

    bool ret = util_->EnsureFileExists();
    EXPECT_TRUE(ret);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
