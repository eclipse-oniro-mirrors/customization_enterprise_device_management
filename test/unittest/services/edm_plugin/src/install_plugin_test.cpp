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

#include "install_plugin_test.h"
#define private public
#include "install_plugin.h"
#undef private

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "parameters.h"

#include "edm_constants.h"
#include "uninstall_plugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string HAP_FILE_PATH = "/data/test/resource/enterprise_device_management/hap/right.hap";
const std::string BOOT_OEM_MODE = "const.boot.oemmode";
const std::string DEVELOP_PARAM = "rd";
const std::string USER_MODE = "user";

void InstallPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void InstallPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicySuc
 * @tc.desc: Test InstallPlugin::OnSetPolicy success case.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnSetPolicySuc, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam == DEVELOP_PARAM) {
        InstallPlugin plugin;
        InstallParam param;
        param.hapFilePaths = {HAP_FILE_PATH};
        param.userId = DEFAULT_USER_ID;
        param.installFlag = 0;
        int32_t fd = open(HAP_FILE_PATH.c_str(), O_RDONLY);
        ASSERT_TRUE(fd >= 0);
        param.hapFds = {fd};
        MessageParcel reply;
        ErrCode ret = plugin.OnSetPolicy(param, reply);
        ASSERT_TRUE(ret == ERR_OK);
        UninstallPlugin uninstallPlugin;
        UninstallParam uninstallParam = {"com.example.l3jsdemo", DEFAULT_USER_ID, false};
        MessageParcel uninstallReply;
        ret = uninstallPlugin.OnSetPolicy(uninstallParam, uninstallReply);
        ASSERT_TRUE(ret == ERR_OK);
    }
}

/**
 * @tc.name: TestOnSetPolicyFailWithInvalidHapPath
 * @tc.desc: Test InstallPlugin::OnSetPolicy when hap file path has no separator (invalid for temp copy).
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnSetPolicyFailWithInvalidHapPath, TestSize.Level1)
{
    InstallPlugin plugin;
    InstallParam param;
    param.hapFilePaths = {"aaa.hap"};
    param.userId = DEFAULT_USER_ID;
    param.installFlag = 0;
    int32_t fd = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    param.hapFds = {fd};
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    int32_t replyCode = reply.ReadInt32();
    ASSERT_TRUE(replyCode == EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    std::string errMsg = reply.ReadString();
    ASSERT_TRUE(errMsg == "invalid hap file path");
}

/**
 * @tc.name: TestOnSetPolicyFailWithFdsSizeMismatch
 * @tc.desc: Test InstallPlugin::OnSetPolicy when hapFilePaths size not match hapFds size.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnSetPolicyFailWithFdsSizeMismatch, TestSize.Level1)
{
    InstallPlugin plugin;
    InstallParam param;
    param.hapFilePaths = {HAP_FILE_PATH};
    param.userId = DEFAULT_USER_ID;
    param.installFlag = 0;
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultUserIdNotFound, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_USER_NOT_EXIST = 301;
    ErrCode ret = plugin.HandleInstallResult(ERR_USER_NOT_EXIST, "user not found", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_USER_ID_NOT_FOUND);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_USER_ID_NOT_FOUND);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultParseFailed, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_PARSE_FAILED = 9568262;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_PARSE_FAILED, "parse failed", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_PARSE_FAILED);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_PARSE_FAILED);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultSignatureVerifyFailed, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_VERIFICATION_FAILED = 9568264;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_VERIFICATION_FAILED, "signature verify failed", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_SIGNATURE_VERIFY_FAILED);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_SIGNATURE_VERIFY_FAILED);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultInsufficientDiskSpace, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_DISK_MEM_INSUFFICIENT = 9568288;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_DISK_MEM_INSUFFICIENT, "no disk space", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_INSUFFICIENT_DISK_SPACE);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_INSUFFICIENT_DISK_SPACE);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultVersionTooEarly, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_VERSION_DOWNGRADE = 9568263;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_VERSION_DOWNGRADE, "version downgrade", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_VERSION_TOO_EARLY);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_VERSION_TOO_EARLY);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultDependantModuleNotExist, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_DEPENDENT_MODULE_NOT_EXIST = 9568305;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_DEPENDENT_MODULE_NOT_EXIST,
        "dependent module not exist", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_DEPENDANT_MODULE_NOT_EXIST);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_DEPENDANT_MODULE_NOT_EXIST);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultOverlayCheckFailed, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_NO_SYSTEM_APPLICATION_FOR_EXTERNAL_OVERLAY = 9568374;
    ErrCode ret = plugin.HandleInstallResult(ERR_OVERLAY_INSTALLATION_FAILED_NO_SYSTEM_APPLICATION_FOR_EXTERNAL_OVERLAY,
        "overlay check failed", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_OVERLAY_CHECK_FAILED);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_OVERLAY_CHECK_FAILED);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultMissingRequiredPermissionsForHsp, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED = 9568309;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED,
        "share app library not allowed", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_MISSING_REQUIRED_PERMISSIONS_FOR_HSP);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_MISSING_REQUIRED_PERMISSIONS_FOR_HSP);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultSharedLibrariesNotAllowed, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_FILE_IS_SHARED_LIBRARY = 9568314;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_FILE_IS_SHARED_LIBRARY,
        "file is shared library", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_SHARED_LIBRARIES_NOT_ALLOWED);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_SHARED_LIBRARIES_NOT_ALLOWED);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultEnterpriseDisallowed, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_DISALLOWED = 9568303;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_DISALLOWED, "disallow install", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_ENTERPRISE_DISALLOWED);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_ENTERPRISE_DISALLOWED);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultUriIncorrect, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSATLL_CHECK_PROXY_DATA_URI_FAILED = 9568315;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSATLL_CHECK_PROXY_DATA_URI_FAILED, "wrong data proxy uri", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_URI_INCORRECT);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_URI_INCORRECT);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultPermissionConfigurationIncorrect, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSATLL_CHECK_PROXY_DATA_PERMISSION_FAILED = 9568316;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSATLL_CHECK_PROXY_DATA_PERMISSION_FAILED,
        "wrong data proxy permission", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_PERMISSION_CONFIGURATION_INCORRECT);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_PERMISSION_CONFIGURATION_INCORRECT);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultIsolationModeNotSupported, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_ISOLATION_MODE_FAILED = 9568317;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_ISOLATION_MODE_FAILED, "wrong mode isolation", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_ISOLATION_MODE_NOT_SUPPORTED);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_ISOLATION_MODE_NOT_SUPPORTED);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultVersionCodeNotGreater, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_ALREADY_EXIST = 9568276;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_ALREADY_EXIST, "install already exist", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_VERSION_CODE_NOT_GREATER);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_VERSION_CODE_NOT_GREATER);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultCodeSignatureVerificationFailure, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_CODE_SIGNATURE_FAILED = 9568393;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_CODE_SIGNATURE_FAILED,
        "code signature failed", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_CODE_SIGNATURE_VERIFICATION_FAILURE);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_CODE_SIGNATURE_VERIFICATION_FAILURE);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultEnterpriseDeviceVerificationFailure, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED = 9568398;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED,
        "enterprise bundle not allowed", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_ENTERPRISE_DEVICE_VERIFICATION_FAILURE);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_ENTERPRISE_DEVICE_VERIFICATION_FAILURE);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultConfigurationMismatch, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_ENTRY_ALREADY_EXIST = 9568267;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_ENTRY_ALREADY_EXIST,
        "multiple hap info inconsistent", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APPS_CONFIGURATION_MISMATCH);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APPS_CONFIGURATION_MISMATCH);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultPathInvalid, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_INVALID_BUNDLE_FILE = 9568271;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_INVALID_BUNDLE_FILE, "hap filepath invalid", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultUnknownError, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t UNKNOWN_ERROR_CODE = 99999999;
    ErrCode ret = plugin.HandleInstallResult(UNKNOWN_ERROR_CODE, "unknown error", reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
}

HWTEST_F(InstallPluginTest, TestHandleInstallResultSuccess, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    ErrCode ret = plugin.HandleInstallResult(ERR_OK, "success", reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetCallingBundleNameFail
 * @tc.desc: Test InstallPlugin::GetCallingBundleName when bundle service is unavailable.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, GetCallingBundleName_BundleServiceUnavailable_ReturnFalse, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string bundleName;
    bool ret = plugin.GetCallingBundleName(bundleName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestGetBundleInfoAndTypeFail
 * @tc.desc: Test InstallPlugin::GetBundleInfoAndType when bundle service is unavailable.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, GetBundleInfoAndType_BundleServiceUnavailable_ReturnFalse, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string bundleName;
    InstalledBundleType bundleType = InstalledBundleType::NORMAL;
    bool ret = plugin.GetBundleInfoAndType("/data/test/test.hap", bundleName, bundleType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestHandleInstallResultSuccessWithEmptyRealPaths
 * @tc.desc: Test InstallPlugin::HandleInstallResult success with empty realPaths, no report event.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, HandleInstallResult_SuccessWithEmptyRealPaths_NoReport, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    std::vector<std::string> realPaths;
    ErrCode ret = plugin.HandleInstallResult(ERR_OK, "success", reply, realPaths);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestHandleInstallResultSuccessWithRealPathsButNoBundleInfo
 * @tc.desc: Test InstallPlugin::HandleInstallResult success with realPaths but GetBundleInfoAndType fails.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, HandleInstallResult_SuccessWithRealPathsButNoBundleInfo_NoReport, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    std::vector<std::string> realPaths = { "/data/test/test.hap" };
    ErrCode ret = plugin.HandleInstallResult(ERR_OK, "success", reply, realPaths);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestHandleInstallResultFailWithRealPaths
 * @tc.desc: Test InstallPlugin::HandleInstallResult fail with realPaths, error handling path.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, HandleInstallResult_FailWithRealPaths_ReturnError, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    std::vector<std::string> realPaths = { "/data/test/test.hap" };
    constexpr int32_t ERR_INSTALL_PARSE_FAILED = 9568262;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_PARSE_FAILED, "parse failed", reply, realPaths);
    ASSERT_EQ(ret, EdmReturnErrCode::INSTALL_APP_PARSE_FAILED);
    ASSERT_EQ(reply.ReadInt32(), EdmReturnErrCode::INSTALL_APP_PARSE_FAILED);
}

/**
 * @tc.name: TestHandleInstallResultUnknownErrorWithRealPaths
 * @tc.desc: Test InstallPlugin::HandleInstallResult unknown error with realPaths.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, HandleInstallResult_UnknownErrorWithRealPaths_ReturnApplicationInstallFailed,
    TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    std::vector<std::string> realPaths = { "/data/test/test.hap" };
    constexpr int32_t UNKNOWN_ERROR_CODE = 99999999;
    ErrCode ret = plugin.HandleInstallResult(UNKNOWN_ERROR_CODE, "unknown error", reply, realPaths);
    ASSERT_EQ(ret, EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    ASSERT_EQ(reply.ReadInt32(), EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
}

/**
 * @tc.name: TestInstalledBundleTypeEnumValues
 * @tc.desc: Test InstalledBundleType enum values are correct.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, InstalledBundleType_EnumValues_Correct, TestSize.Level1)
{
    EXPECT_EQ(static_cast<int32_t>(InstalledBundleType::AG), 0);
    EXPECT_EQ(static_cast<int32_t>(InstalledBundleType::NORMAL), 1);
    EXPECT_EQ(static_cast<int32_t>(InstalledBundleType::MDM), 2);
}

/**
 * @tc.name: GetBundleInfoAndType_EmptyHapFilePath_ReturnFalse
 * @tc.desc: Test InstallPlugin::GetBundleInfoAndType with empty hapFilePath.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, GetBundleInfoAndType_EmptyHapFilePath_ReturnFalse, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string bundleName;
    InstalledBundleType bundleType = InstalledBundleType::NORMAL;
    bool ret = plugin.GetBundleInfoAndType("", bundleName, bundleType);
    EXPECT_FALSE(ret);
    EXPECT_EQ(bundleName, "");
    EXPECT_EQ(bundleType, InstalledBundleType::NORMAL);
}

/**
 * @tc.name: GetBundleInfoAndType_InvalidHapFilePath_ReturnFalse
 * @tc.desc: Test InstallPlugin::GetBundleInfoAndType with invalid hapFilePath.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, GetBundleInfoAndType_InvalidHapFilePath_ReturnFalse, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string bundleName;
    InstalledBundleType bundleType = InstalledBundleType::NORMAL;
    bool ret = plugin.GetBundleInfoAndType("/nonexistent/path/test.hap", bundleName, bundleType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: HandleInstallResult_SuccessWithMultipleRealPaths_NoReport
 * @tc.desc: Test InstallPlugin::HandleInstallResult success with multiple realPaths but GetBundleInfoAndType fails.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, HandleInstallResult_SuccessWithMultipleRealPaths_NoReport, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    std::vector<std::string> realPaths = { "/data/test/test1.hap", "/data/test/test2.hap" };
    ErrCode ret = plugin.HandleInstallResult(ERR_OK, "success", reply, realPaths);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: HandleInstallResult_FailWithEmptyRealPaths_ReturnError
 * @tc.desc: Test InstallPlugin::HandleInstallResult fail with empty realPaths (default parameter).
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, HandleInstallResult_FailWithEmptyRealPaths_ReturnError, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    constexpr int32_t ERR_INSTALL_PARSE_FAILED = 9568262;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_PARSE_FAILED, "parse failed", reply);
    ASSERT_EQ(ret, EdmReturnErrCode::INSTALL_APP_PARSE_FAILED);
    ASSERT_EQ(reply.ReadInt32(), EdmReturnErrCode::INSTALL_APP_PARSE_FAILED);
}

/**
 * @tc.name: HandleInstallResult_SuccessWithEmptyRealPathsAndDefaultParam_NoReport
 * @tc.desc: Test InstallPlugin::HandleInstallResult success with default realPaths parameter.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, HandleInstallResult_SuccessWithDefaultRealPaths_NoReport, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    ErrCode ret = plugin.HandleInstallResult(ERR_OK, "success", reply);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: HandleInstallResult_FailWithMultipleRealPaths_ReturnError
 * @tc.desc: Test InstallPlugin::HandleInstallResult fail with multiple realPaths.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, HandleInstallResult_FailWithMultipleRealPaths_ReturnError, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    std::vector<std::string> realPaths = { "/data/test/test1.hap", "/data/test/test2.hap" };
    constexpr int32_t ERR_INSTALL_VERIFICATION_FAILED = 9568264;
    ErrCode ret = plugin.HandleInstallResult(ERR_INSTALL_VERIFICATION_FAILED, "signature verify failed", reply,
        realPaths);
    ASSERT_EQ(ret, EdmReturnErrCode::INSTALL_APP_SIGNATURE_VERIFY_FAILED);
    ASSERT_EQ(reply.ReadInt32(), EdmReturnErrCode::INSTALL_APP_SIGNATURE_VERIFY_FAILED);
}

/**
 * @tc.name: CopyFileContent_InvalidInputFd_ReturnSystemAbnormally
 * @tc.desc: Test InstallPlugin::CopyFileContent when inputFd is invalid (fstat fails).
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, CopyFileContent_InvalidInputFd_ReturnSystemAbnormally, TestSize.Level1)
{
    InstallPlugin plugin;
    MessageParcel reply;
    ErrCode ret = plugin.CopyFileContent(-1, -1, reply);
    ASSERT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    ASSERT_EQ(reply.ReadInt32(), EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: CopyFileContent_ValidFd_ReturnOk
 * @tc.desc: Test InstallPlugin::CopyFileContent when fds are valid.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, CopyFileContent_ValidFd_ReturnOk, TestSize.Level1)
{
    InstallPlugin plugin;
    int32_t inputFd = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(inputFd >= 0);
    std::string tempPath = "/data/test/resource/enterprise_device_management/temp_copy_content.hap";
    int32_t outputFd = open(tempPath.c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_TRUE(outputFd >= 0);
    MessageParcel reply;
    ErrCode ret = plugin.CopyFileContent(inputFd, outputFd, reply);
    EXPECT_EQ(ret, ERR_OK);
    fdsan_exchange_owner_tag(inputFd, 0, EdmConstants::LOG_DOMAINID);
    fdsan_close_with_tag(inputFd, EdmConstants::LOG_DOMAINID);
    fdsan_exchange_owner_tag(outputFd, 0, EdmConstants::LOG_DOMAINID);
    fdsan_close_with_tag(outputFd, EdmConstants::LOG_DOMAINID);
    remove(tempPath.c_str());
}

/**
 * @tc.name: GenerateUniqueFilePrefix_FormatCorrect_ReturnNonEmpty
 * @tc.desc: Test InstallPlugin::GenerateUniqueFilePrefix generates correct format string.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, GenerateUniqueFilePrefix_FormatCorrect_ReturnNonEmpty, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string filePrefix = plugin.GenerateUniqueFilePrefix();
    EXPECT_FALSE(filePrefix.empty());
    EXPECT_EQ(filePrefix.substr(0, 4), "edm_");
    size_t firstUnderscore = filePrefix.find('_');
    EXPECT_NE(firstUnderscore, std::string::npos);
    size_t secondUnderscore = filePrefix.find('_', firstUnderscore + 1);
    EXPECT_NE(secondUnderscore, std::string::npos);
}

/**
 * @tc.name: GenerateUniqueFilePrefix_TwiceCalled_ReturnDifferent
 * @tc.desc: Test InstallPlugin::GenerateUniqueFilePrefix generates different names when called twice.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, GenerateUniqueFilePrefix_TwiceCalled_ReturnDifferent, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string filePrefix1 = plugin.GenerateUniqueFilePrefix();
    std::string filePrefix2 = plugin.GenerateUniqueFilePrefix();
    EXPECT_NE(filePrefix1, filePrefix2);
}

/**
 * @tc.name: CopyHapFile_InvalidHapPath_ReturnApplicationInstallFailed
 * @tc.desc: Test InstallPlugin::CopyHapFile when hapFilePath has no separator.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, CopyHapFile_InvalidHapPath_ReturnApplicationInstallFailed, TestSize.Level1)
{
    InstallPlugin plugin;
    int32_t inputFd = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(inputFd >= 0);
    std::string tempPath;
    MessageParcel reply;
    ErrCode ret = plugin.CopyHapFile(inputFd, "aaa.hap", tempPath, reply);
    EXPECT_EQ(ret, EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    EXPECT_EQ(reply.ReadString(), "invalid hap file path");
    fdsan_exchange_owner_tag(inputFd, 0, EdmConstants::LOG_DOMAINID);
    fdsan_close_with_tag(inputFd, EdmConstants::LOG_DOMAINID);
}

/**
 * @tc.name: CopyHapFile_PathEndsWithSeparator_ReturnApplicationInstallFailed
 * @tc.desc: Test InstallPlugin::CopyHapFile when hapFilePath ends with separator.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, CopyHapFile_PathEndsWithSeparator_ReturnApplicationInstallFailed, TestSize.Level1)
{
    InstallPlugin plugin;
    int32_t inputFd = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(inputFd >= 0);
    std::string tempPath;
    MessageParcel reply;
    ErrCode ret = plugin.CopyHapFile(inputFd, "/data/test/", tempPath, reply);
    EXPECT_EQ(ret, EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    EXPECT_EQ(reply.ReadString(), "invalid hap file path");
    fdsan_exchange_owner_tag(inputFd, 0, EdmConstants::LOG_DOMAINID);
    fdsan_close_with_tag(inputFd, EdmConstants::LOG_DOMAINID);
}

/**
 * @tc.name: CopyHapFile_InvalidInputFd_ReturnSystemAbnormally
 * @tc.desc: Test InstallPlugin::CopyHapFile when inputFd is invalid (fstat fails in CopyFileContent).
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, CopyHapFile_InvalidInputFd_ReturnSystemAbnormally, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string tempPath;
    MessageParcel reply;
    ErrCode ret = plugin.CopyHapFile(-1, "/data/test/right.hap", tempPath, reply);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: CopyHapFile_ValidInput_ReturnOk
 * @tc.desc: Test InstallPlugin::CopyHapFile when input is valid.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, CopyHapFile_ValidInput_ReturnOk, TestSize.Level1)
{
    InstallPlugin plugin;
    ASSERT_TRUE(plugin.CreateDirectory());
    int32_t inputFd = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(inputFd >= 0);
    std::string tempPath;
    MessageParcel reply;
    ErrCode ret = plugin.CopyHapFile(inputFd, "/data/test/right.hap", tempPath, reply);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(tempPath.empty());
    fdsan_exchange_owner_tag(inputFd, 0, EdmConstants::LOG_DOMAINID);
    fdsan_close_with_tag(inputFd, EdmConstants::LOG_DOMAINID);
    plugin.DeleteFiles({tempPath});
}

/**
 * @tc.name: PrepareTempFiles_FdsSizeMismatch_ReturnSystemAbnormally
 * @tc.desc: Test InstallPlugin::PrepareTempFiles when hapFilePaths size not match hapFds size.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, PrepareTempFiles_FdsSizeMismatch_ReturnSystemAbnormally, TestSize.Level1)
{
    InstallPlugin plugin;
    InstallParam param;
    param.hapFilePaths = {HAP_FILE_PATH};
    param.userId = DEFAULT_USER_ID;
    param.installFlag = 0;
    std::vector<std::string> tempPaths;
    MessageParcel reply;
    ErrCode ret = plugin.PrepareTempFiles(param, tempPaths, reply);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: PrepareTempFiles_InvalidHapPath_ReturnApplicationInstallFailed
 * @tc.desc: Test InstallPlugin::PrepareTempFiles when hapFilePath has no separator.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, PrepareTempFiles_InvalidHapPath_ReturnApplicationInstallFailed, TestSize.Level1)
{
    InstallPlugin plugin;
    InstallParam param;
    param.hapFilePaths = {"aaa.hap"};
    param.userId = DEFAULT_USER_ID;
    param.installFlag = 0;
    int32_t fd = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(fd >= 0);
    param.hapFds = {fd};
    std::vector<std::string> tempPaths;
    MessageParcel reply;
    ErrCode ret = plugin.PrepareTempFiles(param, tempPaths, reply);
    EXPECT_EQ(ret, EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    EXPECT_EQ(reply.ReadString(), "invalid hap file path");
}

/**
 * @tc.name: PrepareTempFiles_ValidInput_ReturnOk
 * @tc.desc: Test InstallPlugin::PrepareTempFiles when input is valid.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, PrepareTempFiles_ValidInput_ReturnOk, TestSize.Level1)
{
    InstallPlugin plugin;
    InstallParam param;
    param.hapFilePaths = {HAP_FILE_PATH};
    param.userId = DEFAULT_USER_ID;
    param.installFlag = 0;
    int32_t fd = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(fd >= 0);
    param.hapFds = {fd};
    std::vector<std::string> tempPaths;
    MessageParcel reply;
    ErrCode ret = plugin.PrepareTempFiles(param, tempPaths, reply);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(tempPaths.size(), 1u);
    plugin.DeleteFiles(tempPaths);
}

/**
 * @tc.name: ExecuteStreamInstall_NullBundleMgr_ReturnSystemAbnormally
 * @tc.desc: Test InstallPlugin::ExecuteStreamInstall when iBundleMgr is null (non-develop env).
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, ExecuteStreamInstall_NullBundleMgr_ReturnSystemAbnormally, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam != DEVELOP_PARAM) {
        InstallPlugin plugin;
        InstallParam param;
        param.userId = DEFAULT_USER_ID;
        param.installFlag = 0;
        std::vector<std::string> tempPaths;
        MessageParcel reply;
        ErrCode ret = plugin.ExecuteStreamInstall(tempPaths, param, reply);
        EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    }
}

/**
 * @tc.name: CopyFileContent_FileTooLarge_ReturnInstallAppPathInvalid
 * @tc.desc: Test InstallPlugin::CopyFileContent when file size exceeds MAX_HAP_FILE_SIZE (4GB).
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, CopyFileContent_FileTooLarge_ReturnInstallAppPathInvalid, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string inputPath = "/data/test/resource/enterprise_device_management/temp_large_input.hap";
    int32_t inputFd = open(inputPath.c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_TRUE(inputFd >= 0);
    int64_t largeSize = 4LL * 1024 * 1024 * 1024 + 1;
    if (ftruncate(inputFd, largeSize) != 0) {
        fdsan_exchange_owner_tag(inputFd, 0, EdmConstants::LOG_DOMAINID);
        fdsan_close_with_tag(inputFd, EdmConstants::LOG_DOMAINID);
        remove(inputPath.c_str());
        GTEST_SKIP() << "ftruncate to 4GB+1 not supported in this environment";
    }
    std::string outputPath = "/data/test/resource/enterprise_device_management/temp_large_output.hap";
    int32_t outputFd = open(outputPath.c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_TRUE(outputFd >= 0);
    MessageParcel reply;
    ErrCode ret = plugin.CopyFileContent(inputFd, outputFd, reply);
    EXPECT_EQ(ret, EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    EXPECT_EQ(reply.ReadString(), "hap file too large");
    fdsan_exchange_owner_tag(inputFd, 0, EdmConstants::LOG_DOMAINID);
    fdsan_close_with_tag(inputFd, EdmConstants::LOG_DOMAINID);
    fdsan_exchange_owner_tag(outputFd, 0, EdmConstants::LOG_DOMAINID);
    fdsan_close_with_tag(outputFd, EdmConstants::LOG_DOMAINID);
    remove(inputPath.c_str());
    remove(outputPath.c_str());
}

/**
 * @tc.name: CopyHapFile_TempPathTooLong_ReturnInstallAppPathInvalid
 * @tc.desc: Test InstallPlugin::CopyHapFile when tempPath length exceeds PATH_MAX.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, CopyHapFile_TempPathTooLong_ReturnInstallAppPathInvalid, TestSize.Level1)
{
    InstallPlugin plugin;
    int32_t inputFd = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(inputFd >= 0);
    std::string longFileName(static_cast<size_t>(PATH_MAX), 'x');
    longFileName += ".hap";
    std::string hapFilePath = "/data/test/" + longFileName;
    std::string tempPath;
    MessageParcel reply;
    ErrCode ret = plugin.CopyHapFile(inputFd, hapFilePath, tempPath, reply);
    EXPECT_EQ(ret, EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    EXPECT_EQ(reply.ReadString(), "invalid hap file path");
    EXPECT_TRUE(tempPath.empty());
    fdsan_exchange_owner_tag(inputFd, 0, EdmConstants::LOG_DOMAINID);
    fdsan_close_with_tag(inputFd, EdmConstants::LOG_DOMAINID);
}

/**
 * @tc.name: PrepareTempFiles_SecondFileFails_RemainingFdsClosedAndTempFilesDeleted
 * @tc.desc: Test InstallPlugin::PrepareTempFiles when second CopyHapFile fails: verify fd and temp file cleanup.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, PrepareTempFiles_SecondFileFails_RemainingFdsClosedAndTempFilesDeleted, TestSize.Level1)
{
    InstallPlugin plugin;
    ASSERT_TRUE(plugin.CreateDirectory());
    InstallParam param;
    param.hapFilePaths = { HAP_FILE_PATH, "invalid_nopath.hap" };
    param.userId = DEFAULT_USER_ID;
    param.installFlag = 0;
    int32_t fd1 = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(fd1 >= 0);
    int32_t fd2 = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(fd2 >= 0);
    param.hapFds = { fd1, fd2 };
    std::vector<std::string> tempPaths;
    MessageParcel reply;
    ErrCode ret = plugin.PrepareTempFiles(param, tempPaths, reply);
    EXPECT_EQ(ret, EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
    EXPECT_EQ(reply.ReadString(), "invalid hap file path");
    EXPECT_EQ(tempPaths.size(), 1u);
    plugin.DeleteFiles(tempPaths);
}

/**
 * @tc.name: PrepareTempFiles_ValidMultipleFiles_AllTempPathsCreated
 * @tc.desc: Test InstallPlugin::PrepareTempFiles when multiple valid files are provided.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, PrepareTempFiles_ValidMultipleFiles_AllTempPathsCreated, TestSize.Level1)
{
    InstallPlugin plugin;
    ASSERT_TRUE(plugin.CreateDirectory());
    InstallParam param;
    param.hapFilePaths = { HAP_FILE_PATH, HAP_FILE_PATH };
    param.userId = DEFAULT_USER_ID;
    param.installFlag = 0;
    int32_t fd1 = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(fd1 >= 0);
    int32_t fd2 = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(fd2 >= 0);
    param.hapFds = { fd1, fd2 };
    std::vector<std::string> tempPaths;
    MessageParcel reply;
    ErrCode ret = plugin.PrepareTempFiles(param, tempPaths, reply);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(tempPaths.size(), 2u);
    EXPECT_FALSE(tempPaths[0].empty());
    EXPECT_FALSE(tempPaths[1].empty());
    plugin.DeleteFiles(tempPaths);
}

/**
 * @tc.name: CopyHapFile_FileNameWithNullChar_ReturnInstallAppPathInvalid
 * @tc.desc: Test InstallPlugin::CopyHapFile when fileName contains null char (tempPath fails TrustedExternalPath).
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, CopyHapFile_FileNameWithNullChar_ReturnInstallAppPathInvalid, TestSize.Level1)
{
    InstallPlugin plugin;
    int32_t inputFd = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(inputFd >= 0);
    std::string hapFilePath = "/data/test/good.hap";
    hapFilePath[12] = '\0';
    std::string tempPath;
    MessageParcel reply;
    ErrCode ret = plugin.CopyHapFile(inputFd, hapFilePath, tempPath, reply);
    EXPECT_EQ(ret, EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    EXPECT_EQ(reply.ReadString(), "invalid hap file path");
    fdsan_exchange_owner_tag(inputFd, 0, EdmConstants::LOG_DOMAINID);
    fdsan_close_with_tag(inputFd, EdmConstants::LOG_DOMAINID);
}

/**
 * @tc.name: CopyHapFile_FileNameWithBackslashPattern_ReturnInstallAppPathInvalid
 * @tc.desc: Test InstallPlugin::CopyHapFile when fileName contains backslash traversal pattern.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, CopyHapFile_FileNameWithBackslashPattern_ReturnInstallAppPathInvalid, TestSize.Level1)
{
    InstallPlugin plugin;
    int32_t inputFd = open(HAP_FILE_PATH.c_str(), O_RDONLY);
    ASSERT_TRUE(inputFd >= 0);
    std::string hapFilePath = R"(/data/test/file.\.\bad.hap)";
    std::string tempPath;
    MessageParcel reply;
    ErrCode ret = plugin.CopyHapFile(inputFd, hapFilePath, tempPath, reply);
    EXPECT_EQ(ret, EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    EXPECT_EQ(reply.ReadString(), "invalid hap file path");
    fdsan_exchange_owner_tag(inputFd, 0, EdmConstants::LOG_DOMAINID);
    fdsan_close_with_tag(inputFd, EdmConstants::LOG_DOMAINID);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS