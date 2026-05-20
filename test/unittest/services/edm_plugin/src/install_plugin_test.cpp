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

#include "parameters.h"

#include "uninstall_plugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string HAP_FILE_PATH = "/data/test/resource/enterprise_device_management/hap/right.hap";
const std::string INVALID_HAP_FILE_PATH = "/data/test/resource/enterprise_device_management/hap/../right.hap";
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
        InstallParam param = {{HAP_FILE_PATH}, DEFAULT_USER_ID, 0};
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
 * @tc.name: TestOnSetPolicyFailWithInvalidFilePath
 * @tc.desc: Test InstallPlugin::OnSetPolicy when file path is invalid (contains relative path).
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnSetPolicyFailWithInvalidFilePath, TestSize.Level1)
{
    InstallPlugin plugin;
    InstallParam param = {{INVALID_HAP_FILE_PATH}, DEFAULT_USER_ID, 0};
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    int32_t replyCode = reply.ReadInt32();
    ASSERT_TRUE(replyCode == EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    std::string errMsg = reply.ReadString();
    ASSERT_TRUE(errMsg == "invalid hap file path");
}

/**
 * @tc.name: TestOnGetPolicyFailWithLongName
 * @tc.desc: Test InstallPlugin::OnGetPolicy when file name is too long (exceeds PATH_MAX).
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnGetPolicyFailWithLongName, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string policyData;
    MessageParcel reply;
    MessageParcel data;
    int32_t userId = DEFAULT_USER_ID;
    std::string strFileName(5000, 'a');
    data.WriteString(strFileName);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
    ASSERT_TRUE(reply.ReadString() == "invalid hapFilePath");
}

/**
 * @tc.name: TestOnGetPolicyFailWithRelativePath01
 * @tc.desc: Test InstallPlugin::OnGetPolicy when file path contains "../" relative path.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnGetPolicyFailWithRelativePath01, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string policyData;
    MessageParcel reply;
    MessageParcel data;
    int32_t userId = DEFAULT_USER_ID;
    std::string strFileName = "../aaa.hap";
    data.WriteString(strFileName);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
}

/**
 * @tc.name: TestOnGetPolicyFailWithRelativePath02
 * @tc.desc: Test InstallPlugin::OnGetPolicy when file path contains "./" relative path.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnGetPolicyFailWithRelativePath02, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string policyData;
    MessageParcel reply;
    MessageParcel data;
    int32_t userId = DEFAULT_USER_ID;
    std::string strFileName = "./aaa.hap";
    data.WriteString(strFileName);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
}

/**
 * @tc.name: TestOnGetPolicyFailWithAbsolutePath
 * @tc.desc: Test InstallPlugin::OnGetPolicy when file path contains "/" absolute path separator.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnGetPolicyFailWithAbsolutePath, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string policyData;
    MessageParcel reply;
    MessageParcel data;
    int32_t userId = DEFAULT_USER_ID;
    std::string strFileName = "/aaa.hap";
    data.WriteString(strFileName);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
}

/**
 * @tc.name: TestOnGetPolicySuc
 * @tc.desc: Test InstallPlugin::OnGetPolicy success case with valid file name.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnGetPolicySuc, TestSize.Level1)
{
    InstallPlugin plugin;
    std::string policyData;
    MessageParcel reply;
    MessageParcel data;
    int32_t userId = DEFAULT_USER_ID;
    std::string strFileName = "aaa.hap";
    data.WriteString(strFileName);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == ERR_OK);
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
} // namespace TEST
} // namespace EDM
} // namespace OHOS