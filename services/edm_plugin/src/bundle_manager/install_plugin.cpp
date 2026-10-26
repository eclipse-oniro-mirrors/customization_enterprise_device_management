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

#include "install_plugin.h"

#include <chrono>
#include <climits>
#include <fcntl.h>
#include <random>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_ability_definition.h>
#include <unistd.h>

#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "directory_ex.h"
#include "edm_bundle_manager_impl.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "edm_utils.h"
#include "hisysevent_adapter.h"
#include "installer_callback.h"
#include "ipc_skeleton.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(InstallPlugin::GetPlugin());
const std::string SEPARATOR = "/";
const std::string FILE_PREFIX = "edm_";
constexpr int32_t RANDOM_NUM_MAX = 9999;
constexpr int64_t MAX_HAP_FILE_SIZE = 4LL * 1024 * 1024 * 1024;
// 临时目录"/data/service/el1/public/edm/stream_install/"，长度是44
constexpr size_t TEMP_DIR_LEN = 44;
constexpr int32_t EDM_UID = 3057;
constexpr int32_t EDM_GID = 3057;

constexpr int32_t ERR_USER_NOT_EXIST = 301;
constexpr int32_t ERR_INSTALL_PARSE_FAILED = 9568262;
constexpr int32_t ERR_INSTALL_PARSE_UNEXPECTED = 9568337;
constexpr int32_t ERR_INSTALL_PARSE_MISSING_BUNDLE = 9568338;
constexpr int32_t ERR_INSTALL_PARSE_NO_PROFILE = 9568340;
constexpr int32_t ERR_INSTALL_PARSE_BAD_PROFILE = 9568341;
constexpr int32_t ERR_INSTALL_PARSE_PROFILE_PROP_TYPE_ERROR = 9568342;
constexpr int32_t ERR_INSTALL_PARSE_PROFILE_MISSING_PROP = 9568259;
constexpr int32_t ERR_INSTALL_PARSE_PERMISSION_ERROR = 9568343;
constexpr int32_t ERR_INSTALL_PARSE_PROFILE_PROP_CHECK_ERROR = 9568344;
constexpr int32_t ERR_INSTALL_PARSE_RPCID_FAILED = 9568346;
constexpr int32_t ERR_INSTALL_PARSE_NATIVE_SO_FAILED = 9568347;
constexpr int32_t ERR_INSTALL_PARSE_AN_FAILED = 9568348;
constexpr int32_t ERR_INSTALL_PARSE_MISSING_ABILITY = 9568339;
constexpr int32_t ERR_INSTALL_FAILED_PROFILE_PARSE_FAIL = 9568321;
constexpr int32_t ERR_INSTALL_BUNDLE_TYPE_NOT_SAME = 9568308;
constexpr int32_t ERR_INSTALL_DEVICE_TYPE_NOT_SUPPORTED = 9568304;
constexpr int32_t ERR_INSTALL_CHECK_SYSCAP_FAILED_AND_DEVICE_TYPE_NOT_SUPPORTED = 9568413;
constexpr int32_t ERR_INSTALL_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR = 9568345;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_NAME_MISSED = 9568365;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_TARGET_MODULE_NAME_MISSED = 9568366;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_INVALID_PRIORITY = 9568370;
constexpr int32_t ERR_INSTALL_DEBUG_ENCRYPTED_BUNDLE_FAILED = 9568415;
constexpr int32_t ERR_INSTALL_CHECK_BIN_FILE_FAILED = 9568449;
constexpr int32_t ERR_INSTALL_VERIFICATION_FAILED = 9568264;
constexpr int32_t ERR_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE = 9568331;
constexpr int32_t ERR_INSTALL_FAILED_INVALID_SIGNATURE_FILE_PATH = 9568318;
constexpr int32_t ERR_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE_FILE = 9568319;
constexpr int32_t ERR_INSTALL_FAILED_NO_BUNDLE_SIGNATURE = 9568320;
constexpr int32_t ERR_INSTALL_FAILED_VERIFY_APP_PKCS7_FAIL = 9568257;
constexpr int32_t ERR_INSTALL_FAILED_APP_SOURCE_NOT_TRUESTED = 9568322;
constexpr int32_t ERR_INSTALL_FAILED_BAD_DIGEST = 9568323;
constexpr int32_t ERR_INSTALL_FAILED_BUNDLE_INTEGRITY_VERIFICATION_FAILURE = 9568324;
constexpr int32_t ERR_INSTALL_FAILED_BAD_PUBLICKEY = 9568326;
constexpr int32_t ERR_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE = 9568327;
constexpr int32_t ERR_INSTALL_FAILED_NO_PROFILE_BLOCK_FAIL = 9568328;
constexpr int32_t ERR_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE = 9568329;
constexpr int32_t ERR_INSTALL_FAILED_VERIFY_SOURCE_INIT_FAIL = 9568330;
constexpr int32_t ERR_INSTALL_FAILED_DEVICE_UNAUTHORIZED = 9568423;
constexpr int32_t ERR_INSTALL_SINGLETON_INCOMPATIBLE = 9568302;
constexpr int32_t ERR_INSTALL_U1_ENABLE_NOT_SAME_IN_ALL_BUNDLE_INFOS = 9568442;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_DIFFERENT_SIGNATURE_CERTIFICATE = 9568375;
constexpr int32_t ERR_INSTALL_INVALID_BUNDLE_FILE = 9568271;
constexpr int32_t ERR_INSTALL_FILE_PATH_INVALID = 9568269;
constexpr int32_t ERR_INSTALL_ENTRY_ALREADY_EXIST = 9568267;
constexpr int32_t ERR_INSTALL_BUNDLENAME_NOT_SAME = 9568277;
constexpr int32_t ERR_INSTALL_VERSIONCODE_NOT_SAME = 9568278;
constexpr int32_t ERR_INSTALL_VERSIONNAME_NOT_SAME = 9568279;
constexpr int32_t ERR_INSTALL_MINCOMPATIBLE_VERSIONCODE_NOT_SAME = 9568280;
constexpr int32_t ERR_INSTALL_VENDOR_NOT_SAME = 9568281;
constexpr int32_t ERR_INSTALL_RELEASETYPE_NOT_SAME = 9568258;
constexpr int32_t ERR_INSTALL_RELEASETYPE_TARGET_NOT_SAME = 9568282;
constexpr int32_t ERR_INSTALL_RELEASETYPE_COMPATIBLE_NOT_SAME = 9568283;
constexpr int32_t ERR_INSTALL_SINGLETON_NOT_SAME = 9568291;
constexpr int32_t ERR_INSTALL_CHECK_SYSCAP_FAILED = 9568293;
constexpr int32_t ERR_INSTALL_APPTYPE_NOT_SAME = 9568294;
constexpr int32_t ERR_INSTALL_URI_DUPLICATE = 9568295;
constexpr int32_t ERR_INSTALL_VERSION_NOT_COMPATIBLE = 9568284;
constexpr int32_t ERR_INSTALL_APP_DISTRIBUTION_TYPE_NOT_SAME = 9568285;
constexpr int32_t ERR_INSTALL_APP_PROVISION_TYPE_NOT_SAME = 9568286;
constexpr int32_t ERR_INSTALL_SO_INCOMPATIBLE = 9568298;
constexpr int32_t ERR_INSTALL_AN_INCOMPATIBLE = 9568299;
constexpr int32_t ERR_INSTALL_TYPE_ERROR = 9568296;
constexpr int32_t ERR_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME = 9568300;
constexpr int32_t ERR_INSTALL_INCONSISTENT_MODULE_NAME = 9568301;
constexpr int32_t ERR_INSTALL_INVALID_NUMBER_OF_ENTRY_HAP = 9568287;
constexpr int32_t ERR_INSTALL_ASAN_ENABLED_NOT_SAME = 9568306;
constexpr int32_t ERR_INSTALL_ASAN_ENABLED_NOT_SUPPORT = 9568307;
constexpr int32_t ERR_INSTALL_COMPATIBLE_POLICY_NOT_SAME = 9568310;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_NAME_NOT_SAME = 9568367;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_INTERNAL_EXTERNAL_OVERLAY_EXISTED_SIMULTANEOUSLY = 9568368;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_TARGET_PRIORITY_NOT_SAME = 9568369;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_INCONSISTENT_VERSION_CODE = 9568371;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_BUNDLE_NAME_SAME_WITH_TARGET_BUNDLE_NAME = 9568373;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_OVERLAY_TYPE_NOT_SAME = 9568378;
constexpr int32_t ERR_INSTALL_FAILED_DEBUG_NOT_SAME = 9568336;
constexpr int32_t ERR_INSTALL_GWP_ASAN_ENABLED_NOT_SAME = 9568400;
constexpr int32_t ERR_INSTALL_DISK_MEM_INSUFFICIENT = 9568288;
constexpr int32_t ERR_INSTALL_VERSION_DOWNGRADE = 9568263;
constexpr int32_t ERR_INSTALL_DEPENDENT_MODULE_NOT_EXIST = 9568305;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_NO_SYSTEM_APPLICATION_FOR_EXTERNAL_OVERLAY = 9568374;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_IS_OVERLAY_BUNDLE = 9568376;
constexpr int32_t ERR_OVERLAY_INSTALLATION_FAILED_TARGET_MODULE_IS_OVERLAY_MODULE = 9568377;
constexpr int32_t ERR_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED = 9568309;
constexpr int32_t ERR_INSTALL_FILE_IS_SHARED_LIBRARY = 9568314;
constexpr int32_t ERR_INSTALL_DISALLOWED = 9568303;
constexpr int32_t ERR_INSATLL_CHECK_PROXY_DATA_URI_FAILED = 9568315;
constexpr int32_t ERR_INSATLL_CHECK_PROXY_DATA_PERMISSION_FAILED = 9568316;
constexpr int32_t ERR_INSTALL_ISOLATION_MODE_FAILED = 9568317;
constexpr int32_t ERR_INSTALL_ALREADY_EXIST = 9568276;
constexpr int32_t ERR_INSTALL_CODE_SIGNATURE_FAILED = 9568393;
constexpr int32_t ERR_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID = 9568394;
constexpr int32_t ERR_INSTALL_CHECK_ENCRYPTION_FAILED = 9568403;
constexpr int32_t ERR_INSTALL_CODE_SIGNATURE_DELIVERY_FILE_FAILED = 9568404;
constexpr int32_t ERR_INSTALL_CODE_SIGNATURE_REMOVE_FILE_FAILED = 9568405;
constexpr int32_t ERR_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED = 9568398;

constexpr int32_t ERROR_INVALID_USER_ID = 17700004;
constexpr int32_t ERROR_INSTALL_PARSE_FAILED_JS = 17700010;
constexpr int32_t ERROR_INSTALL_VERIFY_SIGNATURE_FAILED = 17700011;
constexpr int32_t ERROR_INSTALL_HAP_FILEPATH_INVALID = 17700012;
constexpr int32_t ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT = 17700015;
constexpr int32_t ERROR_INSTALL_NO_DISK_SPACE_LEFT = 17700016;
constexpr int32_t ERROR_INSTALL_VERSION_DOWNGRADE_JS = 17700017;
constexpr int32_t ERROR_INSTALL_DEPENDENT_MODULE_NOT_EXIST_JS = 17700018;
constexpr int32_t ERROR_INSTALL_HAP_OVERLAY_CHECK_FAILED = 17700031;
constexpr int32_t ERROR_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED_JS = 17700036;
constexpr int32_t ERROR_INSTALL_FILE_IS_SHARED_LIBRARY_JS = 17700039;
constexpr int32_t ERROR_DISALLOW_INSTALL = 17700041;
constexpr int32_t ERROR_INSTALL_WRONG_DATA_PROXY_URI = 17700042;
constexpr int32_t ERROR_INSTALL_WRONG_DATA_PROXY_PERMISSION = 17700043;
constexpr int32_t ERROR_INSTALL_WRONG_MODE_ISOLATION = 17700044;
constexpr int32_t ERROR_INSTALL_ALREADY_EXIST_JS = 17700047;
constexpr int32_t ERROR_INSTALL_CODE_SIGNATURE_FAILED_JS = 17700048;
constexpr int32_t ERROR_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED_JS = 17700050;

static const std::unordered_map<uint32_t, uint32_t> STREAM_INSTALL_TO_JS_INSTALL_MAP = {
    { ERR_USER_NOT_EXIST,
        ERROR_INVALID_USER_ID },
    { ERR_INSTALL_PARSE_FAILED,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_UNEXPECTED,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_MISSING_BUNDLE,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_NO_PROFILE,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_BAD_PROFILE,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_PROFILE_PROP_TYPE_ERROR,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_PROFILE_MISSING_PROP,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_PERMISSION_ERROR,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_PROFILE_PROP_CHECK_ERROR,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_RPCID_FAILED,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_NATIVE_SO_FAILED,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_AN_FAILED,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_MISSING_ABILITY,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_FAILED_PROFILE_PARSE_FAIL,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_BUNDLE_TYPE_NOT_SAME,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_DEVICE_TYPE_NOT_SUPPORTED,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_CHECK_SYSCAP_FAILED_AND_DEVICE_TYPE_NOT_SUPPORTED,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_NAME_MISSED,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_OVERLAY_INSTALLATION_FAILED_TARGET_MODULE_NAME_MISSED,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_OVERLAY_INSTALLATION_FAILED_INVALID_PRIORITY,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_DEBUG_ENCRYPTED_BUNDLE_FAILED,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_CHECK_BIN_FILE_FAILED,
        ERROR_INSTALL_PARSE_FAILED_JS },
    { ERR_INSTALL_VERIFICATION_FAILED, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_INVALID_SIGNATURE_FILE_PATH, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE_FILE, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_NO_BUNDLE_SIGNATURE, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_VERIFY_APP_PKCS7_FAIL, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_APP_SOURCE_NOT_TRUESTED, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_BAD_DIGEST, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_BUNDLE_INTEGRITY_VERIFICATION_FAILURE,
        ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_BAD_PUBLICKEY, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_NO_PROFILE_BLOCK_FAIL, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE,
        ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_VERIFY_SOURCE_INIT_FAIL, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_FAILED_DEVICE_UNAUTHORIZED, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_SINGLETON_INCOMPATIBLE, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_U1_ENABLE_NOT_SAME_IN_ALL_BUNDLE_INFOS, ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_OVERLAY_INSTALLATION_FAILED_DIFFERENT_SIGNATURE_CERTIFICATE,
        ERROR_INSTALL_VERIFY_SIGNATURE_FAILED },
    { ERR_INSTALL_INVALID_BUNDLE_FILE, ERROR_INSTALL_HAP_FILEPATH_INVALID },
    { ERR_INSTALL_FILE_PATH_INVALID, ERROR_INSTALL_HAP_FILEPATH_INVALID },
    { ERR_INSTALL_ENTRY_ALREADY_EXIST, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_BUNDLENAME_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_VERSIONCODE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_VERSIONNAME_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_MINCOMPATIBLE_VERSIONCODE_NOT_SAME,
        ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_VENDOR_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_RELEASETYPE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_RELEASETYPE_TARGET_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_RELEASETYPE_COMPATIBLE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_SINGLETON_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_CHECK_SYSCAP_FAILED, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_APPTYPE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_URI_DUPLICATE, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_VERSION_NOT_COMPATIBLE, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_APP_DISTRIBUTION_TYPE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_APP_PROVISION_TYPE_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_SO_INCOMPATIBLE, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_AN_INCOMPATIBLE, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_TYPE_ERROR, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_INCONSISTENT_MODULE_NAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_INVALID_NUMBER_OF_ENTRY_HAP, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_ASAN_ENABLED_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_ASAN_ENABLED_NOT_SUPPORT, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_COMPATIBLE_POLICY_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_NAME_NOT_SAME,
        ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_OVERLAY_INSTALLATION_FAILED_INTERNAL_EXTERNAL_OVERLAY_EXISTED_SIMULTANEOUSLY,
        ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_OVERLAY_INSTALLATION_FAILED_TARGET_PRIORITY_NOT_SAME,
        ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_OVERLAY_INSTALLATION_FAILED_INCONSISTENT_VERSION_CODE,
        ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_OVERLAY_INSTALLATION_FAILED_BUNDLE_NAME_SAME_WITH_TARGET_BUNDLE_NAME,
        ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_OVERLAY_INSTALLATION_FAILED_OVERLAY_TYPE_NOT_SAME,
        ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_FAILED_DEBUG_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_GWP_ASAN_ENABLED_NOT_SAME, ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT },
    { ERR_INSTALL_DISK_MEM_INSUFFICIENT, ERROR_INSTALL_NO_DISK_SPACE_LEFT },
    { ERR_INSTALL_VERSION_DOWNGRADE, ERROR_INSTALL_VERSION_DOWNGRADE_JS },
    { ERR_INSTALL_DEPENDENT_MODULE_NOT_EXIST, ERROR_INSTALL_DEPENDENT_MODULE_NOT_EXIST_JS },
    { ERR_OVERLAY_INSTALLATION_FAILED_NO_SYSTEM_APPLICATION_FOR_EXTERNAL_OVERLAY,
        ERROR_INSTALL_HAP_OVERLAY_CHECK_FAILED },
    { ERR_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_IS_OVERLAY_BUNDLE,
        ERROR_INSTALL_HAP_OVERLAY_CHECK_FAILED },
    { ERR_OVERLAY_INSTALLATION_FAILED_TARGET_MODULE_IS_OVERLAY_MODULE,
        ERROR_INSTALL_HAP_OVERLAY_CHECK_FAILED },
    { ERR_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED, ERROR_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED_JS },
    { ERR_INSTALL_FILE_IS_SHARED_LIBRARY, ERROR_INSTALL_FILE_IS_SHARED_LIBRARY_JS },
    { ERR_INSTALL_DISALLOWED, ERROR_DISALLOW_INSTALL },
    { ERR_INSATLL_CHECK_PROXY_DATA_URI_FAILED,
        ERROR_INSTALL_WRONG_DATA_PROXY_URI },
    { ERR_INSATLL_CHECK_PROXY_DATA_PERMISSION_FAILED,
        ERROR_INSTALL_WRONG_DATA_PROXY_PERMISSION },
    { ERR_INSTALL_ISOLATION_MODE_FAILED, ERROR_INSTALL_WRONG_MODE_ISOLATION },
    { ERR_INSTALL_ALREADY_EXIST, ERROR_INSTALL_ALREADY_EXIST_JS },
    { ERR_INSTALL_CODE_SIGNATURE_FAILED, ERROR_INSTALL_CODE_SIGNATURE_FAILED_JS },
    { ERR_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID, ERROR_INSTALL_CODE_SIGNATURE_FAILED_JS },
    { ERR_INSTALL_CHECK_ENCRYPTION_FAILED, ERROR_INSTALL_CODE_SIGNATURE_FAILED_JS },
    { ERR_INSTALL_CODE_SIGNATURE_DELIVERY_FILE_FAILED, ERROR_INSTALL_CODE_SIGNATURE_FAILED_JS },
    { ERR_INSTALL_CODE_SIGNATURE_REMOVE_FILE_FAILED, ERROR_INSTALL_CODE_SIGNATURE_FAILED_JS },
    { ERR_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED, ERROR_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED_JS },

};

static const std::unordered_map<uint32_t, uint32_t> INSTALL_ERRCODE_CONVERT_MAP = {
    { ERROR_INVALID_USER_ID,
        EdmReturnErrCode::INSTALL_APP_USER_ID_NOT_FOUND },
    { ERROR_INSTALL_PARSE_FAILED_JS,
        EdmReturnErrCode::INSTALL_APP_PARSE_FAILED },
    { ERROR_INSTALL_VERIFY_SIGNATURE_FAILED,
        EdmReturnErrCode::INSTALL_APP_SIGNATURE_VERIFY_FAILED },
    { ERROR_INSTALL_HAP_FILEPATH_INVALID,
        EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE },
    { ERROR_INSTALL_MULTIPLE_HAP_INFO_INCONSISTENT,
        EdmReturnErrCode::INSTALL_APPS_CONFIGURATION_MISMATCH },
    { ERROR_INSTALL_NO_DISK_SPACE_LEFT,
        EdmReturnErrCode::INSTALL_APP_INSUFFICIENT_DISK_SPACE },
    { ERROR_INSTALL_VERSION_DOWNGRADE_JS,
        EdmReturnErrCode::INSTALL_APP_VERSION_TOO_EARLY },
    { ERROR_INSTALL_DEPENDENT_MODULE_NOT_EXIST_JS,
        EdmReturnErrCode::INSTALL_APP_DEPENDANT_MODULE_NOT_EXIST },
    { ERROR_INSTALL_HAP_OVERLAY_CHECK_FAILED,
        EdmReturnErrCode::INSTALL_APP_OVERLAY_CHECK_FAILED },
    { ERROR_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED_JS,
        EdmReturnErrCode::INSTALL_APP_MISSING_REQUIRED_PERMISSIONS_FOR_HSP },
    { ERROR_INSTALL_FILE_IS_SHARED_LIBRARY_JS,
        EdmReturnErrCode::INSTALL_APP_SHARED_LIBRARIES_NOT_ALLOWED },
    { ERROR_DISALLOW_INSTALL,
        EdmReturnErrCode::INSTALL_APP_ENTERPRISE_DISALLOWED },
    { ERROR_INSTALL_WRONG_DATA_PROXY_URI,
        EdmReturnErrCode::INSTALL_APP_URI_INCORRECT },
    { ERROR_INSTALL_WRONG_DATA_PROXY_PERMISSION,
        EdmReturnErrCode::INSTALL_APP_PERMISSION_CONFIGURATION_INCORRECT },
    { ERROR_INSTALL_WRONG_MODE_ISOLATION,
        EdmReturnErrCode::INSTALL_APP_ISOLATION_MODE_NOT_SUPPORTED },
    { ERROR_INSTALL_ALREADY_EXIST_JS,
        EdmReturnErrCode::INSTALL_APP_VERSION_CODE_NOT_GREATER },
    { ERROR_INSTALL_CODE_SIGNATURE_FAILED_JS,
        EdmReturnErrCode::INSTALL_APP_CODE_SIGNATURE_VERIFICATION_FAILURE },
    { ERROR_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED_JS,
        EdmReturnErrCode::INSTALL_APP_ENTERPRISE_DEVICE_VERIFICATION_FAILURE }
};

void InstallPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<InstallPlugin, InstallParam>> ptr)
{
    EDMLOGI("InstallPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::INSTALL, PolicyName::POLICY_INSTALL,
        EdmPermission::PERMISSION_ENTERPRISE_INSTALL_BUNDLE, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(InstallParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&InstallPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode InstallPlugin::CopyHapFile(int32_t inputFd, const std::string &hapFilePath, std::string &tempPath,
    MessageParcel &reply)
{
    // 保证优化前后，相同输入能返回相同错误码。修改前如果输入的hapFilePath以/结尾，抛APPLICATION_INSTALL_FAILED
    size_t pos = hapFilePath.find_last_of(SEPARATOR);
    if (pos == std::string::npos || pos == hapFilePath.size() - 1) {
        EDMLOGE("invalid hap file path");
        reply.WriteInt32(EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
        reply.WriteString("invalid hap file path");
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    std::string fileName = hapFilePath.substr(pos + 1);
    // PATH_MAX 4096
    // 保证优化前后，长度校验一致
    if (fileName.length() > (PATH_MAX - TEMP_DIR_LEN)) {
        EDMLOGE("fileName length is error");
        reply.WriteInt32(EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
        reply.WriteString("invalid hap file path");
        return EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE;
    }
    std::string prefix = GenerateUniqueFilePrefix();
    tempPath = std::string(EdmConstants::BundleManager::HAP_DIRECTORY) + SEPARATOR + prefix + fileName;
    if (!EdmUtils::TrustedExternalPath(tempPath)) {
        EDMLOGE("tempPath invalid");
        reply.WriteInt32(EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
        reply.WriteString("invalid hap file path");
        return EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE;
    }
    int32_t dupFd = dup(inputFd);
    if (dupFd < 0) {
        EDMLOGE("dup input fd failed");
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    fdsan_exchange_owner_tag(dupFd, 0, EdmConstants::LOG_DOMAINID);

    int32_t outputFd = open(tempPath.c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IROTH);
    if (outputFd < 0) {
        EDMLOGE("open temp hap file failed: %{public}s", tempPath.c_str());
        fdsan_close_with_tag(dupFd, EdmConstants::LOG_DOMAINID);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    fdsan_exchange_owner_tag(outputFd, 0, EdmConstants::LOG_DOMAINID);

    ErrCode ret = CopyFileContent(dupFd, outputFd, reply);
    fsync(outputFd);
    fdsan_close_with_tag(outputFd, EdmConstants::LOG_DOMAINID);
    fdsan_close_with_tag(dupFd, EdmConstants::LOG_DOMAINID);
    return ret;
}

ErrCode InstallPlugin::CopyFileContent(int32_t inputFd, int32_t outputFd, MessageParcel &reply)
{
    struct stat statBuff;
    if (fstat(inputFd, &statBuff) != 0) {
        EDMLOGE("fstat file failed");
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    if (statBuff.st_size > MAX_HAP_FILE_SIZE) {
        EDMLOGE("hap file too large, size: %{public}lld", static_cast<long long>(statBuff.st_size));
        reply.WriteInt32(EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
        reply.WriteString("hap file too large");
        return EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE;
    }

    off_t offset = 0;
    if (sendfile(outputFd, inputFd, &offset, statBuff.st_size) == -1) {
        EDMLOGE("sendfile failed");
        reply.WriteInt32(EdmReturnErrCode::APPLICATION_INSTALL_FAILED);
        return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
    }
    return ERR_OK;
}

bool InstallPlugin::CreateDirectory()
{
    if (!OHOS::ForceCreateDirectory(EdmConstants::BundleManager::HAP_DIRECTORY)) {
        EDMLOGE("mkdir %{public}s failed", EdmConstants::BundleManager::HAP_DIRECTORY);
        return false;
    }
    if (chown(EdmConstants::BundleManager::HAP_DIRECTORY, EDM_UID, EDM_GID) != 0) {
        EDMLOGE("fail to change %{public}s ownership", EdmConstants::BundleManager::HAP_DIRECTORY);
        return false;
    }
    mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (!OHOS::ChangeModeFile(EdmConstants::BundleManager::HAP_DIRECTORY, mode)) {
        EDMLOGE("change mode failed, temp install dir : %{public}s", EdmConstants::BundleManager::HAP_DIRECTORY);
        return false;
    }
    return true;
}

std::string InstallPlugin::GenerateUniqueFilePrefix()
{
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, RANDOM_NUM_MAX);
    return FILE_PREFIX + std::to_string(timestamp) + "_" + std::to_string(dis(gen)) + "_";
}

bool InstallPlugin::DeleteFiles(const std::vector<std::string> &files)
{
    bool res = true;
    for (auto const &file : files) {
        if (!OHOS::RemoveFile(file)) {
            EDMLOGW("can not remove file : %{public}s", file.c_str());
            res = false;
        }
    }
    return res;
}

ErrCode InstallPlugin::OnSetPolicy(InstallParam &param, MessageParcel &reply)
{
    EDMLOGI("InstallPlugin OnSetPolicy");
    std::vector<std::string> tempPaths;
    ErrCode ret = PrepareTempFiles(param, tempPaths, reply);
    if (ret != ERR_OK) {
        return ret;
    }
    return ExecuteStreamInstall(tempPaths, param, reply);
}

ErrCode InstallPlugin::PrepareTempFiles(const InstallParam &param, std::vector<std::string> &tempPaths,
    MessageParcel &reply)
{
    if (!CreateDirectory()) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (param.hapFilePaths.size() != param.hapFds.size()) {
        EDMLOGE("hapFilePaths size not match hapFds size");
        for (auto const &fd : param.hapFds) {
            fdsan_exchange_owner_tag(fd, 0, EdmConstants::LOG_DOMAINID);
            fdsan_close_with_tag(fd, EdmConstants::LOG_DOMAINID);
        }
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    for (size_t i = 0; i < param.hapFds.size(); ++i) {
        std::string tempPath;
        ErrCode copyRet = CopyHapFile(param.hapFds[i], param.hapFilePaths[i], tempPath, reply);
        fdsan_exchange_owner_tag(param.hapFds[i], 0, EdmConstants::LOG_DOMAINID);
        fdsan_close_with_tag(param.hapFds[i], EdmConstants::LOG_DOMAINID);
        if (copyRet != ERR_OK) {
            for (size_t j = i + 1; j < param.hapFds.size(); ++j) {
                fdsan_exchange_owner_tag(param.hapFds[j], 0, EdmConstants::LOG_DOMAINID);
                fdsan_close_with_tag(param.hapFds[j], EdmConstants::LOG_DOMAINID);
            }
            DeleteFiles(tempPaths);
            return copyRet;
        }
        tempPaths.emplace_back(tempPath);
    }
    return ERR_OK;
}

ErrCode InstallPlugin::ExecuteStreamInstall(const std::vector<std::string> &tempPaths, const InstallParam &param,
    MessageParcel &reply)
{
    AppExecFwk::InstallParam installParam;
    installParam.userId = param.userId;
    installParam.installFlag = static_cast<AppExecFwk::InstallFlag>(param.installFlag);
    installParam.parameters = param.parameters;

    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    auto iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        EDMLOGE("can not get iBundleMgr");
        DeleteFiles(tempPaths);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        EDMLOGE("can not get iBundleInstaller");
        DeleteFiles(tempPaths);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    if (callback == nullptr) {
        DeleteFiles(tempPaths);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    ErrCode ret = iBundleInstaller->StreamInstall(tempPaths, installParam, callback);
    if (FAILED(ret)) {
        if (!DeleteFiles(tempPaths)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        EDMLOGE("StreamInstall resultCode %{public}d", ret);
        reply.WriteInt32(EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE);
        reply.WriteString("invalid hap file path");
        return EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE;
    }
    ret = callback->GetResultCode();
    std::string errorMessage = callback->GetResultMsg();
    return HandleInstallResult(ret, errorMessage, reply, tempPaths);
}

ErrCode InstallPlugin::HandleInstallResult(int32_t resultCode, const std::string &errorMessage, MessageParcel &reply,
    std::vector<std::string> realPaths)
{
    EDMLOGI("StreamInstall resultCode %{public}d resultMsg %{public}s.", resultCode, errorMessage.c_str());

    std::string adminName;
    std::string bundleName;
    InstalledBundleType bundleType = InstalledBundleType::NORMAL;
    if (resultCode == ERR_OK && !realPaths.empty()) {
        if (!GetCallingBundleName(adminName)) {
            EDMLOGW("InstallPlugin::HandleInstallResult failed: get admin bundleName fail.");
        }
        if (GetBundleInfoAndType(realPaths[0], bundleName, bundleType)) {
            EDMLOGI("InstallPlugin parsed bundle %{public}s with type %{public}d",
                bundleName.c_str(), static_cast<int32_t>(bundleType));
        }
    }

    if (!DeleteFiles(realPaths)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (resultCode != ERR_OK) {
        auto convertedResultCode = EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
        if (STREAM_INSTALL_TO_JS_INSTALL_MAP.find(resultCode) != STREAM_INSTALL_TO_JS_INSTALL_MAP.end()) {
            auto errCodeBMS = STREAM_INSTALL_TO_JS_INSTALL_MAP.at(resultCode);
            if (INSTALL_ERRCODE_CONVERT_MAP.find(errCodeBMS) != INSTALL_ERRCODE_CONVERT_MAP.end()) {
                convertedResultCode = INSTALL_ERRCODE_CONVERT_MAP.at(errCodeBMS);
                EDMLOGI("errCodeBMS:%{public}d convertedResultCode:%{public}d.", errCodeBMS, convertedResultCode);
            }
        } else {
            EDMLOGE("STREAM_INSTALL_TO_JS_INSTALL_MAP can not find resultCode:%{public}d.", resultCode);
        }
        reply.WriteInt32(convertedResultCode);
        reply.WriteString(errorMessage);
        return convertedResultCode;
    }
    EDMLOGI("InstallPlugin OnSetPolicy end");

    if (!adminName.empty() && !bundleName.empty()) {
        InstalledBundleInfoUtil::GetInstance()->AddInstalledBundleInfo(
            adminName, bundleName, bundleType);
    }

    return ERR_OK;
}

bool InstallPlugin::GetCallingBundleName(std::string &bundleName)
{
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    int uid = IPCSkeleton::GetCallingUid();
    if (bundleMgr->GetNameForUid(uid, bundleName) != ERR_OK || bundleName.empty()) {
        EDMLOGW("InstallPlugin::GetCallingBundleName fail.");
        return false;
    }
    return true;
}

bool InstallPlugin::GetBundleInfoAndType(const std::string &hapFilePath, std::string &bundleName,
    InstalledBundleType &installedBundleType)
{
    auto bundleMgr = std::make_shared<EdmBundleManagerImpl>();
    AppExecFwk::BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(
        static_cast<uint32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<uint32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO));
    if (!bundleMgr->GetBundleArchiveInfoV9(hapFilePath, flags, bundleInfo)) {
        EDMLOGW("InstallPlugin::GetBundleInfoAndType failed: get bundleInfo fail.");
        return false;
    }
    bundleName = bundleInfo.name;
    std::string appDistributionType = bundleInfo.applicationInfo.appDistributionType;
    if (appDistributionType == "app_gallery") {
        installedBundleType = InstalledBundleType::AG;
    } else if (appDistributionType == "enterprise_normal") {
        installedBundleType = InstalledBundleType::NORMAL;
    } else if (appDistributionType == "enterprise_mdm") {
        installedBundleType = InstalledBundleType::MDM;
    } else {
        EDMLOGW("InstallPlugin::GetBundleInfoAndType unknown appDistributionType %{public}s",
            appDistributionType.c_str());
        return false;
    }
    return true;
}

} // namespace EDM
} // namespace OHOS
