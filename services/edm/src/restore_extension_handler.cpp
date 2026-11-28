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

#include "restore_extension_handler.h"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "admin.h"
#include "admin_manager.h"
#include "admin_provisioning_proxy.h"
#include "admin_type.h"
#include "backup_error_mapper.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "enable_source.h"
#include "element_name.h"
#include "enterprise_device_mgr_ability.h"
#include "ent_info.h"
#include "external_manager_factory.h"
#include "iexternal_manager_factory.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {

namespace {
constexpr const char* PARAM_IS_ENTERPRISE_DEVICE = "const.edm.is_enterprise_device";
constexpr int32_t MAX_SDA_AND_DA_COUNT = 10;

const std::string RESULT_SUCCESS = "SUCCESS";
const std::string RESULT_FAILED = "FAILED";

std::shared_ptr<IEdmBundleManager> GetBundleMgr()
{
    auto factory = std::make_shared<ExternalManagerFactory>();
    return factory->CreateBundleManager();
}
} // namespace

RestoreExtensionHandler* RestoreExtensionHandler::GetInstance()
{
    static RestoreExtensionHandler instance;
    return &instance;
}

bool RestoreExtensionHandler::IsEnterpriseDevice()
{
    return system::GetBoolParameter(PARAM_IS_ENTERPRISE_DEVICE, false);
}

bool RestoreExtensionHandler::ValidateRestoreDevice(RestoreSummary &summary)
{
#ifdef FEATURE_PC_ONLY
    if (!IsEnterpriseDevice()) {
        EDMLOGE("OnRestore: not enterprise device, reject");
        summary.errorCode = EdmReturnErrCode::NOT_ENTERPRISE_DEVICE;
        summary.errorInfo = "not enterprise device";
        return false;
    }
    return true;
#else
    EDMLOGE("OnRestore: not pc device, reject");
    summary.errorCode = EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    summary.errorInfo = "only pc device supported";
    return false;
#endif
}

bool RestoreExtensionHandler::ReadAndVerify(int32_t fd, std::vector<AdminBackupItem> &admins,
    RestoreSummary &summary)
{
    std::vector<uint8_t> rawData;
    ErrCode readRet = AdminBackupDataCodec::GetInstance()->ReadAll(fd, rawData);
    if (FAILED(readRet)) {
        EDMLOGE("OnRestore: ReadAll failed, ret=%{public}d", readRet);
        summary.errorCode = EdmReturnErrCode::PARAM_ERROR;
        summary.errorInfo = "read backup file failed";
        return false;
    }

    if (!AdminProvisioningProxy::GetInstance()->VerifyApIdentity()) {
        EDMLOGE("OnRestore: verify ap identity failed");
        summary.errorCode = static_cast<int32_t>(EdmReturnErrCode::COMPONENT_INVALID);
        summary.errorInfo = BackupErrorMapper::GetErrorMessage(EdmReturnErrCode::COMPONENT_INVALID);
        return false;
    }

    ErrCode verifyRet = AdminProvisioningProxy::GetInstance()->RestoreVerify(rawData, admins);
    if (FAILED(verifyRet)) {
        EDMLOGE("OnRestore: RestoreVerify failed, ret=%{public}d", verifyRet);
        uint32_t resultCode = BackupErrorMapper::PassThroughApCode(verifyRet);
        summary.errorCode = static_cast<int32_t>(resultCode);
        summary.errorInfo = BackupErrorMapper::GetErrorMessage(resultCode);
        return false;
    }
    return true;
}

ErrCode RestoreExtensionHandler::OnRestore(MessageParcel &data, MessageParcel &reply)
{
    int32_t fd = data.ReadFileDescriptor();
    std::string restoreInfo = data.ReadString();
    (void)restoreInfo;

    RestoreSummary summary;
    if (!ValidateRestoreDevice(summary)) {
        WriteResult(reply, static_cast<uint32_t>(summary.errorCode), summary.errorInfo);
        return ERR_OK;
    }

    std::vector<AdminBackupItem> admins;
    if (!ReadAndVerify(fd, admins, summary)) {
        WriteResult(reply, static_cast<uint32_t>(summary.errorCode), summary.errorInfo);
        return ERR_OK;
    }

    if (admins.empty()) {
        EDMLOGW("OnRestore: no admin to restore");
        WriteResult(reply, summary);
        return ERR_OK;
    }

    std::unique_lock<std::shared_mutex> autoLock(EnterpriseDeviceMgrAbility::adminLock_);
    for (const auto &item : admins) {
        RestoreItem result = RestoreOneAdmin(item);
        if (result.result == RESULT_SUCCESS) {
            if (result.idempotent) {
                ++summary.duplicateCount;
            } else {
                ++summary.succeeded;
            }
        } else {
            ++summary.failed;
        }
        summary.details.push_back(std::move(result));
    }
    EDMLOGI("OnRestore done, succeeded=%{public}d, duplicate=%{public}d, failed=%{public}d",
        summary.succeeded, summary.duplicateCount, summary.failed);
    WriteResult(reply, summary);
    return ERR_OK;
}

bool RestoreExtensionHandler::CheckExistingAdmin(const AdminBackupItem &item, RestoreItem &outResult)
{
    outResult.bundleName = item.bundleName;
    outResult.expectType = AdminBackupDataCodec::AdminTypeToString(item.adminType);
    std::shared_ptr<Admin> exist = AdminManager::GetInstance()->GetAdminByPkgName(item.bundleName, item.userId);
    if (exist == nullptr) {
        return false; // not exist, caller continues
    }
    if (static_cast<int32_t>(exist->GetAdminType()) == item.adminType) {
        outResult.result = RESULT_SUCCESS;
        outResult.idempotent = true;
        return true;
    }
    EDMLOGW("RestoreOneAdmin: %{public}s state inconsistent", item.bundleName.c_str());
    outResult.result = RESULT_FAILED;
    outResult.errorCode = EdmReturnErrCode::BACKUP_ADMIN_STATE_INCONSISTENT;
    outResult.errorInfo = BackupErrorMapper::GetErrorMessage(EdmReturnErrCode::BACKUP_ADMIN_STATE_INCONSISTENT);
    return true;
}

bool RestoreExtensionHandler::CheckCapacityConstraints(const AdminBackupItem &item, RestoreItem &outResult)
{
    if (AdminManager::GetInstance()->GetSuperDeviceAdminAndDeviceAdminCount() >= MAX_SDA_AND_DA_COUNT) {
        EDMLOGW("RestoreOneAdmin: admin count exceeded, %{public}s", item.bundleName.c_str());
        outResult.result = RESULT_FAILED;
        outResult.errorCode = EdmReturnErrCode::BACKUP_ADMIN_COUNT_EXCEEDED;
        outResult.errorInfo = BackupErrorMapper::GetErrorMessage(EdmReturnErrCode::BACKUP_ADMIN_COUNT_EXCEEDED);
        return true;
    }
    if (item.adminType == static_cast<int32_t>(AdminType::ENT) &&
        AdminManager::GetInstance()->IsSuperAdminExist()) {
        EDMLOGW("RestoreOneAdmin: SDA occupied, %{public}s", item.bundleName.c_str());
        outResult.result = RESULT_FAILED;
        outResult.errorCode = EdmReturnErrCode::BACKUP_SDA_OCCUPIED;
        outResult.errorInfo = BackupErrorMapper::GetErrorMessage(EdmReturnErrCode::BACKUP_SDA_OCCUPIED);
        return true;
    }
    return false;
}

RestoreItem RestoreExtensionHandler::RestoreOneAdmin(const AdminBackupItem &item)
{
    RestoreItem result;
    result.bundleName = item.bundleName;
    result.expectType = AdminBackupDataCodec::AdminTypeToString(item.adminType);

    auto bundleMgr = GetBundleMgr();
    if (bundleMgr == nullptr) {
        EDMLOGE("RestoreOneAdmin: bundle mgr null, %{public}s", item.bundleName.c_str());
        result.result = RESULT_FAILED;
        result.errorCode = static_cast<int32_t>(BackupErrorMapper::ToBackupResultCode(
            EdmReturnErrCode::EXECUTE_TIME_OUT));
        result.errorInfo = BackupErrorMapper::GetErrorMessage(EdmReturnErrCode::EXECUTE_TIME_OUT);
        return result;
    }
    if (!bundleMgr->IsBundleInstalled(item.bundleName, item.userId)) {
        EDMLOGW("RestoreOneAdmin: %{public}s not installed", item.bundleName.c_str());
        result.result = RESULT_FAILED;
        result.errorCode = EdmReturnErrCode::BACKUP_APP_NOT_INSTALLED;
        result.errorInfo = BackupErrorMapper::GetErrorMessage(EdmReturnErrCode::BACKUP_APP_NOT_INSTALLED);
        return result;
    }

    if (CheckExistingAdmin(item, result)) {
        return result;
    }

    if (CheckCapacityConstraints(item, result)) {
        return result;
    }

    ErrCode enableRet = EnableAdminFromBackup(item);
    if (FAILED(enableRet)) {
        EDMLOGW("RestoreOneAdmin: EnableAdminFromBackup failed, %{public}s, ret=%{public}d",
            item.bundleName.c_str(), enableRet);
        uint32_t resultCode = BackupErrorMapper::ToBackupResultCode(enableRet);
        result.result = RESULT_FAILED;
        result.errorCode = static_cast<int32_t>(resultCode);
        result.errorInfo = BackupErrorMapper::GetErrorMessage(resultCode);
        return result;
    }
    result.result = RESULT_SUCCESS;
    return result;
}

ErrCode RestoreExtensionHandler::EnableAdminFromBackup(const AdminBackupItem &item)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(item.bundleName);
    admin.SetAbilityName(item.abilityName);
    EntInfo entInfo("", "");
    AdminType adminType = static_cast<AdminType>(item.adminType);
    EnableSource enableSource = static_cast<EnableSource>(item.enableSource);
    auto ability = EnterpriseDeviceMgrAbility::GetInstance();
    if (ability == nullptr) {
        EDMLOGE("EnableAdminFromBackup: EnterpriseDeviceMgrAbility null");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ability->EnableAdminFromBackup(admin, entInfo, adminType, item.userId, enableSource, item.isDebug);
}

void RestoreExtensionHandler::WriteResult(MessageParcel &reply, const RestoreSummary &summary)
{
    std::string json = AdminBackupDataCodec::GetInstance()->SerializeRestoreSummary(summary);
    reply.WriteString(json);
}

void RestoreExtensionHandler::WriteResult(MessageParcel &reply, uint32_t errorCode, const std::string &errorInfo)
{
    std::string json = AdminBackupDataCodec::GetInstance()->SerializeErrorResult(errorCode, errorInfo);
    reply.WriteString(json);
}

} // namespace EDM
} // namespace OHOS
