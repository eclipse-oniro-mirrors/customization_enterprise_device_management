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

#include "backup_extension_handler.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ctime>
#include <filesystem>
#include <random>
#include <set>
#include <string>

#include "admin.h"
#include "admin_backup_data_codec.h"
#include "admin_manager.h"
#include "admin_provisioning_proxy.h"
#include "backup_error_mapper.h"
#include "admin_type.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "parameters.h"
#include "enable_source.h"
#include "enterprise_device_mgr_ability.h"

namespace OHOS {
namespace EDM {

namespace {
constexpr const char* EDM_BACKUP_DIR = "/data/service/el1/public/edm/backup";
constexpr const char* EDM_BACKUP_FILE_PREFIX = "edm_backup_";
constexpr mode_t EDM_BACKUP_DIR_MODE = 0700;
} // namespace

BackupExtensionHandler* BackupExtensionHandler::GetInstance()
{
    static BackupExtensionHandler instance;
    return &instance;
}

ErrCode BackupExtensionHandler::EnsureBackupDir()
{
    if (std::filesystem::exists(EDM_BACKUP_DIR)) {
        return ERR_OK;
    }
    std::error_code ec;
    std::filesystem::create_directories(EDM_BACKUP_DIR, ec);
    if (ec) {
        EDMLOGE("EnsureBackupDir: create dir failed, %{public}s", ec.message().c_str());
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    if (chmod(EDM_BACKUP_DIR, EDM_BACKUP_DIR_MODE) != 0) {
        EDMLOGE("EnsureBackupDir: chmod dir failed, errno=%{public}d", errno);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}

ErrCode BackupExtensionHandler::WriteBackupData(const std::vector<uint8_t> &packedData, MessageParcel &reply,
    bool &fdWritten)
{
    fdWritten = false;
    ErrCode ret = EnsureBackupDir();
    if (FAILED(ret)) {
        return ret;
    }
    std::random_device rd;
    std::string filePath = std::string(EDM_BACKUP_DIR) + "/" + EDM_BACKUP_FILE_PREFIX +
        std::to_string(std::time(nullptr)) + "_" + std::to_string(getpid()) + "_" + std::to_string(rd());
    int32_t fd = open(filePath.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) {
        EDMLOGE("WriteBackupData: open failed, errno=%{public}d", errno);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    fdsan_exchange_owner_tag(fd, 0, EdmConstants::LOG_DOMAINID);
    ret = AdminBackupDataCodec::GetInstance()->WriteAll(fd, packedData);
    if (FAILED(ret)) {
        EDMLOGE("WriteBackupData: write failed");
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        EDMLOGE("WriteBackupData: lseek failed, errno=%{public}d", errno);
        if (SUCCEEDED(ret)) {
            ret = EdmReturnErrCode::EXECUTE_TIME_OUT;
        }
    }
    fdWritten = reply.WriteFileDescriptor(fd);
    if (!fdWritten) {
        ret = EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    fdsan_close_with_tag(fd, EdmConstants::LOG_DOMAINID);
    unlink(filePath.c_str());
    return ret;
}

void BackupExtensionHandler::CollectBackupAdmins(BackupPayload &payload)
{
    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> allAdmins;
    {
        std::shared_lock<std::shared_mutex> autoLock(EnterpriseDeviceMgrAbility::adminLock_);
        AdminManager::GetInstance()->GetAllAdmins(allAdmins);
    }
    payload.version = 1;
    payload.deviceId = system::GetParameter("const.product.sn", "");
    if (payload.deviceId.empty()) {
        EDMLOGW("CollectBackupAdmins: device sn is empty, use fallback");
        payload.deviceId = "unknown";
    }
    std::set<std::string> seenBundle;
    for (const auto &pair : allAdmins) {
        for (const auto &admin : pair.second) {
            if (admin == nullptr || admin->adminInfo_.packageName_.empty()) {
                continue;
            }
            if (seenBundle.count(admin->adminInfo_.packageName_) > 0) {
                continue;
            }
            seenBundle.insert(admin->adminInfo_.packageName_);
            AdminBackupItem item;
            item.bundleName = admin->adminInfo_.packageName_;
            item.abilityName = admin->adminInfo_.className_;
            item.userId = pair.first;
            item.adminType = static_cast<int32_t>(admin->adminInfo_.adminType_);
            item.enableSource = static_cast<int32_t>(admin->adminInfo_.enableSource_);
            item.isDebug = admin->adminInfo_.isDebug_;
            payload.admins.push_back(std::move(item));
        }
    }
}

void BackupExtensionHandler::ReplyBackupResult(MessageParcel &reply, uint32_t errorCode, int32_t successCount)
{
    BackupResult result{static_cast<int32_t>(errorCode), "", successCount};
    reply.WriteString(AdminBackupDataCodec::GetInstance()->SerializeBackupResult(result));
}

ErrCode BackupExtensionHandler::PrepareBackupData(const BackupPayload &payload, std::vector<uint8_t> &packedData)
{
    std::vector<uint8_t> adminBytes;
    if (!AdminBackupDataCodec::GetInstance()->Serialize(payload, adminBytes)) {
        EDMLOGE("PrepareBackupData: serialize failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    if (!AdminProvisioningProxy::GetInstance()->VerifyApIdentity()) {
        EDMLOGE("PrepareBackupData: verify ap identity failed");
        return EdmReturnErrCode::COMPONENT_INVALID;
    }
    ErrCode signRet = AdminProvisioningProxy::GetInstance()->BackupSign(adminBytes, packedData);
    if (FAILED(signRet)) {
        EDMLOGE("PrepareBackupData: BackupSign failed, ret=%{public}d", signRet);
        return static_cast<ErrCode>(BackupErrorMapper::PassThroughApCode(signRet));
    }
    return ERR_OK;
}

ErrCode BackupExtensionHandler::OnBackup(MessageParcel &data, MessageParcel &reply)
{
    std::string backupInfo = data.ReadString();
    (void)backupInfo;

    BackupPayload payload;
    CollectBackupAdmins(payload);

    ErrCode ret = ERR_OK;
    std::vector<uint8_t> packedData;
    if (payload.admins.empty()) {
        EDMLOGW("OnBackup: no activated admin, nothing to backup");
    } else {
        ret = PrepareBackupData(payload, packedData);
    }

    bool fdWritten = false;
    ErrCode writeRet = WriteBackupData(packedData, reply, fdWritten);
    if (FAILED(writeRet) || !fdWritten) {
        ReplyBackupResult(reply, EdmReturnErrCode::EXECUTE_TIME_OUT, 0);
    } else if (FAILED(ret)) {
        ReplyBackupResult(reply, BackupErrorMapper::ToBackupResultCode(ret), 0);
    } else {
        ReplyBackupResult(reply, 0, static_cast<int32_t>(payload.admins.size()));
        EDMLOGI("OnBackup success, admin count=%{public}zu", payload.admins.size());
    }
    return ERR_OK;
}

} // namespace EDM
} // namespace OHOS
