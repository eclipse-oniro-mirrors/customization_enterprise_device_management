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

#include "backup_error_mapper.h"

namespace OHOS {
namespace EDM {

uint32_t BackupErrorMapper::ToBackupResultCode(ErrCode internal)
{
    switch (internal) {
        case ERR_OK:
            return 0;
        case static_cast<ErrCode>(EdmReturnErrCode::PARAM_ERROR):
        case static_cast<ErrCode>(EdmReturnErrCode::INTERFACE_UNSUPPORTED):
        case static_cast<ErrCode>(EdmReturnErrCode::COMPONENT_INVALID):
        case static_cast<ErrCode>(EdmReturnErrCode::SYSTEM_ABNORMALLY):
        case static_cast<ErrCode>(EdmReturnErrCode::NOT_ENTERPRISE_DEVICE):
        case static_cast<ErrCode>(EdmReturnErrCode::BACKUP_SDA_OCCUPIED):
        case static_cast<ErrCode>(EdmReturnErrCode::BACKUP_APP_NOT_INSTALLED):
        case static_cast<ErrCode>(EdmReturnErrCode::BACKUP_ADMIN_STATE_INCONSISTENT):
        case static_cast<ErrCode>(EdmReturnErrCode::BACKUP_ADMIN_COUNT_EXCEEDED):
        case static_cast<ErrCode>(EdmReturnErrCode::BACKUP_PARTIAL_FAILED):
        case static_cast<ErrCode>(EdmReturnErrCode::AP_BACKUP_FORMAT_ERROR):
        case static_cast<ErrCode>(EdmReturnErrCode::AP_BACKUP_CERT_CHAIN_INVALID):
        case static_cast<ErrCode>(EdmReturnErrCode::AP_BACKUP_APPLICATION_ID_MISMATCH):
        case static_cast<ErrCode>(EdmReturnErrCode::AP_BACKUP_SIGNATURE_INVALID):
        case static_cast<ErrCode>(EdmReturnErrCode::AP_BACKUP_PAYLOAD_INVALID):
        case static_cast<ErrCode>(EdmReturnErrCode::AP_BACKUP_DEVICE_IDENTITY_MISMATCH):
        case static_cast<ErrCode>(EdmReturnErrCode::AP_BACKUP_CALLER_NOT_AUTHORIZED):
        case static_cast<ErrCode>(EdmReturnErrCode::AP_BACKUP_INTERNAL_ERROR):
            return static_cast<uint32_t>(internal);
        case ERR_EDM_BMS_ERROR:
        case ERR_EDM_GET_PERMISSION_REQ_FAILED:
        case ERR_EDM_SA_LOAD_FAILED:
            return EdmReturnErrCode::COMPONENT_INVALID;
        case ERR_EDM_PARAM_ERROR:
        case ERR_EDM_POLICY_PARSE_JSON_FAILED:
            return EdmReturnErrCode::PARAM_ERROR;
        default:
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
}

uint32_t BackupErrorMapper::PassThroughApCode(int32_t apCode)
{
    switch (apCode) {
        case 0:
        case static_cast<int32_t>(EdmReturnErrCode::AP_BACKUP_FORMAT_ERROR):
        case static_cast<int32_t>(EdmReturnErrCode::AP_BACKUP_CERT_CHAIN_INVALID):
        case static_cast<int32_t>(EdmReturnErrCode::AP_BACKUP_APPLICATION_ID_MISMATCH):
        case static_cast<int32_t>(EdmReturnErrCode::AP_BACKUP_SIGNATURE_INVALID):
        case static_cast<int32_t>(EdmReturnErrCode::AP_BACKUP_PAYLOAD_INVALID):
        case static_cast<int32_t>(EdmReturnErrCode::AP_BACKUP_DEVICE_IDENTITY_MISMATCH):
        case static_cast<int32_t>(EdmReturnErrCode::AP_BACKUP_CALLER_NOT_AUTHORIZED):
        case static_cast<int32_t>(EdmReturnErrCode::AP_BACKUP_INTERNAL_ERROR):
            return static_cast<uint32_t>(apCode);
        default:
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
}

std::string BackupErrorMapper::GetErrorMessage(uint32_t resultCode)
{
    switch (resultCode) {
        case 0:
            return "Success.";
        case EdmReturnErrCode::PARAM_ERROR:
            return "Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; "
                   "2. Incorrect parameter types; 3. Parameter verification failed.";
        case EdmReturnErrCode::INTERFACE_UNSUPPORTED:
            return "Capability not supported. Failed to call the API due to limited device capabilities.";
        case EdmReturnErrCode::COMPONENT_INVALID:
            return "The administrator ability component is invalid.";
        case EdmReturnErrCode::SYSTEM_ABNORMALLY:
            return "The system ability works abnormally.";
        case EdmReturnErrCode::NOT_ENTERPRISE_DEVICE:
            return "This device is not an enterprise device.";
        case EdmReturnErrCode::BACKUP_SDA_OCCUPIED:
            return "The super device administrator is occupied by another application.";
        case EdmReturnErrCode::BACKUP_APP_NOT_INSTALLED:
            return "The application is not installed.";
        case EdmReturnErrCode::BACKUP_ADMIN_STATE_INCONSISTENT:
            return "The activation state of the application is inconsistent with the backup.";
        case EdmReturnErrCode::BACKUP_ADMIN_COUNT_EXCEEDED:
            return "The number of device administrators has reached the limit.";
        case EdmReturnErrCode::BACKUP_PARTIAL_FAILED:
            return "Some device administrators failed to restore.";
        case EdmReturnErrCode::EXECUTE_TIME_OUT:
            return "The operation timed out.";
        case EdmReturnErrCode::AP_BACKUP_FORMAT_ERROR:
        case EdmReturnErrCode::AP_BACKUP_CERT_CHAIN_INVALID:
        case EdmReturnErrCode::AP_BACKUP_APPLICATION_ID_MISMATCH:
        case EdmReturnErrCode::AP_BACKUP_SIGNATURE_INVALID:
        case EdmReturnErrCode::AP_BACKUP_PAYLOAD_INVALID:
        case EdmReturnErrCode::AP_BACKUP_DEVICE_IDENTITY_MISMATCH:
        case EdmReturnErrCode::AP_BACKUP_CALLER_NOT_AUTHORIZED:
        case EdmReturnErrCode::AP_BACKUP_INTERNAL_ERROR:
            return "Backup data verification failed.";
        default:
            return "Unknown error.";
    }
}

} // namespace EDM
} // namespace OHOS
