/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "enterprise_device_mgr_stub.h"

#include "admin.h"
#include "edm_constants.h"
#include "ent_info.h"
#include "string_ex.h"

using namespace OHOS::HiviewDFX;

namespace OHOS {
namespace EDM {
EnterpriseDeviceMgrStub::EnterpriseDeviceMgrStub() : EnterpriseDeviceMgrIdlStub(false)
{
    InitSystemCodeList();
    EDMLOGI("EnterpriseDeviceMgrStub()");
}

void EnterpriseDeviceMgrStub::InitSystemCodeList()
{
    systemCodeList = {
        EdmInterfaceCode::ADD_DEVICE_ADMIN,
        EdmInterfaceCode::REMOVE_SUPER_ADMIN,
        EdmInterfaceCode::GET_ENABLED_ADMIN,
        EdmInterfaceCode::GET_ENT_INFO,
        EdmInterfaceCode::SET_ENT_INFO,
        EdmInterfaceCode::IS_SUPER_ADMIN,
        EdmInterfaceCode::IS_ADMIN_ENABLED,
        EdmInterfaceCode::AUTHORIZE_ADMIN,
        EdmInterfaceCode::GET_SUPER_ADMIN_WANT_INFO,
        EdmInterfaceCode::GET_ADMINS,
        EdmInterfaceCode::REPLACE_SUPER_ADMIN,
        EdmInterfaceCode::SET_ADMIN_RUNNING_MODE,
        EdmInterfaceCode::SET_DELEGATED_POLICIES_OVERRIDE,
    };
}

#ifdef EDM_SUPPORT_ALL_ENABLE
ErrCode EnterpriseDeviceMgrStub::OnRemoteRequestIdl(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    EDMLOGI("EnterpriseDeviceMgrStub OnRemoteRequestIdl code %{public}u", code);
    if (std::find(systemCodeList.begin(), systemCodeList.end(), code) != systemCodeList.end() &&
        !PermissionChecker::GetInstance()->CheckIsSystemAppOrNative()) {
        EDMLOGE("EnterpriseDeviceMgrStub OnRemoteRequestIdl not system app or native process");
        return EdmReturnErrCode::SYSTEM_API_DENIED;
    }
    return EnterpriseDeviceMgrIdlStub::OnRemoteRequest(code, data, reply, option);
}
#endif

int32_t EnterpriseDeviceMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
#ifdef EDM_SUPPORT_ALL_ENABLE
    if (SERVICE_FLAG(code)) {
        return OnRemoteRequestIdl(code, data, reply, option);
    }
    std::u16string descriptor = GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    EDMLOGI("EnterpriseDeviceMgrStub code %{public}u", code);
    if (descriptor != remoteDescriptor) {
        EDMLOGE("EnterpriseDeviceMgrStub code %{public}d client and service descriptors are inconsistent", code);
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return ERR_OK;
    }
    if (POLICY_FLAG(code)) {
        EDMLOGD("POLICY_FLAG(code:%{public}x)\n", code);
        int32_t hasUserId = 0;
        int32_t userId = EdmConstants::DEFAULT_USER_ID;
        data.ReadInt32(hasUserId);
        if (hasUserId == 1) {
            data.ReadInt32(userId);
        }
        if (FUNC_TO_POLICY(code) == (std::uint32_t)EdmInterfaceCode::GET_ADMINPROVISION_INFO) {
            return CheckAndGetAdminProvisionInfoInner(code, data, reply, userId);
        }
        if (FUNC_TO_OPERATE(code) == static_cast<int>(FuncOperateType::GET)) {
            EDMLOGD("GetDevicePolicyInner");
            return GetDevicePolicyInner(code, data, reply, userId, hasUserId);
        } else {
            EDMLOGD("HandleDevicePolicyInner");
            return HandleDevicePolicyInner(code, data, reply, userId);
        }
    } else {
        EDMLOGE("!POLICY_FLAG(code)");
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
#else
    EDMLOGI("EnterpriseDeviceMgrStub edm unsupport.");
    reply.WriteInt32(EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    return ERR_OK;
#endif
}

std::shared_ptr<IExternalManagerFactory> EnterpriseDeviceMgrStub::GetExternalManagerFactory()
{
    return externalManagerFactory_;
}

ErrCode EnterpriseDeviceMgrStub::HandleDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        EDMLOGW("HandleDevicePolicyInner: ReadParcelable failed");
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return ERR_OK;
    }
    ErrCode errCode = HandleDevicePolicy(code, *admin, data, reply, userId);
    reply.WriteInt32(errCode);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::GetDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply,
    int32_t userId, int32_t hasUserId)
{
    ErrCode errCode = GetDevicePolicy(code, data, reply, userId, hasUserId);
    reply.WriteInt32(errCode);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::CheckAndGetAdminProvisionInfoInner(uint32_t code, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    uint32_t extInfoCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::GET, (uint32_t)EdmInterfaceCode::GET_EXT_INFO);
    ErrCode errCode = CheckAndGetAdminProvisionInfo(extInfoCode, data, reply, userId);
    reply.WriteInt32(errCode);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS