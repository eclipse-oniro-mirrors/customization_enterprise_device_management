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
#include "ent_info.h"
#include "string_ex.h"

using namespace OHOS::HiviewDFX;

namespace OHOS {
namespace EDM {
#ifdef EDM_SUPPORT_ALL_ENABLE
constexpr int32_t DEFAULT_USER_ID = 100;
#endif
EnterpriseDeviceMgrStub::EnterpriseDeviceMgrStub() : IRemoteStub(true)
{
    AddCallFuncMap();
    InitSystemCodeList();
    EDMLOGI("EnterpriseDeviceMgrStub()");
}

void EnterpriseDeviceMgrStub::AddCallFuncMap()
{
    memberFuncMap_[EdmInterfaceCode::ADD_DEVICE_ADMIN] = &EnterpriseDeviceMgrStub::EnableAdminInner;
    memberFuncMap_[EdmInterfaceCode::REMOVE_DEVICE_ADMIN] = &EnterpriseDeviceMgrStub::DisableAdminInner;
    memberFuncMap_[EdmInterfaceCode::REMOVE_SUPER_ADMIN] = &EnterpriseDeviceMgrStub::DisableSuperAdminInner;
    memberFuncMap_[EdmInterfaceCode::GET_ENABLED_ADMIN] = &EnterpriseDeviceMgrStub::GetEnabledAdminInner;
    memberFuncMap_[EdmInterfaceCode::GET_ENT_INFO] = &EnterpriseDeviceMgrStub::GetEnterpriseInfoInner;
    memberFuncMap_[EdmInterfaceCode::SET_ENT_INFO] = &EnterpriseDeviceMgrStub::SetEnterpriseInfoInner;
    memberFuncMap_[EdmInterfaceCode::IS_SUPER_ADMIN] = &EnterpriseDeviceMgrStub::IsSuperAdminInner;
    memberFuncMap_[EdmInterfaceCode::IS_ADMIN_ENABLED] = &EnterpriseDeviceMgrStub::IsAdminEnabledInner;
    memberFuncMap_[EdmInterfaceCode::SUBSCRIBE_MANAGED_EVENT] = &EnterpriseDeviceMgrStub::SubscribeManagedEventInner;
    memberFuncMap_[EdmInterfaceCode::UNSUBSCRIBE_MANAGED_EVENT] =
        &EnterpriseDeviceMgrStub::UnsubscribeManagedEventInner;
    memberFuncMap_[EdmInterfaceCode::AUTHORIZE_ADMIN] = &EnterpriseDeviceMgrStub::AuthorizeAdminInner;
    memberFuncMap_[EdmInterfaceCode::GET_SUPER_ADMIN_WANT_INFO] = &EnterpriseDeviceMgrStub::GetSuperAdminInner;
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
    };
}

int32_t EnterpriseDeviceMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
#ifdef EDM_SUPPORT_ALL_ENABLE
    std::u16string descriptor = GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    EDMLOGI("EnterpriseDeviceMgrStub code %{public}u", code);
    if (descriptor != remoteDescriptor) {
        EDMLOGE("EnterpriseDeviceMgrStub code %{public}d client and service descriptors are inconsistent", code);
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (SERVICE_FLAG(code)) {
        if (std::find(systemCodeList.begin(), systemCodeList.end(), code) != systemCodeList.end() &&
            !GetAccessTokenMgr()->IsSystemAppOrNative()) {
            EDMLOGE("EnterpriseDeviceMgrStub not system app or native process");
            reply.WriteInt32(EdmReturnErrCode::SYSTEM_API_DENIED);
            return EdmReturnErrCode::SYSTEM_API_DENIED;
        }
        auto func = memberFuncMap_.find(code);
        if (func != memberFuncMap_.end()) {
            auto memberFunc = func->second;
            if (memberFunc != nullptr) {
                return (this->*memberFunc)(data, reply);
            }
        }
    }
    if (POLICY_FLAG(code)) {
        EDMLOGD("POLICY_FLAG(code:%{public}x)\n", code);
        int32_t hasUserId;
        int32_t userId = DEFAULT_USER_ID;
        data.ReadInt32(hasUserId);
        if (hasUserId == 1) {
            data.ReadInt32(userId);
        }
        if (FUNC_TO_OPERATE(code) == static_cast<int>(FuncOperateType::GET)) {
            EDMLOGD("GetDevicePolicyInner");
            return GetDevicePolicyInner(code, data, reply, userId);
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
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}

std::shared_ptr<IExternalManagerFactory> EnterpriseDeviceMgrStub::GetExternalManagerFactory()
{
    return externalManagerFactory_;
}

std::shared_ptr<IEdmAccessTokenManager> EnterpriseDeviceMgrStub::GetAccessTokenMgr()
{
    return GetExternalManagerFactory()->CreateAccessTokenManager();
}

ErrCode EnterpriseDeviceMgrStub::EnableAdminInner(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    EDMLOGD("EnableAdminInner bundleName:: %{public}s : abilityName : %{public}s ", admin->GetBundleName().c_str(),
        admin->GetAbilityName().c_str());
    EntInfo entInfo;
    if (!EntInfo::Unmarshalling(data, entInfo)) {
        EDMLOGE("EnterpriseDeviceMgrStub::EnableAdminInner read parcel fail");
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    int32_t type = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    AdminType adminType = AdminType::UNKNOWN;
    if (type == static_cast<int32_t>(AdminType::NORMAL) || type == static_cast<int32_t>(AdminType::ENT)) {
        adminType = static_cast<AdminType>(type);
    }
    ErrCode retCode = EnableAdmin(*admin, entInfo, adminType, userId);
    reply.WriteInt32(retCode);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::DisableAdminInner(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    int32_t userId = data.ReadInt32();
    ErrCode retCode = DisableAdmin(*admin, userId);
    reply.WriteInt32(retCode);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::DisableSuperAdminInner(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    EDMLOGD("DisableSuperAdminInner bundleName:: %{public}s :", bundleName.c_str());
    ErrCode retCode = DisableSuperAdmin(bundleName);
    reply.WriteInt32(retCode);
    return retCode;
}

ErrCode EnterpriseDeviceMgrStub::HandleDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        EDMLOGW("HandleDevicePolicyInner: ReadParcelable failed");
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return ERR_EDM_PARAM_ERROR;
    }
    ErrCode errCode = HandleDevicePolicy(code, *admin, data, reply, userId);
    reply.WriteInt32(errCode);
    return errCode;
}

ErrCode EnterpriseDeviceMgrStub::GetDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return GetDevicePolicy(code, data, reply, userId);
}

ErrCode EnterpriseDeviceMgrStub::GetEnabledAdminInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:GetEnabledAdmin");
    int32_t type = static_cast<int32_t>(AdminType::UNKNOWN);
    if (!data.ReadInt32(type)) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        EDMLOGE("EnterpriseDeviceMgrStub:GetEnabledAdminInner read type fail %{public}u", type);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<std::string> enabledAdminList;
    ErrCode res = GetEnabledAdmin((AdminType)type, enabledAdminList);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrStub:GetEnabledAdmin failed:%{public}d", res);
        reply.WriteInt32(res);
        return res;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteStringVector(enabledAdminList);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::GetEnterpriseInfoInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:GetEnterpriseInfoInner");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    EDMLOGD("GetEnterpriseInfoInner bundleName:: %{public}s : abilityName : %{public}s ",
        admin->GetBundleName().c_str(), admin->GetAbilityName().c_str());

    return GetEnterpriseInfo(*admin, reply);
}

ErrCode EnterpriseDeviceMgrStub::IsSuperAdminInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:IsSuperAdminInner");
    std::string bundleName = data.ReadString();
    EDMLOGD("IsSuperAdminInner bundleName:: %{public}s :", bundleName.c_str());
    bool ret = IsSuperAdmin(bundleName);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(ret);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::IsAdminEnabledInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:IsAdminEnabled");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        EDMLOGE("EnterpriseDeviceMgrStub::IsAdminEnabledInner read parcel fail");
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    int32_t userId = data.ReadInt32();
    bool ret = IsAdminEnabled(*admin, userId);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(ret);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::SetEnterpriseInfoInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:SetEnterpriseInfoInner");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    EntInfo entInfo;
    if (!EntInfo::Unmarshalling(data, entInfo)) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    ErrCode ret = SetEnterpriseInfo(*admin, entInfo);
    reply.WriteInt32(ret);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::SubscribeManagedEventInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:SubscribeManagedEventInner");
    return SubscribeManagedEventInner(data, reply, true);
}

ErrCode EnterpriseDeviceMgrStub::UnsubscribeManagedEventInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:UnsubscribeManagedEventInner");
    return SubscribeManagedEventInner(data, reply, false);
}

ErrCode EnterpriseDeviceMgrStub::SubscribeManagedEventInner(MessageParcel &data, MessageParcel &reply, bool subscribe)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::vector<uint32_t> events;
    data.ReadUInt32Vector(&events);
    ErrCode code;
    if (subscribe) {
        code = SubscribeManagedEvent(*admin, events);
    } else {
        code = UnsubscribeManagedEvent(*admin, events);
    }
    reply.WriteInt32(code);
    return code;
}

ErrCode EnterpriseDeviceMgrStub::AuthorizeAdminInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:AuthorizeAdminInner.");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::string bundleName = data.ReadString();
    ErrCode ret = AuthorizeAdmin(*admin, bundleName);
    reply.WriteInt32(ret);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::GetSuperAdminInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:IsSuperAdminInner");
    ErrCode ret = GetSuperAdmin(reply);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(ret);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS