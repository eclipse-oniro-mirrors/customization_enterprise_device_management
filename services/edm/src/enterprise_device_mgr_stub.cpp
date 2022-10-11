/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
EnterpriseDeviceMgrStub::EnterpriseDeviceMgrStub()
{
    AddCallFuncMap();
    EDMLOGI("EnterpriseDeviceMgrStub()");
}

EnterpriseDeviceMgrStub::~EnterpriseDeviceMgrStub()
{
    EDMLOGI("~EnterpriseDeviceMgrStub()");
}

void EnterpriseDeviceMgrStub::AddCallFuncMap()
{
    memberFuncMap_[ADD_DEVICE_ADMIN] = &EnterpriseDeviceMgrStub::EnableAdminInner;
    memberFuncMap_[REMOVE_DEVICE_ADMIN] = &EnterpriseDeviceMgrStub::DisableAdminInner;
    memberFuncMap_[REMOVE_SUPER_ADMIN] = &EnterpriseDeviceMgrStub::DisableSuperAdminInner;
    memberFuncMap_[GET_ENABLED_ADMIN] = &EnterpriseDeviceMgrStub::GetEnabledAdminInner;
    memberFuncMap_[GET_ENT_INFO] = &EnterpriseDeviceMgrStub::GetEnterpriseInfoInner;
    memberFuncMap_[SET_ENT_INFO] =  &EnterpriseDeviceMgrStub::SetEnterpriseInfoInner;
    memberFuncMap_[IS_SUPER_ADMIN] =  &EnterpriseDeviceMgrStub::IsSuperAdminInner;
    memberFuncMap_[IS_ADMIN_ENABLED] =  &EnterpriseDeviceMgrStub::IsAdminEnabledInner;
    memberFuncMap_[SUBSCRIBE_MANAGED_EVENT] = &EnterpriseDeviceMgrStub::SubscribeManagedEventInner;
    memberFuncMap_[UNSUBSCRIBE_MANAGED_EVENT] = &EnterpriseDeviceMgrStub::UnsubscribeManagedEventInner;
}

int32_t EnterpriseDeviceMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::u16string descriptor = GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    EDMLOGI("EnterpriseDeviceMgrStub code %{public}u", code);
    if (descriptor != remoteDescriptor) {
        EDMLOGE("EnterpriseDeviceMgrStub code %{public}d client and service descriptors are inconsistent", code);
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (SERVICE_FLAG(code)) {
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
        if (FUNC_TO_OPERATE(code) == static_cast<int>(FuncOperateType::GET)) {
            EDMLOGD("GetDevicePolicyInner");
            return GetDevicePolicyInner(code, data, reply);
        } else {
            EDMLOGD("HandleDevicePolicyInner");
            return HandleDevicePolicyInner(code, data, reply);
        }
    } else {
        EDMLOGE("!POLICY_FLAG(code)");
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
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
    std::unique_ptr<EntInfo> entInfo(data.ReadParcelable<EntInfo>());
    uint32_t type = data.ReadUint32();
    int32_t userId = data.ReadInt32();
    ErrCode retCode = EnableAdmin(*admin, *entInfo, AdminType(type), userId);
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

ErrCode EnterpriseDeviceMgrStub::HandleDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        EDMLOGW("HandleDevicePolicyInner: ReadParcelable failed");
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return ERR_EDM_PARAM_ERROR;
    }
    ErrCode errCode = HandleDevicePolicy(code, *admin, data);
    reply.WriteInt32(errCode);
    return errCode;
}

ErrCode EnterpriseDeviceMgrStub::GetDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    AppExecFwk::ElementName *admin = nullptr;
    if (data.ReadInt32() != ERR_OK) {
        admin = AppExecFwk::ElementName::Unmarshalling(data);
    } else {
        admin = nullptr;
    }
    if (admin != nullptr) {
        EDMLOGD("GetDevicePolicyInner bundleName:: %{public}s : abilityName : %{public}s code : %{public}x",
            admin->GetBundleName().c_str(), admin->GetAbilityName().c_str(), code);
    }
    ErrCode retCode = GetDevicePolicy(code, admin, reply);
    delete admin;
    return retCode;
}

ErrCode EnterpriseDeviceMgrStub::GetEnabledAdminInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:GetEnabledAdmin");
    uint32_t type = AdminType::UNKNOWN;
    if (!data.ReadUint32(type)) {
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
    std::vector<std::u16string> writeArray;
    ArrayPolicyUtils::StringToU16String(enabledAdminList, writeArray);
    reply.WriteString16Vector(writeArray);
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
    reply.WriteInt32(ret);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::IsAdminEnabledInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:IsAdminEnabled");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    int32_t userId = data.ReadInt32();
    bool ret = IsAdminEnabled(*admin, userId);
    reply.WriteInt32(ret);
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
    std::unique_ptr<EntInfo> entInfo(data.ReadParcelable<EntInfo>());
    ErrCode ret = SetEnterpriseInfo(*admin, *entInfo);
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
} // namespace EDM
} // namespace OHOS