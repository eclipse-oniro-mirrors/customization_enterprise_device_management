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
#include <string>
#include "admin.h"
#include "ent_info.h"
#include "string_ex.h"

using namespace OHOS::HiviewDFX;

namespace OHOS {
namespace EDM {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, 0xD001E00, "EDM" };

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
    memberFuncMap_[ADD_DEVICE_ADMIN] = &EnterpriseDeviceMgrStub::ActiveAdminInner;
    memberFuncMap_[REMOVE_DEVICE_ADMIN] = &EnterpriseDeviceMgrStub::DeactiveAdminInner;
    memberFuncMap_[REMOVE_SUPER_ADMIN] = &EnterpriseDeviceMgrStub::DeactiveSuperAdminInner;
    memberFuncMap_[GET_ACTIVE_ADMIN] = &EnterpriseDeviceMgrStub::GetActiveAdminInner;
    memberFuncMap_[GET_ENT_INFO] = &EnterpriseDeviceMgrStub::GetEnterpriseInfoInner;
    memberFuncMap_[SET_ENT_INFO] =  &EnterpriseDeviceMgrStub::SetEnterpriseInfoInner;
    memberFuncMap_[IS_SUPER_ADMIN] =  &EnterpriseDeviceMgrStub::IsSuperAdminInner;
    memberFuncMap_[IS_ADMIN_ACTIVE] =  &EnterpriseDeviceMgrStub::IsAdminActiveInner;
}

int32_t EnterpriseDeviceMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::u16string descriptor = GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    HiLog::Info(LABEL, "EnterpriseDeviceMgrStub code %{public}d", code);
    if (descriptor != remoteDescriptor) {
        EDMLOGE("EnterpriseDeviceMgrStub code %{public}d client and service descriptors are inconsistent", code);
        reply.WriteInt32(ERR_EDM_PARAM_ERROR);
        return ERR_EDM_PARAM_ERROR;
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

ErrCode EnterpriseDeviceMgrStub::ActiveAdminInner(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(ERR_EDM_PARAM_ERROR);
        return ERR_EDM_PARAM_ERROR;
    }
    EDMLOGD("ActiveAdminInner bundleName:: %{public}s : abilityName : %{public}s ", admin->GetBundleName().c_str(),
        admin->GetAbilityName().c_str());
    std::unique_ptr<EntInfo> entInfo(data.ReadParcelable<EntInfo>());
    uint32_t type = data.ReadUint32();
    int32_t userId = data.ReadInt32();
    ErrCode retCode = ActiveAdmin(*admin, *entInfo, AdminType(type), userId);
    reply.WriteInt32(retCode);
    return (retCode != ERR_OK) ? ERR_EDM_ADD_ADMIN_FAILED : ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::DeactiveAdminInner(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    EDMLOGD("DeactiveAdminInner bundleName: %{public}s", admin->GetBundleName().c_str());
    if (!admin) {
        reply.WriteInt32(ERR_EDM_PARAM_ERROR);
        return ERR_EDM_PARAM_ERROR;
    }
    int32_t userId = data.ReadInt32();
    ErrCode retCode = DeactiveAdmin(*admin, userId);
    if (retCode != ERR_OK) {
        EDMLOGW("DeactiveAdminInner failed: %{public}d", retCode);
        reply.WriteInt32(ERR_EDM_DEL_ADMIN_FAILED);
        return ERR_EDM_DEL_ADMIN_FAILED;
    }
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::DeactiveSuperAdminInner(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    EDMLOGD("DeactiveSuperAdminInner bundleName:: %{public}s :", bundleName.c_str());
    ErrCode retCode = DeactiveSuperAdmin(bundleName);
    if (retCode != ERR_OK) {
        reply.WriteInt32(ERR_EDM_DEL_SUPER_ADMIN_FAILED);
        return ERR_EDM_DEL_SUPER_ADMIN_FAILED;
    }
    reply.WriteInt32(ERR_OK);
    return retCode;
}

ErrCode EnterpriseDeviceMgrStub::HandleDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        EDMLOGW("HandleDevicePolicyInner: ReadParcelable<Intent> failed");
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

ErrCode EnterpriseDeviceMgrStub::GetActiveAdminInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:GetActiveAdmin");
    uint32_t type = AdminType::UNKNOWN;
    if (!data.ReadUint32(type)) {
        reply.WriteInt32(ERR_EDM_PARAM_ERROR);
        EDMLOGE("EnterpriseDeviceMgrStub:GetActiveAdminInner read type fail %{public}d", type);
        return ERR_EDM_PARAM_ERROR;
    }
    std::vector<std::string> activeAdminList;
    ErrCode res = GetActiveAdmin((AdminType)type, activeAdminList);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrStub:GetActiveAdmin failed:%{public}d", res);
        reply.WriteInt32(res);
        return res;
    }
    reply.WriteInt32(ERR_OK);
    std::vector<std::u16string> writeArray;
    ArrayPolicyUtils::StringToU16String(activeAdminList, writeArray);
    reply.WriteString16Vector(writeArray);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::GetEnterpriseInfoInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:GetEnterpriseInfoInner");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(ERR_EDM_PARAM_ERROR);
        return ERR_EDM_PARAM_ERROR;
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

ErrCode EnterpriseDeviceMgrStub::IsAdminActiveInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:IsAdminActive");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(ERR_EDM_PARAM_ERROR);
        return ERR_EDM_PARAM_ERROR;
    }
    EDMLOGD("GetEnterpriseInfoInner bundleName:: %{public}s : abilityName : %{public}s ",
            admin->GetBundleName().c_str(), admin->GetAbilityName().c_str());
    bool ret = IsAdminActive(*admin);
    reply.WriteInt32(ret);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::SetEnterpriseInfoInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:SetEnterpriseInfoInner");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(ERR_EDM_PARAM_ERROR);
        return ERR_EDM_PARAM_ERROR;
    }
    std::unique_ptr<EntInfo> entInfo(data.ReadParcelable<EntInfo>());
    ErrCode code = SetEnterpriseInfo(*admin, *entInfo);
    if (code != ERR_OK) {
        EDMLOGW("EnterpriseDeviceMgrStub:SetEnterpriseInfoInner failed:%{public}d", code);
        reply.WriteInt32(ERR_EDM_SET_ENTINFO_FAILED);
        return code;
    }
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS