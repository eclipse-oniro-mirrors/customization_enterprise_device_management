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
#ifdef EDM_SUPPORT_ALL_ENABLE
constexpr int32_t WITHOUT_FUNCTION_CODE = -1;
#endif
EnterpriseDeviceMgrStub::EnterpriseDeviceMgrStub() : IRemoteStub(true)
{
    InitSystemCodeList();
    EDMLOGI("EnterpriseDeviceMgrStub()");
}

#ifdef EDM_SUPPORT_ALL_ENABLE
ErrCode EnterpriseDeviceMgrStub::CallFuncByCode(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    switch (code) {
        case EdmInterfaceCode::ADD_DEVICE_ADMIN:
            return EnableAdminInner(data, reply);
        case EdmInterfaceCode::REMOVE_DEVICE_ADMIN:
            return DisableAdminInner(data, reply);
        case EdmInterfaceCode::REMOVE_SUPER_ADMIN:
            return DisableSuperAdminInner(data, reply);
        case EdmInterfaceCode::GET_ENABLED_ADMIN:
            return GetEnabledAdminInner(data, reply);
        case EdmInterfaceCode::GET_ENT_INFO:
            return GetEnterpriseInfoInner(data, reply);
        case EdmInterfaceCode::SET_ENT_INFO:
            return SetEnterpriseInfoInner(data, reply);
        case EdmInterfaceCode::IS_SUPER_ADMIN:
            return IsSuperAdminInner(data, reply);
        case EdmInterfaceCode::IS_ADMIN_ENABLED:
            return IsAdminEnabledInner(data, reply);
        case EdmInterfaceCode::SUBSCRIBE_MANAGED_EVENT:
            return SubscribeManagedEventInner(data, reply);
        case EdmInterfaceCode::UNSUBSCRIBE_MANAGED_EVENT:
            return UnsubscribeManagedEventInner(data, reply);
        case EdmInterfaceCode::AUTHORIZE_ADMIN:
            return AuthorizeAdminInner(data, reply);
        case EdmInterfaceCode::GET_SUPER_ADMIN_WANT_INFO:
            return GetSuperAdminInner(data, reply);
        case EdmInterfaceCode::SET_DELEGATED_POLICIES:
            return SetDelegatedPoliciesInner(data, reply);
        case EdmInterfaceCode::GET_DELEGATED_POLICIES:
            return GetDelegatedPoliciesInner(data, reply);
        case EdmInterfaceCode::GET_DELEGATED_BUNDLE_NAMES:
            return GetDelegatedBundleNamesInner(data, reply);
        case EdmInterfaceCode::GET_ADMINS:
            return GetAdminsInner(data, reply);
        default:
            return WITHOUT_FUNCTION_CODE;
    }
}
#endif

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
        return ERR_OK;
    }
    if (SERVICE_FLAG(code)) {
        if (std::find(systemCodeList.begin(), systemCodeList.end(), code) != systemCodeList.end() &&
            !PermissionChecker::GetInstance()->CheckIsSystemAppOrNative()) {
            EDMLOGE("EnterpriseDeviceMgrStub not system app or native process");
            reply.WriteInt32(EdmReturnErrCode::SYSTEM_API_DENIED);
            return ERR_OK;
        }
        ErrCode ret = CallFuncByCode(code, data, reply);
        if (ret != WITHOUT_FUNCTION_CODE) {
            return ret;
        }
    }
    if (POLICY_FLAG(code)) {
        EDMLOGD("POLICY_FLAG(code:%{public}x)\n", code);
        int32_t hasUserId;
        int32_t userId = EdmConstants::DEFAULT_USER_ID;
        data.ReadInt32(hasUserId);
        if (hasUserId == 1) {
            data.ReadInt32(userId);
        }
        if (FUNC_TO_POLICY(code) == (std::uint32_t)EdmInterfaceCode::GET_ADMINPROVISION_INFO) {
            return GetAdminProvisionInfoInner(code, data, reply, userId);
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
    return ERR_OK;
#endif
}

std::shared_ptr<IExternalManagerFactory> EnterpriseDeviceMgrStub::GetExternalManagerFactory()
{
    return externalManagerFactory_;
}

ErrCode EnterpriseDeviceMgrStub::EnableAdminInner(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return ERR_OK;
    }
    EDMLOGD("EnableAdminInner bundleName:: %{public}s : abilityName : %{public}s ", admin->GetBundleName().c_str(),
        admin->GetAbilityName().c_str());
    EntInfo entInfo;
    if (!EntInfo::Unmarshalling(data, entInfo)) {
        EDMLOGE("EnterpriseDeviceMgrStub::EnableAdminInner read parcel fail");
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return ERR_OK;
    }
    int32_t type = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    AdminType adminType = AdminType::UNKNOWN;
    if (type != static_cast<int32_t>(AdminType::NORMAL) && type != static_cast<int32_t>(AdminType::ENT) &&
        type != static_cast<int32_t>(AdminType::BYOD)) {
        EDMLOGE("EnableAdminInner: admin type is invalid.");
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return ERR_OK;
    }
    adminType = static_cast<AdminType>(type);
    ErrCode retCode = EnableAdmin(*admin, entInfo, adminType, userId);
    reply.WriteInt32(retCode);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::DisableAdminInner(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return ERR_OK;
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
        return ERR_OK;
    }
    ErrCode errCode = HandleDevicePolicy(code, *admin, data, reply, userId);
    reply.WriteInt32(errCode);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::GetDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    ErrCode errCode = GetDevicePolicy(code, data, reply, userId);
    reply.WriteInt32(errCode);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::GetAdminProvisionInfoInner(uint32_t code, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    ErrCode errCode = GetAdminProvisionInfo(code, data, reply, userId);
    reply.WriteInt32(errCode);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::GetEnabledAdminInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:GetEnabledAdmin");
    int32_t type = static_cast<int32_t>(AdminType::UNKNOWN);
    if (!data.ReadInt32(type)) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        EDMLOGE("EnterpriseDeviceMgrStub:GetEnabledAdminInner read type fail %{public}u", type);
        return ERR_OK;
    }
    std::vector<std::string> enabledAdminList;
    ErrCode res = GetEnabledAdmin((AdminType)type, enabledAdminList);
    if (FAILED(res)) {
        EDMLOGE("EnterpriseDeviceMgrStub:GetEnabledAdmin failed:%{public}d", res);
        reply.WriteInt32(res);
        return ERR_OK;
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
        return ERR_OK;
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
        return ERR_OK;
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
        return ERR_OK;
    }
    EntInfo entInfo;
    if (!EntInfo::Unmarshalling(data, entInfo)) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return ERR_OK;
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
        return ERR_OK;
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
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::AuthorizeAdminInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:AuthorizeAdminInner.");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return ERR_OK;
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

ErrCode EnterpriseDeviceMgrStub::SetDelegatedPoliciesInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:SetDelegatedPoliciesInner.");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::string bundleName = data.ReadString();
    std::vector<std::string> policies;
    data.ReadStringVector(&policies);
    if (policies.size() > EdmConstants::POLICIES_MAX_SIZE) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    return SetDelegatedPolicies(admin->GetBundleName(), bundleName, policies);
}

ErrCode EnterpriseDeviceMgrStub::GetDelegatedPoliciesInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:GetDelegatedPoliciesInner.");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::string bundleName = data.ReadString();
    std::vector<std::string> policies;
    ErrCode ret = GetDelegatedPolicies(admin->GetBundleName(), bundleName, policies);
    if (FAILED(ret)) {
        return ret;
    }
    reply.WriteUint32(policies.size());
    reply.WriteStringVector(policies);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::GetDelegatedBundleNamesInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:GetDelegatedBundleNamesInner.");
    std::unique_ptr<AppExecFwk::ElementName> admin(data.ReadParcelable<AppExecFwk::ElementName>());
    if (!admin) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::string policyName = data.ReadString();
    std::vector<std::string> bundleNames;
    ErrCode ret = GetDelegatedBundleNames(admin->GetBundleName(), policyName, bundleNames);
    if (FAILED(ret)) {
        return ret;
    }
    reply.WriteUint32(bundleNames.size());
    reply.WriteStringVector(bundleNames);
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrStub::GetAdminsInner(MessageParcel &data, MessageParcel &reply)
{
    EDMLOGD("EnterpriseDeviceMgrStub:GetAdminsInner");
    std::string bundleName = data.ReadString();
    EDMLOGD("GetAdminsInner bundleName:: %{public}s :", bundleName.c_str());
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    ErrCode ret = GetAdmins(wants);
    if (FAILED(ret)) {
        return ret;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteUint32(wants.size());
    for (std::shared_ptr<AAFwk::Want> want : wants) {
        reply.WriteParcelable(want.get());
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS