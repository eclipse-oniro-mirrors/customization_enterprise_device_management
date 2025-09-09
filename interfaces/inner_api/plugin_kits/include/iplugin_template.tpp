/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

template <class CT, class DT>
IPluginTemplate<CT, DT>::IPluginTemplate()
{
}

template <class CT, class DT>
ErrCode IPluginTemplate<CT, DT>::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    auto entry = handlePolicyFuncMap_.find(type);
    if (entry == handlePolicyFuncMap_.end() || entry->second.handlePolicy_ == nullptr) {
        return ERR_OK;
    }
    ErrCode res = entry->second.handlePolicy_(data, reply, policyData, type, userId);
    EDMLOGI("IPluginTemplate::OnHandlePolicy operate: %{public}d, res: %{public}d", type, res);
    return res;
}

template <class CT, class DT>
ErrCode IPluginTemplate<CT, DT>::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("IPluginTemplate::OnGetPolicy");
    return instance_->OnGetPolicy(policyData, data, reply, userId);
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnHandlePolicyListener(Supplier &&listener, FuncOperateType type)
{
    if (instance_ == nullptr) {
        return;
    }
    auto handle = [this](MessageParcel &data, MessageParcel &reply, HandlePolicyData &policyData,
                      FuncOperateType funcOperate, int32_t userId) -> ErrCode {
        auto entry = handlePolicyFuncMap_.find(funcOperate);
        if (entry == handlePolicyFuncMap_.end() || entry->second.supplier_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        return (instance_.get()->*(entry->second.supplier_))();
    };
    handlePolicyFuncMap_.insert(std::make_pair(type, HandlePolicyFunc(handle, listener)));
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnHandlePolicyListener(Function &&listener, FuncOperateType type)
{
    if (instance_ == nullptr) {
        return;
    }
    auto handle = [this](MessageParcel &data, MessageParcel &reply, HandlePolicyData &policyData,
                      FuncOperateType funcOperate, int32_t userId) -> ErrCode {
        DT handleData;
        if (!serializer_->GetPolicy(data, handleData)) {
            return ERR_EDM_OPERATE_PARCEL;
        }
        auto entry = handlePolicyFuncMap_.find(funcOperate);
        if (entry == handlePolicyFuncMap_.end() || entry->second.function_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        ErrCode result = (instance_.get()->*(entry->second.function_))(handleData);
        if (result != ERR_OK) {
            return result;
        }
        std::string afterHandle;
        if (!serializer_->Serialize(handleData, afterHandle)) {
            return ERR_EDM_OPERATE_JSON;
        }
        policyData.isChanged = (policyData.policyData != afterHandle);
        if (policyData.isChanged) {
            policyData.policyData = afterHandle;
        }
        policyData.mergePolicyData = afterHandle;
        return ERR_OK;
    };
    handlePolicyFuncMap_.insert(std::make_pair(type, HandlePolicyFunc(handle, listener)));
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnHandlePolicyListener(ReplyFunction &&listener, FuncOperateType type)
{
    if (instance_ == nullptr) {
        return;
    }
    auto handle = [this](MessageParcel &data, MessageParcel &reply, HandlePolicyData &policyData,
                      FuncOperateType funcOperate, int32_t userId) -> ErrCode {
        DT handleData;
        if (!serializer_->GetPolicy(data, handleData)) {
            return ERR_EDM_OPERATE_PARCEL;
        }
        auto entry = handlePolicyFuncMap_.find(funcOperate);
        if (entry == handlePolicyFuncMap_.end() || entry->second.replyfunction_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        ErrCode result = (instance_.get()->*(entry->second.replyfunction_))(handleData, reply);
        if (result != ERR_OK) {
            return result;
        }
        std::string afterHandle;
        if (!serializer_->Serialize(handleData, afterHandle)) {
            return ERR_EDM_OPERATE_JSON;
        }
        policyData.isChanged = (policyData.policyData != afterHandle);
        if (policyData.isChanged) {
            policyData.policyData = afterHandle;
        }
        policyData.mergePolicyData = afterHandle;
        return ERR_OK;
    };
    handlePolicyFuncMap_.insert(std::make_pair(type, HandlePolicyFunc(handle, listener)));
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnHandlePolicyListener(BiFunction &&listener, FuncOperateType type)
{
    if (instance_ == nullptr || instance_.get() == nullptr) {
        return;
    }
    auto handle = [this](MessageParcel &data, MessageParcel &reply, HandlePolicyData &policyData,
                      FuncOperateType funcOperate, int32_t userId) -> ErrCode {
        DT handleData;
        if (!serializer_->GetPolicy(data, handleData)) {
            return ERR_EDM_OPERATE_PARCEL;
        }
        DT currentData;
        if (!policyData.policyData.empty() && !serializer_->Deserialize(policyData.policyData, currentData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        auto entry = handlePolicyFuncMap_.find(funcOperate);
        if (entry == handlePolicyFuncMap_.end() || entry->second.biFunction_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        DT mergeData;
        if (!policyData.mergePolicyData.empty() &&
            !serializer_->Deserialize(policyData.mergePolicyData, mergeData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        ErrCode result = (instance_.get()->*(entry->second.biFunction_))(handleData, currentData, mergeData, userId);
        if (result != ERR_OK) {
            return result;
        }
        std::string afterHandle;
        if (!serializer_->Serialize(currentData, afterHandle)) {
            return ERR_EDM_OPERATE_JSON;
        }
        std::string afterMerge;
        if (!serializer_->Serialize(mergeData, afterMerge)) {
            return ERR_EDM_OPERATE_JSON;
        }
        policyData.isChanged = (policyData.policyData != afterHandle);
        policyData.policyData = afterHandle;
        policyData.mergePolicyData = afterMerge;
        return ERR_OK;
    };
    handlePolicyFuncMap_.insert(std::make_pair(type, HandlePolicyFunc(handle, listener)));
}

using AdminValueItemsMap = std::unordered_map<std::string, std::string>;
template <class CT, class DT>
ErrCode IPluginTemplate<CT, DT>::GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
    std::string &othersMergePolicyData)
{
    AdminValueItemsMap adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues, userId);
    EDMLOGD("IPluginTemplate::GetOthersMergePolicyData %{public}s value size %{public}d.", GetPolicyName().c_str(),
        (uint32_t)adminValues.size());
    if (adminValues.empty()) {
        return ERR_OK;
    }
    // Update or remove policy value from the cache map.
    auto entry = adminValues.find(adminName);
    // Remove policy value from the cache map.
    if (entry != adminValues.end()) {
        adminValues.erase(entry);
    }
    if (adminValues.empty()) {
        return ERR_OK;
    }
    std::vector<DT> data;
    for (const auto &item : adminValues) {
        DT dataItem;
        if (!item.second.empty()) {
            if (!serializer_->Deserialize(item.second, dataItem)) {
                return ERR_EDM_OPERATE_JSON;
            }
            data.push_back(dataItem);
        }
    }
    DT result;
    if (!serializer_->MergePolicy(data, result)) {
        return ERR_EDM_OPERATE_JSON;
    }
    if (!serializer_->Serialize(result, othersMergePolicyData)) {
        return ERR_EDM_OPERATE_JSON;
    }
    return ERR_OK;
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName,
    const bool isGlobalChanged, int32_t userId)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    auto entry = handlePolicyDoneFuncMap_.find(type);
    if (entry == handlePolicyDoneFuncMap_.end() || entry->second.handlePolicyDone_ == nullptr) {
        return;
    }
    ErrCode res = entry->second.handlePolicyDone_(adminName, isGlobalChanged, type, userId);
    EDMLOGI("IPluginTemplate::OnHandlePolicyDone operate: %{public}d, isGlobalChanged: %{public}d, res: %{public}d",
        type, isGlobalChanged, res);
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnHandlePolicyDoneListener(BoolConsumer &&listener, FuncOperateType type)
{
    if (instance_ == nullptr) {
        return;
    }
    auto handle = [this](const std::string &adminName, bool isGlobalChanged, FuncOperateType funcOperate,
                      int32_t userId) -> ErrCode {
        auto entry = handlePolicyDoneFuncMap_.find(funcOperate);
        if (entry == handlePolicyDoneFuncMap_.end() || entry->second.boolConsumer_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        (instance_.get()->*(entry->second.boolConsumer_))(isGlobalChanged);
        return ERR_OK;
    };
    handlePolicyDoneFuncMap_.insert(std::make_pair(type, HandlePolicyDoneFunc(handle, listener)));
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnHandlePolicyDoneListener(BiBoolConsumer &&listener, FuncOperateType type)
{
    if (instance_ == nullptr) {
        return;
    }
    auto handle = [this](const std::string &adminName, bool isGlobalChanged, FuncOperateType funcOperate,
                      int32_t userId) -> ErrCode {
        auto entry = handlePolicyDoneFuncMap_.find(funcOperate);
        if (entry == handlePolicyDoneFuncMap_.end() || entry->second.biBoolConsumer_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        DT currentData;
        if (NeedSavePolicy() && !this->GetMergePolicyData(currentData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        (instance_.get()->*(entry->second.biBoolConsumer_))(currentData, isGlobalChanged, userId);
        return ERR_OK;
    };
    handlePolicyDoneFuncMap_.insert(std::make_pair(type, HandlePolicyDoneFunc(handle, listener)));
}

template <class CT, class DT>
ErrCode IPluginTemplate<CT, DT>::OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
    const std::string &mergeJsonData, int32_t userId)
{
    if (adminRemoveFunc_.adminRemove_ == nullptr) {
        return ERR_OK;
    }
    ErrCode res = (adminRemoveFunc_.adminRemove_)(adminName, currentJsonData, mergeJsonData, userId);
    EDMLOGI("IPluginTemplate::OnAdminRemove admin:%{public}s, res: %{public}d", adminName.c_str(), res);
    return res;
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnAdminRemoveListener(Supplier &&listener)
{
    if (instance_ == nullptr) {
        return;
    }
    auto adminRemove = [this](const std::string &adminName, const std::string &currentJsonData,
                           const std::string &mergeJsonData, int32_t userId) -> ErrCode {
        if (adminRemoveFunc_.supplier_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        return (instance_.get()->*(adminRemoveFunc_.supplier_))();
    };
    adminRemoveFunc_ = AdminRemoveFunc(adminRemove, listener);
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnAdminRemoveListener(BiAdminFunction &&listener)
{
    if (instance_ == nullptr) {
        return;
    }
    auto adminRemove = [this](const std::string &adminName, const std::string &currentJsonData,
                           const std::string &mergeJsonData, int32_t userId) -> ErrCode {
        DT currentData;
        if (!serializer_->Deserialize(currentJsonData, currentData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        DT mergeData;
        if (!serializer_->Deserialize(mergeJsonData, mergeData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        if (adminRemoveFunc_.biAdminFunction_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        return (instance_.get()->*(adminRemoveFunc_.biAdminFunction_))(adminName, currentData, mergeData, userId);
    };
    adminRemoveFunc_ = AdminRemoveFunc(adminRemove, listener);
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
    int32_t userId)
{
    if (instance_ == nullptr) {
        return;
    }
    if (adminRemoveDoneFunc_.adminRemoveDone_ == nullptr) {
        return;
    }
    (adminRemoveDoneFunc_.adminRemoveDone_)(adminName, currentJsonData, userId);
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnAdminRemoveDoneListener(Runner &&listener)
{
    if (instance_ == nullptr) {
        return;
    }
    auto adminRemoveDone = [this](const std::string &adminName, const std::string &currentJsonData,
                               int32_t userId) -> ErrCode {
        if (adminRemoveDoneFunc_.runner_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        (instance_.get()->*(adminRemoveDoneFunc_.runner_))();
        return ERR_OK;
    };
    adminRemoveDoneFunc_ = AdminRemoveDoneFunc(adminRemoveDone, listener);
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetOnAdminRemoveDoneListener(BiAdminConsumer &&listener)
{
    if (instance_ == nullptr) {
        return;
    }
    auto adminRemoveDone = [this](const std::string &adminName, const std::string &currentJsonData,
                               int32_t userId) -> ErrCode {
        if (adminRemoveDoneFunc_.biAdminConsumer_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        DT currentData;
        if (!serializer_->Deserialize(currentJsonData, currentData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        (instance_.get()->*(adminRemoveDoneFunc_.biAdminConsumer_))(adminName, currentData, userId);
        return ERR_OK;
    };
    adminRemoveDoneFunc_ = AdminRemoveDoneFunc(adminRemoveDone, listener);
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::OnOtherServiceStart(int32_t systemAbilityId)
{
    if (instance_ == nullptr) {
        return;
    }
    if (otherServiceStartFunc_.otherServiceStart_ == nullptr) {
        return;
    }
    (otherServiceStartFunc_.otherServiceStart_)(systemAbilityId);
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetOtherServiceStartListener(IntConsumer &&listener)
{
    if (instance_ == nullptr) {
        return;
    }
    auto otherServiceStart = [this](int32_t systemAbilityId) -> void {
        if (otherServiceStartFunc_.intConsumer_ == nullptr) {
            return;
        }
        (instance_.get()->*(otherServiceStartFunc_.intConsumer_))(systemAbilityId);
        return;
    };
    otherServiceStartFunc_ = OtherServiceStartFunc(otherServiceStart, listener);
}

template <class CT, class DT>
bool IPluginTemplate<CT, DT>::GetMergePolicyData(DT &policyData)
{
    AdminValueItemsMap adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues);
    if (adminValues.empty()) {
        return true;
    }
    if (adminValues.size() == 1) {
        for (const auto &item : adminValues) {
            if (!serializer_->Deserialize(item.second, policyData)) {
                return false;
            } else {
                return true;
            }
        }
    } else {
        std::vector<DT> adminValueArray;
        for (const auto &item : adminValues) {
            DT dataItem;
            if (!serializer_->Deserialize(item.second, dataItem)) {
                return false;
            }
            adminValueArray.push_back(dataItem);
        }
        if (!serializer_->MergePolicy(adminValueArray, policyData)) {
            return false;
        }
    }
    return true;
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetInstance(std::shared_ptr<CT> instance)
{
    instance_ = instance;
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::SetSerializer(std::shared_ptr<IPolicySerializer<DT>> serializer)
{
    serializer_ = serializer;
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::InitAttribute(uint32_t policyCode, const std::string &policyName,
    PolicyPermissionConfig config, bool needSave, bool global)
{
    policyCode_ = policyCode;
    policyName_ = policyName;
    permissionConfig_ = config;
    needSave_ = needSave;
    isGlobal_ = global;
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::InitAttribute(uint32_t policyCode, const std::string &policyName,
    const std::string &permission, IPlugin::PermissionType permissionType, bool needSave, bool global)
{
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(permission,
        permissionType, IPlugin::ApiType::PUBLIC);
    InitAttribute(policyCode, policyName, config, needSave, global);
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::InitAttribute(uint32_t policyCode, const std::string &policyName, bool needSave,
    bool global)
{
    policyCode_ = policyCode;
    policyName_ = policyName;
    needSave_ = needSave;
    isGlobal_ = global;
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::InitPermission(FuncOperateType operateType, PolicyPermissionConfig config)
{
    if (static_cast<int32_t>(operateType) >= static_cast<int32_t>(FuncOperateType::GET) &&
        static_cast<int32_t>(operateType) <= static_cast<int32_t>(FuncOperateType::REMOVE)) {
        permissionMap_.insert(std::make_pair(operateType, config));
    }
}

template <class CT, class DT>
void IPluginTemplate<CT, DT>::InitPermission(FuncOperateType operateType, const std::string &permission,
    IPlugin::PermissionType permissionType)
{
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(permission,
        permissionType, IPlugin::ApiType::PUBLIC);
    InitPermission(operateType, config);
}

template <class CT, class DT>
IPluginTemplate<CT, DT>::~IPluginTemplate()
{
    if (instance_ != nullptr) {
        instance_.reset();
    }
    if (serializer_ != nullptr) {
        serializer_.reset();
    }
}