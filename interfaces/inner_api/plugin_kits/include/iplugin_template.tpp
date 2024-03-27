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
    ErrCode res = entry->second.handlePolicy_(data, reply, policyData.policyData, policyData.isChanged, type, userId);
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
    auto handle = [this](MessageParcel &data, MessageParcel &reply, std::string &policyData, bool &isChanged,
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
    auto handle = [this](MessageParcel &data, MessageParcel &reply, std::string &policyData, bool &isChanged,
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
        isChanged = (policyData != afterHandle);
        if (isChanged) {
            policyData = afterHandle;
        }
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
    auto handle = [this](MessageParcel &data, MessageParcel &reply, std::string &policyData, bool &isChanged,
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
        isChanged = (policyData != afterHandle);
        if (isChanged) {
            policyData = afterHandle;
        }
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
    auto handle = [this](MessageParcel &data, MessageParcel &reply, std::string &policyData, bool &isChanged,
                      FuncOperateType funcOperate, int32_t userId) -> ErrCode {
        DT handleData;
        if (!serializer_->GetPolicy(data, handleData)) {
            return ERR_EDM_OPERATE_PARCEL;
        }
        DT currentData;
        if (!policyData.empty() && !serializer_->Deserialize(policyData, currentData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        auto entry = handlePolicyFuncMap_.find(funcOperate);
        if (entry == handlePolicyFuncMap_.end() || entry->second.biFunction_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        std::string beforeHandle;
        if (!serializer_->Serialize(currentData, beforeHandle)) {
            return ERR_EDM_OPERATE_JSON;
        }
        ErrCode result = (instance_.get()->*(entry->second.biFunction_))(handleData, currentData, userId);
        if (result != ERR_OK) {
            return result;
        }
        std::string afterHandle;
        if (!serializer_->Serialize(currentData, afterHandle)) {
            return ERR_EDM_OPERATE_JSON;
        }
        policyData = afterHandle;
        isChanged = (beforeHandle != afterHandle);
        return ERR_OK;
    };
    handlePolicyFuncMap_.insert(std::make_pair(type, HandlePolicyFunc(handle, listener)));
}
using AdminValueItemsMap = std::unordered_map<std::string, std::string>;
template <class CT, class DT>
ErrCode IPluginTemplate<CT, DT>::MergePolicyData(const std::string &adminName, std::string &policyData)
{
    AdminValueItemsMap adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues);
    EDMLOGD("IPluginTemplate::MergePolicyData %{public}s value size %{public}d.", GetPolicyName().c_str(),
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
    if (adminValues.empty() && policyData.empty()) {
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
    // Add current policy to last, some policy must ensure the order, Deserialize can not parse empty String
    DT last;
    if (!policyData.empty()) {
        if (!serializer_->Deserialize(policyData, last)) {
            return ERR_EDM_OPERATE_JSON;
        }
        data.push_back(last);
    }
    DT result;
    if (!serializer_->MergePolicy(data, result)) {
        return ERR_EDM_OPERATE_JSON;
    }
    if (!serializer_->Serialize(result, policyData)) {
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
    int32_t userId)
{
    if (adminRemoveFunc_.adminRemove_ == nullptr) {
        return ERR_OK;
    }
    ErrCode res = (adminRemoveFunc_.adminRemove_)(adminName, currentJsonData, userId);
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
                           int32_t userId) -> ErrCode {
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
                           int32_t userId) -> ErrCode {
        DT currentData;
        if (!serializer_->Deserialize(currentJsonData, currentData)) {
            return ERR_EDM_OPERATE_JSON;
        }
        if (adminRemoveFunc_.biAdminFunction_ == nullptr) {
            return ERR_EDM_NOT_EXIST_FUNC;
        }
        return (instance_.get()->*(adminRemoveFunc_.biAdminFunction_))(adminName, currentData, userId);
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
ErrCode IPluginTemplate<CT, DT>::WritePolicyToParcel(const std::string &policyData, MessageParcel &reply)
{
    DT currentData;
    if (!serializer_->Deserialize(policyData, currentData)) {
        return ERR_EDM_OPERATE_JSON;
    }
    if (!serializer_->WritePolicy(reply, currentData)) {
        return ERR_EDM_OPERATE_PARCEL;
    }
    return ERR_OK;
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
        instance_ = nullptr;
    }
    if (serializer_ != nullptr) {
        serializer_.reset();
        serializer_ = nullptr;
    }
}