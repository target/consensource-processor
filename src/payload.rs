/*
 * CertPayload
 */

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        use sabre_sdk::ApplyError;
    } else {
        use sawtooth_sdk::processor::handler::ApplyError;
    }
}

use common::proto::organization;
use common::proto::payload;
use common::proto::request;
use protobuf;

#[derive(PartialEq, Clone, Debug)]
pub enum Action {
    CreateAgent(payload::CreateAgentAction),
    CreateOrganization(payload::CreateOrganizationAction),
    UpdateOrganization(payload::UpdateOrganizationAction),
    AuthorizeAgent(payload::AuthorizeAgentAction),
    IssueCertificate(payload::IssueCertificateAction),
    CreateStandard(payload::CreateStandardAction),
    UpdateStandard(payload::UpdateStandardAction),
    OpenRequest(payload::OpenRequestAction),
    ChangeRequestStatus(payload::ChangeRequestStatusAction),
    AccreditCertifyingBody(payload::AccreditCertifyingBodyAction),
}

#[derive(PartialEq, Clone, Debug)]
pub struct CertPayload {
    action: Action,
}

/// Macro
/// Given an obejct and one or more fields it checks if the any of the fields in the object are empty
/// ```
/// # Errors
/// Returns an error if any of the fields passed in as arguments are empty in the object.
macro_rules! reject_empty {
    ($obj:ident, $first_field:ident) => {
        {
        if $obj.$first_field.is_empty() {
            Err(ApplyError::InvalidTransaction(
                    format!("{}.{} is empty",
                            stringify!($obj),
                            stringify!($first_field))))
        }
        else {
            Ok(())
        }
        }
    };
    ($obj:ident, $first_field:ident, $($field:ident),*) => {
        {
        if $obj.$first_field.is_empty() {
            Err(ApplyError::InvalidTransaction(
                    format!("{}.{} is empty",
                            stringify!($obj),
                            stringify!($first_field))))
        }
        $(
            else if $obj.$field.is_empty() {
                Err(ApplyError::InvalidTransaction(
                        format!("{}.{} is empty",
                                stringify!($obj),
                                stringify!($field))))
            }
        )*
        else {
            Ok(())
        }
        }
    };
}

impl CertPayload {
    /// Validates the payload data.
    /// It checks that all necessary fields have been passed for the specified
    /// action and performs some validation when possible.
    /// This performs all payload validation that does not require fetching data from
    /// state.
    /// ```
    /// # Errors
    /// Returns an error if the payload is not valid
    /// ```
    pub fn new(payload_data: &[u8]) -> Result<CertPayload, ApplyError> {
        let payload: payload::CertificateRegistryPayload = unpack_data(&payload_data)?;

        let payload_action = match payload.get_action() {
            payload::CertificateRegistryPayload_Action::UNSET_ACTION => {
                return Err(ApplyError::InvalidTransaction(String::from(
                    "No action specified",
                )));
            }
            payload::CertificateRegistryPayload_Action::CREATE_AGENT => {
                let create_agent = payload.get_create_agent();

                if create_agent.get_name() == "" {
                    return Err(ApplyError::InvalidTransaction(String::from(
                        "Name was not provided",
                    )));
                }
                Action::CreateAgent(create_agent.clone())
            }
            payload::CertificateRegistryPayload_Action::CREATE_ORGANIZATION => {
                let create_org = payload.get_create_organization();

                reject_empty!(create_org, id, name, contacts)?;

                if create_org.get_organization_type() == organization::Organization_Type::UNSET_TYPE
                {
                    return Err(ApplyError::InvalidTransaction(String::from(
                        "Organization type is unset",
                    )));
                }

                if create_org.get_organization_type() == organization::Organization_Type::FACTORY {
                    if create_org.has_address() {
                        let address = create_org.get_address();
                        reject_empty!(address, street_line_1, city, country)?;
                    } else {
                        return Err(ApplyError::InvalidTransaction(String::from(
                            "Factory must be created with an address",
                        )));
                    }
                } else if create_org.has_address() {
                    return Err(ApplyError::InvalidTransaction(String::from(
                        "Only a factory can have an address",
                    )));
                }

                Action::CreateOrganization(create_org.clone())
            }
            payload::CertificateRegistryPayload_Action::UPDATE_ORGANIZATION => {
                let update = payload.get_update_organization();
                Action::UpdateOrganization(update.clone())
            }
            payload::CertificateRegistryPayload_Action::AUTHORIZE_AGENT => {
                let authorize_agent = payload.get_authorize_agent();

                reject_empty!(authorize_agent, public_key)?;

                if authorize_agent.get_role()
                    == organization::Organization_Authorization_Role::UNSET_ROLE
                {
                    return Err(ApplyError::InvalidTransaction(String::from(
                        "Agent role is UNSET. Set the role to TRANSACTOR or ADMIN",
                    )));
                }

                if authorize_agent.get_role()
                    != organization::Organization_Authorization_Role::TRANSACTOR
                    && authorize_agent.get_role()
                        != organization::Organization_Authorization_Role::ADMIN
                {
                    return Err(ApplyError::InvalidTransaction(String::from(
                        "Agent role is invalid. Agents can only have the roles: TRANSACTOR or ADMIN",
                    )));
                }

                Action::AuthorizeAgent(authorize_agent.clone())
            }
            payload::CertificateRegistryPayload_Action::ISSUE_CERTIFICATE => {
                let issue_cert = payload.get_issue_certificate();
                reject_empty!(issue_cert, id)?;

                match issue_cert.get_source() {
                    payload::IssueCertificateAction_Source::UNSET_SOURCE => {
                        return Err(ApplyError::InvalidTransaction(String::from(
                            "Issue Certificate source must be set. It can be
                            FROM_REQUEST if the there is an request associated with the
                            action, or INDEPENDENT if there is not request associated.",
                        )));
                    }
                    payload::IssueCertificateAction_Source::FROM_REQUEST => {
                        reject_empty!(issue_cert, id, request_id)?;
                    }
                    payload::IssueCertificateAction_Source::INDEPENDENT => {
                        reject_empty!(issue_cert, id, factory_id, standard_id)?;
                    }
                }

                if issue_cert.get_valid_from() == 0 {
                    return Err(ApplyError::InvalidTransaction(String::from(
                        "Certificate's valid_from field is invalid",
                    )));
                }

                if issue_cert.get_valid_to() == 0 {
                    return Err(ApplyError::InvalidTransaction(String::from(
                        "Certificate's valid_to field is invalid",
                    )));
                }

                Action::IssueCertificate(issue_cert.clone())
            }
            payload::CertificateRegistryPayload_Action::OPEN_REQUEST_ACTION => {
                let open_request = payload.get_open_request_action();
                reject_empty!(open_request, id, standard_id)?;
                Action::OpenRequest(open_request.clone())
            }
            payload::CertificateRegistryPayload_Action::CHANGE_REQUEST_STATUS_ACTION => {
                let change_request = payload.get_change_request_status_action();
                reject_empty!(change_request, request_id)?;

                if change_request.status != request::Request_Status::IN_PROGRESS
                    && change_request.status != request::Request_Status::CLOSED
                {
                    return Err(ApplyError::InvalidTransaction(format!(
                        "ChangeRequest status is invalid. Status can only be set to IN_PROGRESS or CLOSED.
                        Status: {:?}",
                        change_request.status
                    )));
                }

                Action::ChangeRequestStatus(change_request.clone())
            }
            payload::CertificateRegistryPayload_Action::CREATE_STANDARD => {
                let create_standard = payload.get_create_standard();

                // Check if any fields are empty and return error if so
                reject_empty!(
                    create_standard,
                    standard_id,
                    name,
                    version,
                    description,
                    link
                )?;
                if create_standard.approval_date == 0 {
                    return Err(ApplyError::InvalidTransaction(
                        "Approval date must be provided".to_string(),
                    ));
                }
                Action::CreateStandard(create_standard.clone())
            }
            payload::CertificateRegistryPayload_Action::UPDATE_STANDARD => {
                let update_standard = payload.get_update_standard();
                reject_empty!(update_standard, standard_id, version, description, link)?;
                if update_standard.approval_date == 0 {
                    return Err(ApplyError::InvalidTransaction(
                        "Approval date must be provided".to_string(),
                    ));
                }
                Action::UpdateStandard(update_standard.clone())
            }
            payload::CertificateRegistryPayload_Action::ACCREDIT_CERTIFYING_BODY_ACTION => {
                let accredit_certifying_body = payload.get_accredit_certifying_body_action();
                reject_empty!(accredit_certifying_body, certifying_body_id, standard_id)?;

                if accredit_certifying_body.get_valid_from() == 0 {
                    return Err(ApplyError::InvalidTransaction(String::from(
                        "Accreditation's valid_from field is invalid",
                    )));
                }

                if accredit_certifying_body.get_valid_to() == 0 {
                    return Err(ApplyError::InvalidTransaction(String::from(
                        "Accreditations's valid_to field is invalid",
                    )));
                }

                Action::AccreditCertifyingBody(accredit_certifying_body.clone())
            }
        };
        Ok(CertPayload {
            action: payload_action,
        })
    }

    pub fn get_action(&self) -> Action {
        self.action.clone()
    }
}

/// Deserializes binary data to a protobuf object
fn unpack_data<T>(data: &[u8]) -> Result<T, ApplyError>
where
    T: protobuf::Message,
{
    protobuf::parse_from_bytes(&data).map_err(|err| {
        ApplyError::InvalidTransaction(format!(
            "Failed to unmarshal CertRegistryTransaction: {:?}",
            err
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::proto::payload::*;

    pub trait IntoBytes: Sized {
        fn into_bytes(self) -> Result<Vec<u8>, protobuf::error::ProtobufError>;
    }

    impl IntoBytes for CertificateRegistryPayload {
        fn into_bytes(self) -> Result<Vec<u8>, protobuf::error::ProtobufError> {
            protobuf::Message::write_to_bytes(&self)
        }
    }

    #[test]
    // Test creating a UNSET Action executes correctly, should error
    fn test_unset_action_creation_err() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::UNSET_ACTION);

        let bytes = new_payload.into_bytes().unwrap();

        assert_eq!(
            format!("{:?}", CertPayload::new(&bytes).unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from("No action specified",))
            )
        );
    }

    #[test]
    // Test creating a Create Agent Action executes correctly
    fn test_create_agent_action_creation_ok() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::CREATE_AGENT);

        let mut new_agent = CreateAgentAction::new();
        new_agent.set_name("test".to_string());
        new_payload.set_create_agent(new_agent.clone());

        let bytes = new_payload.into_bytes().unwrap();

        assert_eq!(
            CertPayload::new(&bytes).unwrap(),
            CertPayload {
                action: Action::CreateAgent(new_agent.clone())
            }
        );
    }

    #[test]
    // Test creating a Create Organization Action executes correctly
    fn test_create_organization_action_creation_ok() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::CREATE_ORGANIZATION);

        let mut new_org = CreateOrganizationAction::new();
        new_org.set_id("test".to_string());
        new_org.set_organization_type(organization::Organization_Type::STANDARDS_BODY);
        new_org.set_name("test".to_string());
        let mut new_contact = organization::Organization_Contact::new();
        new_contact.set_name("test".to_string());
        new_contact.set_phone_number("test".to_string());
        new_contact.set_language_code("test".to_string());
        new_org.set_contacts(protobuf::RepeatedField::from_vec(vec![new_contact]));
        new_payload.set_create_organization(new_org.clone());

        let bytes = new_payload.into_bytes().unwrap();

        assert_eq!(
            CertPayload::new(&bytes).unwrap(),
            CertPayload {
                action: Action::CreateOrganization(new_org.clone())
            }
        );
    }

    #[test]
    // Test creating a Update Organization Action executes correctly
    fn test_update_organization_action_creation_ok() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::UPDATE_ORGANIZATION);

        let mut org_update = UpdateOrganizationAction::new();
        let mut new_contact = organization::Organization_Contact::new();
        new_contact.set_name("test".to_string());
        new_contact.set_phone_number("test".to_string());
        new_contact.set_language_code("test".to_string());
        org_update.set_contacts(protobuf::RepeatedField::from_vec(vec![new_contact]));
        new_payload.set_update_organization(org_update.clone());

        let bytes = new_payload.into_bytes().unwrap();

        assert_eq!(
            CertPayload::new(&bytes).unwrap(),
            CertPayload {
                action: Action::UpdateOrganization(org_update.clone())
            }
        );
    }

    #[test]
    // Test creating a Authorize Agent Action executes correctly
    fn test_authorize_agent_action_creation_ok() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::AUTHORIZE_AGENT);

        let mut auth = AuthorizeAgentAction::new();
        auth.set_public_key("test".to_string());
        auth.set_role(organization::Organization_Authorization_Role::TRANSACTOR);
        new_payload.set_authorize_agent(auth.clone());

        let bytes = new_payload.into_bytes().unwrap();

        assert_eq!(
            CertPayload::new(&bytes).unwrap(),
            CertPayload {
                action: Action::AuthorizeAgent(auth.clone())
            }
        );
    }

    #[test]
    // Test creating a Issue Certificate Action executes correctly
    fn test_issue_certificate_action_creation_ok() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::ISSUE_CERTIFICATE);

        let mut issuance = IssueCertificateAction::new();
        issuance.set_id("test".to_string());
        issuance.set_source(IssueCertificateAction_Source::FROM_REQUEST);
        issuance.set_request_id("test".to_string());
        issuance.set_valid_from(1);
        issuance.set_valid_to(2);
        new_payload.set_issue_certificate(issuance.clone());

        let bytes = new_payload.into_bytes().unwrap();

        assert_eq!(
            CertPayload::new(&bytes).unwrap(),
            CertPayload {
                action: Action::IssueCertificate(issuance.clone())
            }
        );
    }

    #[test]
    // Test creating a Create Standard Action executes correctly
    fn test_create_standard_action_creation_ok() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::CREATE_STANDARD);

        let mut standard = CreateStandardAction::new();
        standard.set_standard_id("test".to_string());
        standard.set_name("test".to_string());
        standard.set_version("test".to_string());
        standard.set_description("test".to_string());
        standard.set_link("test".to_string());
        standard.set_approval_date(1);
        new_payload.set_create_standard(standard.clone());

        let bytes = new_payload.into_bytes().unwrap();
        assert_eq!(
            CertPayload::new(&bytes).unwrap(),
            CertPayload {
                action: Action::CreateStandard(standard.clone())
            }
        );
    }

    #[test]
    // Test creating a Update Standard Action executes correctly
    fn test_update_standard_action_creation_ok() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::UPDATE_STANDARD);

        let mut standard = UpdateStandardAction::new();
        standard.set_standard_id("test".to_string());
        standard.set_version("test".to_string());
        standard.set_description("test".to_string());
        standard.set_link("test".to_string());
        standard.set_approval_date(1);
        new_payload.set_update_standard(standard.clone());

        let bytes = new_payload.into_bytes().unwrap();
        assert_eq!(
            CertPayload::new(&bytes).unwrap(),
            CertPayload {
                action: Action::UpdateStandard(standard.clone())
            }
        );
    }

    #[test]
    // Test creating a Open Request Action executes correctly
    fn test_open_request_action_creation_ok() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::OPEN_REQUEST_ACTION);

        let mut request = OpenRequestAction::new();
        request.set_id("test".to_string());
        request.set_standard_id("test".to_string());
        request.set_request_date(1);
        new_payload.set_open_request_action(request.clone());

        let bytes = new_payload.into_bytes().unwrap();
        assert_eq!(
            CertPayload::new(&bytes).unwrap(),
            CertPayload {
                action: Action::OpenRequest(request.clone())
            }
        );
    }

    #[test]
    // Test creating a Change Request Status Action executes correctly
    fn test_change_request_status_action_creation_ok() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::CHANGE_REQUEST_STATUS_ACTION);

        let mut request = ChangeRequestStatusAction::new();
        request.set_request_id("test".to_string());
        request.set_status(request::Request_Status::CLOSED);
        new_payload.set_change_request_status_action(request.clone());

        let bytes = new_payload.into_bytes().unwrap();

        assert_eq!(
            CertPayload::new(&bytes).unwrap(),
            CertPayload {
                action: Action::ChangeRequestStatus(request.clone())
            }
        );
    }

    #[test]
    // Test creating a Accredit Certifying Body Action executes correctly
    fn test_accredit_certifying_body_action_creation_ok() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::ACCREDIT_CERTIFYING_BODY_ACTION);

        let mut accreditation = AccreditCertifyingBodyAction::new();
        accreditation.set_certifying_body_id("test".to_string());
        accreditation.set_standard_id("test".to_string());
        accreditation.set_valid_from(1);
        accreditation.set_valid_to(2);
        new_payload.set_accredit_certifying_body_action(accreditation.clone());

        let bytes = new_payload.into_bytes().unwrap();

        assert_eq!(
            CertPayload::new(&bytes).unwrap(),
            CertPayload {
                action: Action::AccreditCertifyingBody(accreditation.clone())
            }
        );
    }

    #[test]
    // Test unpack_data executes correctly
    fn test_unpack_data_ok() {
        let mut new_payload = CertificateRegistryPayload::new();
        new_payload.set_action(CertificateRegistryPayload_Action::AUTHORIZE_AGENT);

        let mut auth = AuthorizeAgentAction::new();
        auth.set_public_key("test".to_string());
        auth.set_role(organization::Organization_Authorization_Role::TRANSACTOR);
        new_payload.set_authorize_agent(auth.clone());

        let bytes = new_payload.into_bytes().unwrap();
        let payload: Result<payload::CertificateRegistryPayload, ApplyError> = unpack_data(&bytes);

        assert!(payload.is_ok());
    }
}
