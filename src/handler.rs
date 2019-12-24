/*
 * CertTransactionHandler
 */
cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        use sabre_sdk::ApplyError;
        use sabre_sdk::TransactionContext;
        use sabre_sdk::TransactionHandler;
        use sabre_sdk::TpProcessRequest;
        use sabre_sdk::{WasmPtr, execute_entrypoint};
    } else {
        use sawtooth_sdk::messages::processor::TpProcessRequest;
        use sawtooth_sdk::processor::handler::ApplyError;
        use sawtooth_sdk::processor::handler::TransactionContext;
        use sawtooth_sdk::processor::handler::TransactionHandler;
    }
}

use common::addressing;
use common::proto;
use payload::{Action, CertPayload};
use protobuf;
use state::CertState;

pub struct CertTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl CertTransactionHandler {
    pub fn new() -> CertTransactionHandler {
        CertTransactionHandler {
            family_name: addressing::FAMILY_NAMESPACE.to_string(),
            family_versions: vec![addressing::FAMILY_VERSION.to_string()],
            namespaces: vec![addressing::get_family_namespace_prefix()],
        }
    }

    /// Creates a new Agent and submits it to state
    /// ```
    /// # Errors
    /// Returns an error if:
    ///     - Signer public key already associated with an agent
    ///     - It fails to submit the new Agent to state.
    /// ```
    pub fn create_agent(
        &self,
        payload: &proto::payload::CreateAgentAction,
        state: &mut CertState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        match state.get_agent(signer_public_key) {
            Ok(Some(_)) => Err(ApplyError::InvalidTransaction(format!(
                "Agent already exists: {}",
                signer_public_key
            ))),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }?;

        // Create agent
        let mut new_agent = proto::agent::Agent::new();
        new_agent.set_public_key(signer_public_key.to_string());
        new_agent.set_name(payload.get_name().to_string());
        new_agent.set_timestamp(payload.get_timestamp());

        // Put agent in state
        state.set_agent(signer_public_key, new_agent)?;

        Ok(())
    }

    /// Creates a new Organization and submits it to state
    ///
    /// ```
    /// # Errors
    /// Returns an error if
    ///   - an Organization already exists with the same ID
    ///   - an Agent with the signer public key does not exist
    ///   - the Agent submitting the transaction is already associated with an organization
    ///   - it fails to submit the new Organization to state.
    /// ```
    pub fn create_organization(
        &self,
        payload: &proto::payload::CreateOrganizationAction,
        state: &mut CertState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        match state.get_organization(payload.get_id()) {
            Ok(Some(_)) => Err(ApplyError::InvalidTransaction(format!(
                "Organization already exists: {}",
                payload.get_id()
            ))),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }?;

        // Validate signer public key and agent
        let mut agent = match state.get_agent(signer_public_key) {
            Ok(Some(agent)) => Ok(agent),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No agent exists: {}",
                signer_public_key
            ))),
            Err(err) => Err(err),
        }?;

        if !agent.get_organization_id().is_empty() {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent is already associated with an organization: {}",
                agent.get_organization_id(),
            )));
        }

        // Set agent for the organization
        agent.set_organization_id(payload.get_id().to_string());
        state.set_agent(signer_public_key, agent)?;

        // Create organization
        let mut new_organization = proto::organization::Organization::new();
        new_organization.set_id(payload.get_id().to_string());
        new_organization.set_name(payload.get_name().to_string());
        new_organization.set_organization_type(payload.get_organization_type());
        new_organization.set_contacts(protobuf::RepeatedField::from_vec(
            payload.get_contacts().to_vec(),
        ));

        let mut admin_authorization = proto::organization::Organization_Authorization::new();
        admin_authorization.set_public_key(signer_public_key.to_string());
        admin_authorization.set_role(proto::organization::Organization_Authorization_Role::ADMIN);

        let mut transactor_authorization = proto::organization::Organization_Authorization::new();
        transactor_authorization.set_public_key(signer_public_key.to_string());
        transactor_authorization
            .set_role(proto::organization::Organization_Authorization_Role::TRANSACTOR);

        new_organization.set_authorizations(::protobuf::RepeatedField::from_vec(vec![
            admin_authorization,
            transactor_authorization,
        ]));

        if payload.get_organization_type() == proto::organization::Organization_Type::FACTORY {
            let mut factory_details = proto::organization::Factory::new();
            factory_details.set_address(payload.get_address().clone());
            new_organization.set_factory_details(factory_details);
        }

        // Put organization in state
        state.set_organization(payload.get_id(), new_organization)?;

        Ok(())
    }

    /// Updates an existing Organization and submits it to state
    ///
    /// ```
    /// # Errors
    /// Returns an error if
    ///   - the Organization to be updated does not exist
    ///   - an Agent with the signer public key does not exist
    ///   - the Agent submitting the transaction is not associated with the organization
    ///   - the Agent submitting the transaction is not authorized as an ADMIN of the organization
    ///   - it fails to submit the Organization to state.
    /// ```
    pub fn update_organization(
        &self,
        payload: &proto::payload::UpdateOrganizationAction,
        state: &mut CertState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        // Check agent
        let agent = match state.get_agent(signer_public_key) {
            Ok(Some(agent)) => Ok(agent),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No agent exists: {}",
                signer_public_key
            ))),
            Err(err) => Err(err),
        }?;

        // Check agent's organization
        if agent.get_organization_id().is_empty() {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent is not associated with an organization: {}",
                agent.get_organization_id(),
            )));
        }

        let mut organization = match state.get_organization(agent.get_organization_id()) {
            Ok(Some(organization)) => Ok(organization),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No organization exists: {}",
                agent.get_organization_id()
            ))),
            Err(err) => Err(err),
        }?;

        // Validate agent is authorized
        let mut is_admin = false;
        for authorization in organization.get_authorizations() {
            if authorization.get_public_key() == signer_public_key
                && authorization.get_role()
                    == proto::organization::Organization_Authorization_Role::ADMIN
            {
                is_admin = true;
                break;
            }
        }
        if !is_admin {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent is not authorized to update organization: {}",
                agent.get_organization_id()
            )));
        }

        // Handle updates
        if payload.has_address() {
            if organization.get_organization_type()
                == proto::organization::Organization_Type::FACTORY
            {
                let mut updated_factory_details = organization.factory_details.get_ref().clone();
                updated_factory_details.set_address(payload.address.get_ref().clone());
                organization.set_factory_details(updated_factory_details);
            } else {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Unable to update address for organization {}: Organization is not a factory",
                    organization.get_id()
                )));
            }
        }
        if !payload.get_contacts().is_empty() {
            organization.set_contacts(protobuf::RepeatedField::from_vec(
                payload.get_contacts().to_vec(),
            ));
        }

        state.set_organization(&agent.get_organization_id(), organization)?;
        Ok(())
    }

    /// Updates an existing Organization to include a new authorization for an agent
    /// and submits it to state
    ///
    /// ```
    /// # Errors
    /// Returns an error if
    ///   - the Organization to be updated does not exist
    ///   - an Agent with the signer public key does not exist
    ///   - the Agent submitting the transaction is not authorized as an ADMIN of the organization
    ///   - the Agent submitting the transaction is not associated with the organization
    ///   - and Agent with the public key being authorized does not exist
    ///   - the Agent being authorized is already associated with a different Organization
    ///   - it fails to submit the Organization to state.
    /// ```
    pub fn authorize_agent(
        &self,
        payload: &proto::payload::AuthorizeAgentAction,
        state: &mut CertState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        // Validate an agent associated with the signer public key exists
        let signer_agent = {
            let signer_agent = state.get_agent(signer_public_key)?;
            if signer_agent.is_none() {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Signing agent does not exist: {}",
                    signer_public_key
                )));
            }
            signer_agent.unwrap()
        };

        // Validate signer is associated with an organization
        if signer_agent.get_organization_id().is_empty() {
            return Err(ApplyError::InvalidTransaction(format!(
                "Transaction signer is not associated with an organization: {}",
                signer_agent.get_organization_id(),
            )));
        }

        // Validate the organization the signer is associated with exists
        let mut organization = {
            let organization = state.get_organization(signer_agent.get_organization_id())?;
            if organization.is_none() {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Organization does not exist: {}",
                    signer_agent.get_organization_id()
                )));
            }
            organization.unwrap()
        };

        {
            // Validate signer agent is an ADMIN
            let authorization = organization.get_authorizations().iter().find(|auth| {
                auth.get_public_key() == signer_public_key
                    && auth.get_role()
                        == proto::organization::Organization_Authorization_Role::ADMIN
            });
            if authorization.is_none() {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Signing agent {} is not an authorized ADMIN for the organization: {}",
                    signer_public_key,
                    signer_agent.get_organization_id()
                )));
            }
        }

        // Validate agent to be authorized exists.
        let mut agent_to_be_authorized = {
            let agent_to_be_authorized = state.get_agent(payload.get_public_key())?;
            if agent_to_be_authorized.is_none() {
                return Err(ApplyError::InvalidTransaction(format!(
                    "No agent exists: {}",
                    payload.get_public_key()
                )));
            }
            agent_to_be_authorized.unwrap()
        };

        // Validate agent to be authorized is not already associated with an org
        // if the org is the same as the signer org, it will be allowed, in case
        // an authorization is being updated, e.g. an ISSUER is being promoted to ADMIN.
        if !agent_to_be_authorized.get_organization_id().is_empty()
            && agent_to_be_authorized.get_organization_id() != signer_agent.get_organization_id()
        {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent is already associated with a different organization: {}",
                agent_to_be_authorized.get_organization_id(),
            )));
        }

        {
            let authorization = organization.get_authorizations().iter().find(|auth| {
                auth.get_public_key() == agent_to_be_authorized.get_public_key()
                    && auth.get_role() == payload.get_role()
            });
            if authorization.is_some() {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Agent {} is already authorized as {:?}",
                    agent_to_be_authorized.get_public_key(),
                    payload.get_role()
                )));
            }
        }

        let mut new_authorization = proto::organization::Organization_Authorization::new();
        new_authorization.set_public_key(agent_to_be_authorized.get_public_key().to_string());
        new_authorization.set_role(payload.get_role());

        organization.authorizations.push(new_authorization);

        // Put updated organization in state
        state.set_organization(signer_agent.get_organization_id(), organization)?;

        // Update organization for the agent being authorized
        agent_to_be_authorized.set_organization_id(signer_agent.get_organization_id().to_string());
        state.set_agent(payload.get_public_key(), agent_to_be_authorized)?;

        Ok(())
    }

    /// Creates a new Certificate and submits it to state
    ///
    /// ```
    /// # Errors
    /// Returns an error if
    ///   - a certificate with the certificate id already exist
    ///   - an Agent with the signer public key does not exist
    ///   - the Agent submitting the transaction is not associated with the organization
    ///   - the Agent submitting the transaction is not authorized as a TRANSACTOR of the organization
    ///   - the Organization the Agent is associated with is not a CertifyingBody
    ///   - the standard does not exist
    ///   - if source is from request:
    ///        - the request does not exist
    ///        - the request does not have status set to IN_PROGRESS
    ///   - the factory the certificate is for does not exist. x
    ///   - it fails to submit the new Certificate to state.
    /// ```
    pub fn issue_certificate(
        &self,
        payload: &proto::payload::IssueCertificateAction,
        state: &mut CertState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        // Verify that certificate ID is not already associated with a Certificate object
        match state.get_certificate(payload.get_id()) {
            Ok(Some(_)) => Err(ApplyError::InvalidTransaction(format!(
                "Certificate already exists: {}",
                payload.get_id()
            ))),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }?;

        // Validate signer public key and agent
        let agent = match state.get_agent(signer_public_key) {
            Ok(Some(agent)) => Ok(agent),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No agent exists: {}",
                signer_public_key
            ))),
            Err(err) => Err(err),
        }?;

        if agent.get_organization_id().is_empty() {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent is not associated with an organization: {}",
                agent.get_organization_id(),
            )));
        }

        // Validate org existence
        let organization = match state.get_organization(agent.get_organization_id()) {
            Ok(Some(organization)) => Ok(organization),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No organization exists: {}",
                agent.get_organization_id()
            ))),
            Err(err) => Err(err),
        }?;

        if organization.get_organization_type()
            != proto::organization::Organization_Type::CERTIFYING_BODY
        {
            return Err(ApplyError::InvalidTransaction(format!(
                "Organization {} is not a certifying body",
                agent.get_organization_id()
            )));
        }

        // Validate agent is authorized
        let mut is_transactor = false;
        let authorizations = organization.get_authorizations();
        for authorization in authorizations {
            if authorization.get_public_key() == signer_public_key
                && authorization.get_role()
                    == proto::organization::Organization_Authorization_Role::TRANSACTOR
            {
                is_transactor = true;
                break;
            }
        }
        if !is_transactor {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent is not authorized to issue certificate: {}",
                payload.get_id()
            )));
        }

        // Validate current issue date
        let valid_from = payload.get_valid_from();
        let valid_to = payload.get_valid_to();
        if valid_to < valid_from {
            return Err(ApplyError::InvalidTransaction(
                "Invalid dates. Valid to must be after valid from".to_string(),
            ));
        }

        let (factory_id, standard_id) = match payload.get_source() {
            proto::payload::IssueCertificateAction_Source::FROM_REQUEST => {
                let request = match state.get_request(payload.get_request_id())? {
                    Some(request) => Ok(request),
                    None => Err(ApplyError::InvalidTransaction(format!(
                        "Request does not exist: {}",
                        payload.get_request_id()
                    ))),
                }?;

                if request.get_status() != proto::request::Request_Status::IN_PROGRESS {
                    return Err(ApplyError::InvalidTransaction(format!(
                        "The request with id {} has its status set to {:?}. Only requests with status set to IN_PROGRESS can be certified.",
                        request.get_id(),
                        request.get_status()
                    )));
                }

                // update status of request
                let mut updated_request = request.clone();
                updated_request.set_status(proto::request::Request_Status::CERTIFIED);
                state.set_request(payload.get_request_id(), updated_request)?;

                Ok((
                    request.get_factory_id().to_string(),
                    request.get_standard_id().to_string(),
                ))
            }
            proto::payload::IssueCertificateAction_Source::INDEPENDENT => {
                match state.get_organization(&payload.get_factory_id())? {
                    Some(_) => Ok(()),
                    None => Err(ApplyError::InvalidTransaction(format!(
                        "Factory does not exist: {}",
                        payload.get_factory_id()
                    ))),
                }?;
                Ok((
                    payload.get_factory_id().to_string(),
                    payload.get_standard_id().to_string(),
                ))
            }
            proto::payload::IssueCertificateAction_Source::UNSET_SOURCE => {
                Err(ApplyError::InvalidTransaction(String::from(
                    "Issue Certificate source must be set. It can be
                    FROM_REQUEST if the there is an request associated with the
                    action, or INDEPENDENT if there is not request associated.",
                )))
            }
        }?;

        // Get standard version from organization's cert_body_details
        let certifying_body_details = organization.get_certifying_body_details();
        let accreditations = certifying_body_details.get_accreditations().to_vec();
        if accreditations
            .iter()
            .find(|accreditation| accreditation.get_standard_id() == standard_id)
            .is_none()
        {
            return Err(ApplyError::InvalidTransaction(format!(
                "Certifying body is not accredited for Standard {}",
                standard_id
            )));
        }
        let latest_standard_version = accreditations.last().unwrap();

        // Create certificate
        let mut new_certificate = proto::certificate::Certificate::new();
        new_certificate.set_id(payload.get_id().to_string());
        new_certificate.set_certifying_body_id(agent.get_organization_id().to_string());
        new_certificate.set_factory_id(factory_id);
        new_certificate.set_standard_id(standard_id);
        new_certificate
            .set_standard_version(latest_standard_version.get_standard_version().to_string());
        new_certificate.set_certificate_data(::protobuf::RepeatedField::from_vec(
            payload.get_certificate_data().to_vec(),
        ));
        new_certificate.set_valid_from(valid_from);
        new_certificate.set_valid_to(valid_to);

        // Put certificate in state
        state.set_certificate(payload.get_id(), new_certificate)?;

        Ok(())
    }

    /// Creates a new Request and submits it to state
    ///
    /// ```
    /// # Errors
    /// Returns an error if
    ///   - a request with the request id already exist
    ///   - an Agent with the signer public key does not exist
    ///   - the Agent submitting the transaction is not associated with the organization
    ///   - the Agent submitting the transaction is not authorized as a TRANSACTOR of the organization
    ///   - the Organization the Agent is associated with is not a Factory
    ///   - the standard does not exist
    ///   - it fails to submit the new Request to state.
    /// ```
    pub fn open_request(
        &self,
        payload: &proto::payload::OpenRequestAction,
        state: &mut CertState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        // Validate that the signer associated with a factory
        let agent = match state.get_agent(signer_public_key) {
            Ok(Some(agent)) => Ok(agent),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No agent exists: {}",
                signer_public_key
            ))),
            Err(err) => Err(err),
        }?;
        let organization = match state.get_organization(agent.get_organization_id()) {
            Ok(Some(organization)) => Ok(organization),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No organization exists: {}",
                agent.get_organization_id()
            ))),
            Err(err) => Err(err),
        }?;
        if organization.get_organization_type() != proto::organization::Organization_Type::FACTORY {
            return Err(ApplyError::InvalidTransaction(format!(
                "Organization {} is not a factory",
                agent.get_organization_id()
            )));
        }

        // Validate that agent is a transactor
        let mut is_transactor = false;
        let authorizations = organization.get_authorizations();
        for authorization in authorizations {
            if authorization.get_public_key() == signer_public_key
                && authorization.get_role()
                    == proto::organization::Organization_Authorization_Role::TRANSACTOR
            {
                is_transactor = true;
                break;
            }
        }
        if !is_transactor {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent {} is not authorized to open a request",
                agent.get_public_key(),
            )));
        }

        // Verify that the request does not already exist
        match state.get_request(&payload.get_id()) {
            Ok(Some(_)) => Err(ApplyError::InvalidTransaction(format!(
                "Request already exists: {}",
                payload.get_id()
            ))),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }?;

        // Validate that the standard_id and version are associated with a valid standard
        match state.get_standard(&payload.get_standard_id()) {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No standard with ID {} exists",
                payload.get_standard_id()
            ))),
            Err(err) => Err(err),
        }?;

        // Create and open new certification request
        let mut request = proto::request::Request::new();
        request.set_id(payload.get_id().to_string());
        request.set_status(proto::request::Request_Status::OPEN);
        request.set_standard_id(payload.get_standard_id().to_string());
        request.set_factory_id(agent.get_organization_id().to_string());
        request.set_request_date(payload.get_request_date());

        // Put new request in state
        state.set_request(&payload.get_id(), request)?;

        Ok(())
    }

    /// Updates an existing Request status and submits it to state
    ///
    /// ```
    /// # Errors
    /// Returns an error if
    ///   - a request with the request id already exist
    ///   - an Agent with the signer public key does not exist
    ///   - the Agent submitting the transaction is not associated with the organization
    ///   - the Agent submitting the transaction is not authorized as a TRANSACTOR of the organization
    ///   - the Organization the Agent is associated with is not a Factory
    ///   - the new request status is not IN_PROGRESS or CLOSED.
    ///   - the current request status is not OPEN or IN_PROGRESS.
    ///   - it fails to submit the updated Request to state.
    /// ```
    pub fn change_request_status(
        &self,
        payload: &proto::payload::ChangeRequestStatusAction,
        state: &mut CertState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        // Verify that the request does exist
        let mut request = match state.get_request(&payload.request_id) {
            Ok(Some(request)) => Ok(request),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "Request does not exists: {}",
                payload.request_id
            ))),
            Err(err) => Err(err),
        }?;

        // Validate that the signer associated with a factory
        let agent = match state.get_agent(signer_public_key) {
            Ok(Some(agent)) => Ok(agent),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No agent exists: {}",
                signer_public_key
            ))),
            Err(err) => Err(err),
        }?;
        let organization = match state.get_organization(agent.get_organization_id()) {
            Ok(Some(organization)) => Ok(organization),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No organization exists: {}",
                agent.get_organization_id()
            ))),
            Err(err) => Err(err),
        }?;

        // Validate that agent is a transactor
        let mut is_transactor = false;
        let authorizations = organization.get_authorizations();
        for authorization in authorizations {
            if authorization.get_public_key() == signer_public_key
                && authorization.get_role()
                    == proto::organization::Organization_Authorization_Role::TRANSACTOR
            {
                is_transactor = true;
                break;
            }
        }
        if !is_transactor {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent {} is not authorized to update request {}",
                agent.get_public_key(),
                request.get_id()
            )));
        }

        if request.get_factory_id() != agent.get_organization_id() {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent {} is not authorized to update request {}",
                agent.get_organization_id(),
                request.get_factory_id()
            )));
        }

        // Validate that the request is not in a finalized state
        let status = request.get_status();
        if status == proto::request::Request_Status::CLOSED
            || status == proto::request::Request_Status::CERTIFIED
        {
            return Err(ApplyError::InvalidTransaction(format!(
                "Once CLOSED or CERTIFIED, the request status can not be modified again.
                Status: {:?}",
                status
            )));
        }

        // Update request status
        request.set_status(payload.get_status());

        // Put updated request in state
        state.set_request(&payload.get_request_id(), request)?;

        Ok(())
    }

    /// Creates a new Standard and submits it to state
    ///
    /// ```
    /// # Errors
    /// Returns an error if
    ///   - a standard with the standard id already exist
    ///   - an Agent with the signer public key does not exist
    ///   - the Agent submitting the transaction is not associated with the organization
    ///   - the Agent submitting the transaction is not authorized as a TRANSACTOR of the organization
    ///   - the Organization the Agent is associated with is not a StandardsBody
    ///   - the standard does not exist
    ///   - it fails to submit the new Standard to state.
    /// ```
    pub fn create_standard(
        &self,
        payload: &proto::payload::CreateStandardAction,
        state: &mut CertState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        // Verify that name is not already associated with a Standard object
        match state.get_standard(&payload.standard_id) {
            Ok(Some(_)) => Err(ApplyError::InvalidTransaction(format!(
                "Standard already exists: {}",
                payload.name
            ))),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }?;

        // Validate signer public key and agent
        let agent = match state.get_agent(signer_public_key) {
            Ok(Some(agent)) => Ok(agent),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No agent exists: {}",
                signer_public_key
            ))),
            Err(err) => Err(err),
        }?;

        if agent.get_organization_id().is_empty() {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent is not associated with an organization: {}",
                agent.get_organization_id(),
            )));
        }

        // Validate org existence
        let organization = match state.get_organization(agent.get_organization_id()) {
            Ok(Some(organization)) => Ok(organization),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No organization exists: {}",
                agent.get_organization_id()
            ))),
            Err(err) => Err(err),
        }?;

        match organization.get_organization_type() {
            proto::organization::Organization_Type::STANDARDS_BODY => Ok(()),
            _ => Err(ApplyError::InvalidTransaction(
                "Organization associated with agent cannot create standards".to_string(),
            )),
        }?;

        // Validate agent is authorized
        let transactor_authorization =
            organization
                .get_authorizations()
                .iter()
                .find(|authorization| {
                    authorization.get_public_key() == signer_public_key
                        && authorization.get_role()
                            == proto::organization::Organization_Authorization_Role::TRANSACTOR
                });
        if transactor_authorization.is_none() {
            return Err(ApplyError::InvalidTransaction(
                "Agent is not authorized to create a certification standard".to_string(),
            ));
        }

        let mut new_standard_version = proto::standard::Standard_StandardVersion::new();
        new_standard_version.set_version(payload.version.clone());
        new_standard_version.set_description(payload.description.clone());
        new_standard_version.set_link(payload.link.clone());
        new_standard_version.set_approval_date(payload.approval_date.clone());

        let mut new_standard = proto::standard::Standard::new();
        new_standard.set_id(payload.standard_id.clone());
        new_standard.set_name(payload.name.clone());
        new_standard.set_organization_id(organization.id.clone());
        new_standard.set_versions(protobuf::RepeatedField::from_vec(vec![
            new_standard_version,
        ]));

        // Put new standard in state
        state.set_standard(&payload.standard_id, new_standard)?;

        Ok(())
    }

    /// Adds a new version of an existing Standard and submits it to state
    ///
    /// ```
    /// # Errors
    /// Returns an error if
    ///   - an standard with the standard id does not exist
    ///   - the same standard version already exists for this standard
    ///   - an Agent with the signer public key does not exist
    ///   - the Agent submitting the transaction is not associated with the organization
    ///   - the Agent submitting the transaction is not authorized as a TRANSACTOR of the organization
    ///   - the Organization the Agent is associated with is not a StandardsBody
    ///   - the standard being updated was not created by the organization of the Agent who signed the transaction
    ///   - it fails to submit the new Standard to state.
    /// ```
    pub fn update_standard(
        &self,
        payload: &proto::payload::UpdateStandardAction,
        state: &mut CertState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        // Verify that name is not already associated with a Standard object
        let mut standard = match state.get_standard(&payload.standard_id)? {
            Some(standard) => Ok(standard),
            None => Err(ApplyError::InvalidTransaction(format!(
                "Standard {} does not exist",
                payload.standard_id
            ))),
        }?;

        let mut versions = standard.get_versions().to_vec();

        if versions
            .iter()
            .any(|version| version.version == payload.version)
        {
            return Err(ApplyError::InvalidTransaction(format!(
                "Version already exists. Version  {}",
                payload.version
            )));
        }

        // Validate signer public key and agent
        let agent = match state.get_agent(signer_public_key) {
            Ok(Some(agent)) => Ok(agent),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "Agent does not exist: {}",
                signer_public_key
            ))),
            Err(err) => Err(err),
        }?;

        if agent.get_organization_id().is_empty() {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent is not associated with an organization: {}",
                agent.get_organization_id(),
            )));
        }

        // Validate org existence
        let organization = match state.get_organization(agent.get_organization_id()) {
            Ok(Some(organization)) => Ok(organization),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "Organization does not exist: {}",
                agent.get_organization_id()
            ))),
            Err(err) => Err(err),
        }?;

        match organization.get_organization_type() {
            proto::organization::Organization_Type::STANDARDS_BODY => Ok(()),
            _ => Err(ApplyError::InvalidTransaction(
                "Organization associated with agent cannot create standards".to_string(),
            )),
        }?;

        // Validate agent is authorized
        let transactor_authorization =
            organization
                .get_authorizations()
                .iter()
                .find(|authorization| {
                    authorization.get_public_key() == signer_public_key
                        && authorization.get_role()
                            == proto::organization::Organization_Authorization_Role::TRANSACTOR
                });
        if transactor_authorization.is_none() {
            return Err(ApplyError::InvalidTransaction(
                "Agent is not authorized to create a certification standard".to_string(),
            ));
        }

        // Validade standard was created by agent's organizatio
        if agent.get_organization_id() != standard.get_organization_id() {
            return Err(ApplyError::InvalidTransaction(format!(
                "Organization {} did not create the certification standard {}",
                organization.get_name(),
                standard.get_name()
            )));
        }

        let mut new_standard_version = proto::standard::Standard_StandardVersion::new();
        new_standard_version.set_version(payload.version.clone());
        new_standard_version.set_description(payload.description.clone());
        new_standard_version.set_link(payload.link.clone());
        new_standard_version.set_approval_date(payload.approval_date.clone());

        versions.push(new_standard_version);

        standard.set_versions(protobuf::RepeatedField::from_vec(versions));

        // Put updated standard in state
        state.set_standard(&standard.id.clone(), standard)?;

        Ok(())
    }

    /// Adds a new accreditation to an existing CertifyingBody organization and submits it to state
    ///
    /// ```
    /// # Errors
    /// Returns an error if
    ///   - an Agent with the signer public key does not exist
    ///   - the Agent submitting the transaction is not associated with the organization
    ///   - the Agent submitting the transaction is not authorized as a TRANSACTOR of the organization
    ///   - the Organization the Agent is associated with is not a StandardsBody
    ///   - the certifying body id does provided in the payload does not identify an existing CertifyingBody organization
    ///   - the standard provided in the payload does not exist
    ///   - the standard was not created by the organization of the Agent who signed the transaction
    ///   - the CertifyingBody is already accredited for the latest version of the standard
    ///   - it fails to submit the new Standard to state.
    /// ```
    pub fn accredit_certifying_body(
        &self,
        payload: &proto::payload::AccreditCertifyingBodyAction,
        state: &mut CertState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        // Verify the signer
        let agent = match state.get_agent(signer_public_key) {
            Ok(Some(agent)) => Ok(agent),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "Agent does not exist: {}",
                signer_public_key
            ))),
            Err(err) => Err(err),
        }?;

        // Verify the signer is associated with a Standards Body
        if agent.get_organization_id().is_empty() {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent is not associated with an organization: {}",
                agent.get_organization_id(),
            )));
        }

        let agent_organization = match state.get_organization(agent.get_organization_id()) {
            Ok(Some(agent_organization)) => Ok(agent_organization),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No organization exists: {}",
                agent.get_organization_id()
            ))),
            Err(err) => Err(err),
        }?;

        match agent_organization.get_organization_type() {
            proto::organization::Organization_Type::STANDARDS_BODY => Ok(()),
            _ => Err(ApplyError::InvalidTransaction(
                "Organization associated with agent cannot accredit Certifying Bodies".to_string(),
            )),
        }?;

        // Verify the signer is an authorized transactor within their organization
        let mut is_transactor = false;
        let authorizations = agent_organization.get_authorizations();
        for authorization in authorizations {
            if authorization.get_public_key() == signer_public_key
                && authorization.get_role()
                    == proto::organization::Organization_Authorization_Role::TRANSACTOR
            {
                is_transactor = true;
                break;
            }
        }
        if !is_transactor {
            return Err(ApplyError::InvalidTransaction(format!(
                "Agent {} is not authorized to accredit certifying body: {}",
                signer_public_key,
                payload.get_certifying_body_id(),
            )));
        }

        // Verify the certifying_body_id is associated with a Certifying body
        let mut certifying_body = match state.get_organization(payload.get_certifying_body_id()) {
            Ok(Some(certifying_body)) => Ok(certifying_body),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No organization exists: {}",
                payload.get_certifying_body_id(),
            ))),
            Err(err) => Err(err),
        }?;

        match certifying_body.get_organization_type() {
            proto::organization::Organization_Type::CERTIFYING_BODY => Ok(()),
            _ => Err(ApplyError::InvalidTransaction(
                "Only Certifying Bodies may be accredited".to_string(),
            )),
        }?;

        // Verify the name is associated with an existing standard
        let standard = match state.get_standard(&payload.get_standard_id()) {
            Ok(Some(standard)) => Ok(standard),
            Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                "No standard with ID {} exists",
                payload.get_standard_id()
            ))),
            Err(err) => Err(err),
        }?;

        // Verify the agent's organization created the standard
        if agent.get_organization_id() != standard.get_organization_id() {
            return Err(ApplyError::InvalidTransaction(format!(
                "Signer's associated organization did not create the certification standard {}",
                standard.get_name()
            )));
        }

        let mut certifying_body_details = certifying_body.get_certifying_body_details().clone();

        let mut accreditations = certifying_body_details.get_accreditations().to_vec();

        let standard_versions = standard.get_versions().to_vec();
        let latest_standard_version = match standard_versions.last() {
            Some(valid_version) => valid_version,
            None => {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Invalid version for Standard {}",
                    standard.get_id()
                )));
            }
        };

        if accreditations.iter().any(|accreditation| {
            accreditation.get_standard_id() == payload.get_standard_id()
                && accreditation.get_standard_version() == latest_standard_version.get_version()
        }) {
            return Err(ApplyError::InvalidTransaction(format!(
                "Accreditation for Standard {}, version {} already exists",
                payload.get_standard_id(),
                latest_standard_version.get_version().to_string(),
            )));
        }

        // Verify the date
        let valid_from = payload.get_valid_from();
        if valid_from < latest_standard_version.get_approval_date() {
            return Err(ApplyError::InvalidTransaction(
                "Invalid date, Standard is not valid from this date".to_string(),
            ));
        }

        let valid_to = payload.get_valid_to();
        if valid_to < valid_from {
            return Err(ApplyError::InvalidTransaction(
                "Invalid dates. Valid to must be after valid from".to_string(),
            ));
        }

        let mut new_accreditation = proto::organization::CertifyingBody_Accreditation::new();
        new_accreditation.set_standard_id(payload.get_standard_id().to_string());
        new_accreditation.set_standard_version(latest_standard_version.get_version().to_string());
        new_accreditation.set_accreditor_id(agent_organization.get_id().to_string());
        new_accreditation.set_valid_to(payload.get_valid_to());
        new_accreditation.set_valid_from(payload.get_valid_from());

        accreditations.push(new_accreditation);
        certifying_body_details
            .set_accreditations(protobuf::RepeatedField::from_vec(accreditations));

        certifying_body.set_certifying_body_details(certifying_body_details);

        // Put updated CertifyingBody in state
        state.set_organization(payload.get_certifying_body_id(), certifying_body)?;

        Ok(())
    }
}

impl TransactionHandler for CertTransactionHandler {
    fn family_name(&self) -> String {
        self.family_name.clone()
    }

    fn family_versions(&self) -> Vec<String> {
        self.family_versions.clone()
    }

    fn namespaces(&self) -> Vec<String> {
        self.namespaces.clone()
    }

    /// Applies the correct transaction logic depending on the payload action type.
    /// It will use helper methods to perform all payload validation that requires
    /// fetching data from state. If the payload is valid it will apply the changes
    /// to state.
    ///
    /// ```
    /// # Errors
    /// Returns an error if the transaction fails
    /// ```
    fn apply(
        &self,
        request: &TpProcessRequest,
        context: &mut dyn TransactionContext,
    ) -> Result<(), ApplyError> {
        let header = request.get_header();
        let signer_public_key = header.get_signer_public_key();

        // Return an action enum as the payload
        let payload = CertPayload::new(request.get_payload())?;
        let mut state = CertState::new(context);

        match payload.get_action() {
            Action::CreateAgent(payload) => {
                self.create_agent(&payload, &mut state, signer_public_key)
            }

            Action::CreateOrganization(payload) => {
                self.create_organization(&payload, &mut state, signer_public_key)
            }

            Action::UpdateOrganization(payload) => {
                self.update_organization(&payload, &mut state, signer_public_key)
            }

            Action::AuthorizeAgent(payload) => {
                self.authorize_agent(&payload, &mut state, signer_public_key)
            }

            Action::IssueCertificate(payload) => {
                self.issue_certificate(&payload, &mut state, signer_public_key)
            }
            Action::CreateStandard(payload) => {
                self.create_standard(&payload, &mut state, signer_public_key)
            }
            Action::UpdateStandard(payload) => {
                self.update_standard(&payload, &mut state, signer_public_key)
            }
            Action::OpenRequest(payload) => {
                self.open_request(&payload, &mut state, signer_public_key)
            }
            Action::ChangeRequestStatus(payload) => {
                self.change_request_status(&payload, &mut state, signer_public_key)
            }
            Action::AccreditCertifyingBody(payload) => {
                self.accredit_certifying_body(&payload, &mut state, signer_public_key)
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]

// If the TP will be compiled to WASM to be run as a smart contract in Sabre this apply method will be
// used as wrapper for the handler apply method. For Sabre the apply must return a boolean
fn apply(
    request: &TpProcessRequest,
    context: &mut dyn TransactionContext,
) -> Result<bool, ApplyError> {
    let handler = CertTransactionHandler::new();
    match handler.apply(request, context) {
        Ok(_) => Ok(true),
        Err(err) => Err(err),
    }
}

#[allow(dead_code)]
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe fn entrypoint(payload: WasmPtr, signer: WasmPtr, signature: WasmPtr) -> i32 {
    execute_entrypoint(payload, signer, signature, apply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::proto::payload::*;

    use std::cell::RefCell;
    use std::collections::HashMap;

    use sawtooth_sdk::processor::handler::{ContextError, TransactionContext};

    const PUBLIC_KEY_1: &str = "test_public_key_1";
    const PUBLIC_KEY_2: &str = "test_public_key_2";
    const PUBLIC_KEY_3: &str = "test_public_key_3";
    const CERT_ORG_ID: &str = "test_cert_org";
    const FACTORY_ID: &str = "test_factory";
    const STANDARDS_BODY_ID: &str = "test_standards_body";
    const CERT_ID: &str = "test_cert";
    const REQUEST_ID: &str = "test_request";
    const STANDARD_ID: &str = "test_standard";

    #[derive(Default, Debug)]
    /// A MockTransactionContext that can be used to test
    struct MockTransactionContext {
        state: RefCell<HashMap<String, Vec<u8>>>,
    }

    impl TransactionContext for MockTransactionContext {
        fn get_state_entries(
            &self,
            addresses: &[String],
        ) -> Result<Vec<(String, Vec<u8>)>, ContextError> {
            let mut results = Vec::new();
            for addr in addresses {
                let data = match self.state.borrow().get(addr) {
                    Some(data) => data.clone(),
                    None => Vec::new(),
                };
                results.push((addr.to_string(), data));
            }
            Ok(results)
        }

        fn set_state_entries(&self, entries: Vec<(String, Vec<u8>)>) -> Result<(), ContextError> {
            for (addr, data) in entries {
                self.state.borrow_mut().insert(addr, data);
            }
            Ok(())
        }

        /// this is not needed for these tests
        fn delete_state_entries(&self, _addresses: &[String]) -> Result<Vec<String>, ContextError> {
            unimplemented!()
        }

        /// this is not needed for these tests
        fn add_receipt_data(&self, _data: &[u8]) -> Result<(), ContextError> {
            unimplemented!()
        }

        /// this is not needed for these tests
        fn add_event(
            &self,
            _event_type: String,
            _attributes: Vec<(String, String)>,
            _data: &[u8],
        ) -> Result<(), ContextError> {
            unimplemented!()
        }
    }

    #[test]
    /// Test that if CreateAgentAction is valid an OK is returned and a new Agent is added to state
    fn test_create_agent_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);
        let transaction_handler = CertTransactionHandler::new();
        let action = make_agent_create_action();

        assert!(transaction_handler
            .create_agent(&action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let agent = state
            .get_agent(PUBLIC_KEY_1)
            .expect("Failed to fetch agent")
            .expect("No agent found");

        assert_eq!(agent, make_agent(PUBLIC_KEY_1));
    }

    #[test]
    /// Test that if CreateOrganizationAction is valid an OK is returned and a new Organization is added to state
    fn test_create_organization_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);
        let transaction_handler = CertTransactionHandler::new();
        //add agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );

        assert!(transaction_handler
            .create_organization(&action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let org = state
            .get_organization(STANDARDS_BODY_ID)
            .expect("Failed to fetch organization")
            .expect("No organization found");

        assert_eq!(
            org,
            make_organization(
                STANDARDS_BODY_ID,
                proto::organization::Organization_Type::STANDARDS_BODY,
                PUBLIC_KEY_1
            )
        );
    }

    #[test]
    /// Test that if UpdateOrganizationAction is valid an OK is returned and the Organization is updated in state
    fn test_update_organization_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);
        let transaction_handler = CertTransactionHandler::new();
        //add agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let action = make_organization_update_action();

        assert!(transaction_handler
            .update_organization(&action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let org = state
            .get_organization(STANDARDS_BODY_ID)
            .expect("Failed to fetch organization")
            .expect("No organization found");

        assert_eq!(
            org,
            make_organization_update(
                STANDARDS_BODY_ID,
                proto::organization::Organization_Type::STANDARDS_BODY,
                PUBLIC_KEY_1
            )
        );
    }

    #[test]
    /// Test that if AuthorizeAgentAction is valid an OK is returned and a new Authorization is added to state
    fn test_authorize_agent_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);
        let transaction_handler = CertTransactionHandler::new();
        //add agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add second agent
        let second_agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&second_agent_action, &mut state, PUBLIC_KEY_2)
            .unwrap();

        let action = make_authorize_agent_action(PUBLIC_KEY_2);

        assert!(transaction_handler
            .authorize_agent(&action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let organization = state
            .get_organization(STANDARDS_BODY_ID)
            .expect("Failed to fetch Organization")
            .expect("No Organization found");
        //Find the new authorization in the organization, if it exists
        let authorization = organization.get_authorizations().iter().find(|auth| {
            auth.get_public_key() == PUBLIC_KEY_2
                && auth.get_role()
                    == proto::organization::Organization_Authorization_Role::TRANSACTOR
        });

        assert!(authorization.is_some());
    }

    #[test]
    /// Test that if IssueCertificateAction is valid an OK is returned and a new Certificate is added to state
    fn test_issue_certificate_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);
        let transaction_handler = CertTransactionHandler::new();
        //add agent
        let standard_agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&standard_agent_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add org
        let standard_org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        transaction_handler
            .create_organization(&standard_org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        transaction_handler
            .create_standard(&standard_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add second agent
        let factory_agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&factory_agent_action, &mut state, PUBLIC_KEY_2)
            .unwrap();
        //add factory org
        let factory_org_action = make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        );
        transaction_handler
            .create_organization(&factory_org_action, &mut state, PUBLIC_KEY_2)
            .unwrap();
        //add third agent
        let cert_agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&cert_agent_action, &mut state, PUBLIC_KEY_3)
            .unwrap();
        //add certifying org
        let cert_org_action = make_organization_create_action(
            CERT_ORG_ID,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        );
        transaction_handler
            .create_organization(&cert_org_action, &mut state, PUBLIC_KEY_3)
            .unwrap();
        //accredit the cert org
        let accredit_action = make_accredit_certifying_body_action();
        transaction_handler
            .accredit_certifying_body(&accredit_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let action = make_issue_certificate_action();

        assert!(transaction_handler
            .issue_certificate(&action, &mut state, PUBLIC_KEY_3)
            .is_ok());

        let certificate = state
            .get_certificate(CERT_ID)
            .expect("Failed to fetch certificate")
            .expect("No certificate found");

        assert_eq!(certificate, make_certificate());
    }

    #[test]
    /// Test that if CreateStandardAction is valid an OK is returned and a new Standard is added to state
    fn test_create_standard_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);
        let transaction_handler = CertTransactionHandler::new();
        //add agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let action = make_standard_create_action();

        assert!(transaction_handler
            .create_standard(&action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let standard = state
            .get_standard(STANDARD_ID)
            .expect("Failed to fetch Standard")
            .expect("No Standard found");

        assert_eq!(standard, make_standard());
    }

    #[test]
    /// Test that if UpdateStandardAction is valid an OK is returned and the Standard is changed in state
    fn test_update_standard_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);
        let transaction_handler = CertTransactionHandler::new();
        //add agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        transaction_handler
            .create_standard(&standard_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let action = make_standard_update_action();

        assert!(transaction_handler
            .update_standard(&action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let standard = state
            .get_standard(STANDARD_ID)
            .expect("Failed to fetch Standard")
            .expect("No Standard found");

        assert_eq!(standard, make_standard_update());
    }

    #[test]
    /// Test that if OpenRequestAction is valid an OK is returned and a new Request is added to state
    fn test_open_request_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);
        let transaction_handler = CertTransactionHandler::new();
        //add agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add org
        let org_action = make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_2)
            .unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_2)
            .unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        transaction_handler
            .create_standard(&standard_action, &mut state, PUBLIC_KEY_2)
            .unwrap();

        let action = make_open_request_action();

        assert!(transaction_handler
            .open_request(&action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let request = state
            .get_request(REQUEST_ID)
            .expect("Failed to fetch Request")
            .expect("No Request found");

        assert_eq!(request, make_request());
    }

    #[test]
    /// Test that if ChangeRequestStatusAction is valid an OK is returned and the Request is updated in state
    fn test_change_request_status_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);
        let transaction_handler = CertTransactionHandler::new();
        //add agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add org
        let org_action = make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_2)
            .unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_2)
            .unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        transaction_handler
            .create_standard(&standard_action, &mut state, PUBLIC_KEY_2)
            .unwrap();

        let request_action = make_open_request_action();
        transaction_handler
            .open_request(&request_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let action = make_change_request_action();

        assert!(transaction_handler
            .change_request_status(&action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let request = state
            .get_request(REQUEST_ID)
            .expect("Failed to fetch Request")
            .expect("No Request found");

        assert_eq!(request, make_request_update());
    }

    #[test]
    /// Test that if AccreditCertifyingBodyAction is valid an OK is returned and a new Accreditation is added to state
    fn test_accredit_certifying_body_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);
        let transaction_handler = CertTransactionHandler::new();
        //add agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_2)
            .unwrap();
        //add certifying org
        let org_action = make_organization_create_action(
            CERT_ORG_ID,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_2)
            .unwrap();
        //add standard
        let standard = make_standard_create_action();
        transaction_handler
            .create_standard(&standard, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let action = make_accredit_certifying_body_action();

        assert!(transaction_handler
            .accredit_certifying_body(&action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let certifying_body = state
            .get_organization(CERT_ORG_ID)
            .expect("Failed to fetch Certifying Body")
            .expect("No Certifying Body found");

        let certifying_body_details = certifying_body.get_certifying_body_details().clone();
        let accreditations = certifying_body_details.get_accreditations().to_vec();

        assert!(accreditations
            .iter()
            .any(|accreditation| { accreditation.get_standard_id() == STANDARD_ID }));
    }

    fn make_agent(pub_key: &str) -> proto::agent::Agent {
        let mut new_agent = proto::agent::Agent::new();
        new_agent.set_public_key(pub_key.to_string());
        new_agent.set_name("test".to_string());

        new_agent
    }

    fn make_organization(
        org_id: &str,
        org_type: proto::organization::Organization_Type,
        signer_public_key: &str,
    ) -> proto::organization::Organization {
        let mut new_org = proto::organization::Organization::new();
        new_org.set_id(org_id.to_string());
        new_org.set_name("test".to_string());
        new_org.set_organization_type(org_type);

        let mut admin_authorization = proto::organization::Organization_Authorization::new();
        admin_authorization.set_public_key(signer_public_key.to_string());
        admin_authorization.set_role(proto::organization::Organization_Authorization_Role::ADMIN);

        let mut transactor_authorization = proto::organization::Organization_Authorization::new();
        transactor_authorization.set_public_key(signer_public_key.to_string());
        transactor_authorization
            .set_role(proto::organization::Organization_Authorization_Role::TRANSACTOR);

        new_org.set_authorizations(::protobuf::RepeatedField::from_vec(vec![
            admin_authorization,
            transactor_authorization,
        ]));

        let mut new_contact = proto::organization::Organization_Contact::new();
        new_contact.set_name("test".to_string());
        new_contact.set_phone_number("test".to_string());
        new_contact.set_language_code("test".to_string());
        new_org.set_contacts(protobuf::RepeatedField::from_vec(vec![new_contact]));

        if org_type == proto::organization::Organization_Type::FACTORY {
            let mut factory_details = proto::organization::Factory::new();
            let mut address = proto::organization::Factory_Address::new();
            address.set_street_line_1("test".to_string());
            address.set_city("test".to_string());
            address.set_state_province("test".to_string());
            address.set_country("test".to_string());
            address.set_postal_code("test".to_string());
            factory_details.set_address(address);
            new_org.set_factory_details(factory_details);
        }

        new_org
    }

    fn make_organization_update(
        org_id: &str,
        org_type: proto::organization::Organization_Type,
        signer_public_key: &str,
    ) -> proto::organization::Organization {
        let mut new_org = proto::organization::Organization::new();
        new_org.set_id(org_id.to_string());
        new_org.set_name("test".to_string());
        new_org.set_organization_type(org_type);

        let mut admin_authorization = proto::organization::Organization_Authorization::new();
        admin_authorization.set_public_key(signer_public_key.to_string());
        admin_authorization.set_role(proto::organization::Organization_Authorization_Role::ADMIN);

        let mut transactor_authorization = proto::organization::Organization_Authorization::new();
        transactor_authorization.set_public_key(signer_public_key.to_string());
        transactor_authorization
            .set_role(proto::organization::Organization_Authorization_Role::TRANSACTOR);

        new_org.set_authorizations(::protobuf::RepeatedField::from_vec(vec![
            admin_authorization,
            transactor_authorization,
        ]));

        let mut new_contact = proto::organization::Organization_Contact::new();
        new_contact.set_name("test_change".to_string());
        new_contact.set_phone_number("test_change".to_string());
        new_contact.set_language_code("test_change".to_string());
        new_org.set_contacts(protobuf::RepeatedField::from_vec(vec![new_contact]));

        if org_type == proto::organization::Organization_Type::FACTORY {
            let mut factory_details = proto::organization::Factory::new();
            let mut address = proto::organization::Factory_Address::new();
            address.set_street_line_1("test_change".to_string());
            address.set_city("test_change".to_string());
            address.set_state_province("test_change".to_string());
            address.set_country("test_change".to_string());
            address.set_postal_code("test_change".to_string());
            factory_details.set_address(address);
            new_org.set_factory_details(factory_details);
        }

        new_org
    }

    fn make_certificate() -> proto::certificate::Certificate {
        let mut new_certificate = proto::certificate::Certificate::new();
        new_certificate.set_id(CERT_ID.to_string());
        new_certificate.set_certifying_body_id(CERT_ORG_ID.to_string());
        new_certificate.set_factory_id(FACTORY_ID.to_string());
        new_certificate.set_standard_id(STANDARD_ID.to_string());
        new_certificate.set_standard_version("test".to_string());
        new_certificate.set_valid_from(1);
        new_certificate.set_valid_to(2);

        new_certificate
    }

    fn make_request() -> proto::request::Request {
        let mut request = proto::request::Request::new();
        request.set_id(REQUEST_ID.to_string());
        request.set_status(proto::request::Request_Status::OPEN);
        request.set_standard_id(STANDARD_ID.to_string());
        request.set_factory_id(FACTORY_ID.to_string());
        request.set_request_date(1);

        request
    }

    fn make_request_update() -> proto::request::Request {
        let mut request = proto::request::Request::new();
        request.set_id(REQUEST_ID.to_string());
        request.set_status(proto::request::Request_Status::IN_PROGRESS);
        request.set_standard_id(STANDARD_ID.to_string());
        request.set_factory_id(FACTORY_ID.to_string());
        request.set_request_date(1);

        request
    }

    fn make_standard() -> proto::standard::Standard {
        let mut new_standard_version = proto::standard::Standard_StandardVersion::new();
        new_standard_version.set_version("test".to_string());
        new_standard_version.set_description("test".to_string());
        new_standard_version.set_link("test".to_string());
        new_standard_version.set_approval_date(1);

        let mut new_standard = proto::standard::Standard::new();
        new_standard.set_id(STANDARD_ID.to_string());
        new_standard.set_name("test".to_string());
        new_standard.set_organization_id(STANDARDS_BODY_ID.to_string());
        new_standard.set_versions(protobuf::RepeatedField::from_vec(vec![
            new_standard_version,
        ]));

        new_standard
    }

    fn make_standard_update() -> proto::standard::Standard {
        let mut old_standard_version = proto::standard::Standard_StandardVersion::new();
        old_standard_version.set_version("test".to_string());
        old_standard_version.set_description("test".to_string());
        old_standard_version.set_link("test".to_string());
        old_standard_version.set_approval_date(1);

        let mut new_standard_version = proto::standard::Standard_StandardVersion::new();
        new_standard_version.set_version("test_change".to_string());
        new_standard_version.set_description("test_change".to_string());
        new_standard_version.set_link("test_change".to_string());
        new_standard_version.set_approval_date(1);

        let mut new_standard = proto::standard::Standard::new();
        new_standard.set_id(STANDARD_ID.to_string());
        new_standard.set_name("test".to_string());
        new_standard.set_organization_id(STANDARDS_BODY_ID.to_string());
        new_standard.set_versions(protobuf::RepeatedField::from_vec(vec![
            old_standard_version,
            new_standard_version,
        ]));

        new_standard
    }

    fn make_agent_create_action() -> CreateAgentAction {
        let mut new_agent_action = CreateAgentAction::new();
        new_agent_action.set_name("test".to_string());
        new_agent_action
    }

    fn make_organization_create_action(
        org_id: &str,
        org_type: proto::organization::Organization_Type,
    ) -> CreateOrganizationAction {
        let mut new_org_action = CreateOrganizationAction::new();
        new_org_action.set_id(org_id.to_string());
        new_org_action.set_organization_type(org_type);
        new_org_action.set_name("test".to_string());
        let mut new_contact = proto::organization::Organization_Contact::new();
        new_contact.set_name("test".to_string());
        new_contact.set_phone_number("test".to_string());
        new_contact.set_language_code("test".to_string());
        new_org_action.set_contacts(protobuf::RepeatedField::from_vec(vec![new_contact]));

        if org_type == proto::organization::Organization_Type::FACTORY {
            //let mut factory_details = proto::organization::Factory::new();
            let mut address = proto::organization::Factory_Address::new();
            address.set_street_line_1("test".to_string());
            address.set_city("test".to_string());
            address.set_state_province("test".to_string());
            address.set_country("test".to_string());
            address.set_postal_code("test".to_string());
            //factory_details.set_address(address);
            new_org_action.set_address(address);
        }

        new_org_action
    }

    fn make_organization_update_action() -> UpdateOrganizationAction {
        let mut org_update_action = UpdateOrganizationAction::new();
        let mut new_contact = proto::organization::Organization_Contact::new();
        new_contact.set_name("test_change".to_string());
        new_contact.set_phone_number("test_change".to_string());
        new_contact.set_language_code("test_change".to_string());
        org_update_action.set_contacts(protobuf::RepeatedField::from_vec(vec![new_contact]));
        org_update_action
    }

    fn make_authorize_agent_action(pub_key: &str) -> AuthorizeAgentAction {
        let mut new_auth_action = AuthorizeAgentAction::new();
        new_auth_action.set_public_key(pub_key.to_string());
        new_auth_action.set_role(proto::organization::Organization_Authorization_Role::TRANSACTOR);
        new_auth_action
    }

    fn make_issue_certificate_action() -> IssueCertificateAction {
        let mut issuance_action = IssueCertificateAction::new();
        issuance_action.set_id(CERT_ID.to_string());
        issuance_action.set_source(IssueCertificateAction_Source::INDEPENDENT);
        issuance_action.set_standard_id(STANDARD_ID.to_string());
        issuance_action.set_factory_id(FACTORY_ID.to_string());
        issuance_action.set_valid_from(1);
        issuance_action.set_valid_to(2);
        issuance_action
    }

    fn make_standard_create_action() -> CreateStandardAction {
        let mut new_standard_action = CreateStandardAction::new();
        new_standard_action.set_standard_id(STANDARD_ID.to_string());
        new_standard_action.set_name("test".to_string());
        new_standard_action.set_version("test".to_string());
        new_standard_action.set_description("test".to_string());
        new_standard_action.set_link("test".to_string());
        new_standard_action.set_approval_date(1);
        new_standard_action
    }

    fn make_standard_update_action() -> UpdateStandardAction {
        let mut standard_update_action = UpdateStandardAction::new();
        standard_update_action.set_standard_id(STANDARD_ID.to_string());
        standard_update_action.set_version("test_change".to_string());
        standard_update_action.set_description("test_change".to_string());
        standard_update_action.set_link("test_change".to_string());
        standard_update_action.set_approval_date(1);
        standard_update_action
    }

    fn make_open_request_action() -> OpenRequestAction {
        let mut new_request_action = OpenRequestAction::new();
        new_request_action.set_id(REQUEST_ID.to_string());
        new_request_action.set_standard_id(STANDARD_ID.to_string());
        new_request_action.set_request_date(1);
        new_request_action
    }

    fn make_change_request_action() -> ChangeRequestStatusAction {
        let mut change_request_action = ChangeRequestStatusAction::new();
        change_request_action.set_request_id(REQUEST_ID.to_string());
        change_request_action.set_status(proto::request::Request_Status::IN_PROGRESS);
        change_request_action
    }

    fn make_accredit_certifying_body_action() -> AccreditCertifyingBodyAction {
        let mut accredit_action = AccreditCertifyingBodyAction::new();
        accredit_action.set_certifying_body_id(CERT_ORG_ID.to_string());
        accredit_action.set_standard_id(STANDARD_ID.to_string());
        accredit_action.set_valid_from(1);
        accredit_action.set_valid_to(2);
        accredit_action
    }
}
