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
use common::proto::organization::Organization_Authorization_Role::{ADMIN, TRANSACTOR};
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
        let mut agent = get_agent(state, signer_public_key)?;

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
        let new_organization = make_organization(&payload, signer_public_key);

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
        let agent = get_agent(state, signer_public_key)?;

        // Check agent's organization
        check_agent_has_org(&agent)?;

        let mut organization = get_organization(state, agent.get_organization_id())?;

        // Validate agent is authorized
        check_authorization(&organization, signer_public_key, ADMIN)?;

        // Handle updates
        if payload.has_address() {
            check_org_type(
                &organization,
                proto::organization::Organization_Type::FACTORY,
            )?;

            let mut updated_factory_details = organization.factory_details.get_ref().clone();
            updated_factory_details.set_address(payload.address.get_ref().clone());
            organization.set_factory_details(updated_factory_details);
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
        let signer_agent = get_agent(state, signer_public_key)?;

        // Validate signer is associated with an organization
        check_agent_has_org(&signer_agent)?;

        // Validate the organization the signer is associated with exists
        let mut organization = get_organization(state, signer_agent.get_organization_id())?;

        // Validate signer agent is an ADMIN
        check_authorization(&organization, signer_public_key, ADMIN)?;

        // Validate agent to be authorized exists.
        let mut agent_to_be_authorized = get_agent(state, payload.get_public_key())?;

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
        let agent = get_agent(state, signer_public_key)?;

        check_agent_has_org(&agent)?;

        // Validate org existence
        let organization = get_organization(state, agent.get_organization_id())?;

        check_org_type(
            &organization,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        )?;

        // Validate agent is authorized
        check_authorization(&organization, signer_public_key, TRANSACTOR)?;

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
                get_organization(state, &payload.get_factory_id())?;
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
        let agent = get_agent(state, signer_public_key)?;
        let organization = get_organization(state, agent.get_organization_id())?;

        check_org_type(
            &organization,
            proto::organization::Organization_Type::FACTORY,
        )?;

        // Validate that agent is a transactor
        check_authorization(&organization, signer_public_key, TRANSACTOR)?;

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
        let agent = get_agent(state, signer_public_key)?;
        let organization = get_organization(state, agent.get_organization_id())?;

        // Validate that agent is a transactor
        check_authorization(&organization, signer_public_key, TRANSACTOR)?;

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
        let agent = get_agent(state, signer_public_key)?;

        check_agent_has_org(&agent)?;

        // Validate org existence
        let organization = get_organization(state, agent.get_organization_id())?;

        check_org_type(
            &organization,
            proto::organization::Organization_Type::STANDARDS_BODY,
        )?;

        // Validate agent is authorized
        check_authorization(&organization, signer_public_key, TRANSACTOR)?;

        let new_standard = make_standard(payload, &organization.get_id());

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
                "Version already exists. Version {}",
                payload.version
            )));
        }

        // Validate signer public key and agent
        let agent = get_agent(state, signer_public_key)?;

        check_agent_has_org(&agent)?;

        // Validate org existence
        let organization = get_organization(state, agent.get_organization_id())?;

        check_org_type(
            &organization,
            proto::organization::Organization_Type::STANDARDS_BODY,
        )?;

        // Validate agent is authorized
        check_authorization(&organization, signer_public_key, TRANSACTOR)?;

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
        let agent = get_agent(state, signer_public_key)?;

        // Verify the signer is associated with a Standards Body
        check_agent_has_org(&agent)?;

        let agent_organization = get_organization(state, agent.get_organization_id())?;

        check_org_type(
            &agent_organization,
            proto::organization::Organization_Type::STANDARDS_BODY,
        )?;

        // Verify the signer is an authorized transactor within their organization
        check_authorization(&agent_organization, signer_public_key, TRANSACTOR)?;

        // Verify the certifying_body_id is associated with a Certifying body
        let mut certifying_body = get_organization(state, payload.get_certifying_body_id())?;

        check_org_type(
            &certifying_body,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        )?;

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

        let standard_compare =
            |accreditation: &proto::organization::CertifyingBody_Accreditation| -> bool {
                accreditation.get_standard_id() == payload.get_standard_id()
                    && accreditation.get_standard_version() == latest_standard_version.get_version()
            };

        if accreditations.iter().any(standard_compare) {
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

    /// Creates a new assertion and submits it to state along with the object of the assertion
    ///
    /// ```
    /// # Errors
    /// Returns an error if
    ///   - an Agent with the signer public key does not exist
    ///   - the Agent submitting the transaction is not associated with an organization
    ///   - an Assertion with the provided ID already exists
    ///   - the Certificate provided has invalid dates
    ///   - the Certificate provided is not set to Independent Source
    ///   - the Standard of the Certificate does not exist
    ///   - the Factory of the Certificate does not exist
    ///   - the AssertAction contained no assertion (factory, certificate, or standard)
    ///   - it fails to submit the new Assertion to state.
    /// ```
    pub fn create_assertion(
        &self,
        payload: &proto::payload::AssertAction,
        state: &mut CertState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        // Verify the signer
        let agent = get_agent(state, signer_public_key)?;
        // Check agent's organization
        check_agent_has_org(&agent)?;

        let organization = get_organization(state, agent.get_organization_id())?;

        check_org_type(
            &organization,
            proto::organization::Organization_Type::INGESTION,
        )?;

        // Validate that agent is a transactor
        check_authorization(&organization, signer_public_key, TRANSACTOR)?;

        match state.get_assertion(payload.get_assertion_id()) {
            Ok(Some(_)) => Err(ApplyError::InvalidTransaction(format!(
                "Assertion with ID {} already exists",
                payload.get_assertion_id()
            ))),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }?;

        let (assertion_type, object_id, data_id) = if payload.has_new_factory() {
            let factory_assertion = payload.get_new_factory();
            // contains new data about existing factory
            let new_organization =
                make_organization(&factory_assertion.get_factory(), signer_public_key);
            // Put organization in state
            state.set_organization(factory_assertion.get_factory().get_id(), new_organization)?;
            (
                proto::assertion::Assertion_Type::FACTORY,
                factory_assertion.get_factory().get_id(),
                Some(factory_assertion.get_existing_factory_id()),
            )
        } else if payload.has_new_certificate() {
            let certificate = payload.get_new_certificate();
            // Validate current issue date
            if certificate.get_valid_to() < certificate.get_valid_from() {
                return Err(ApplyError::InvalidTransaction(
                    "Invalid dates. Valid to must be after valid from".to_string(),
                ));
            }
            // Ensure the certificate has an independent source and the factory exists
            match certificate.get_source() {
                proto::payload::IssueCertificateAction_Source::INDEPENDENT => {
                    // will error if the factory does not exist
                    get_organization(state, &certificate.get_factory_id())?;
                }
                _ => {
                    return Err(ApplyError::InvalidTransaction(
                        "The `IssueCertificateAction_Source` of a Certificate Assertion must be
                        `INDEPENDENT` to indicate no request was made"
                            .to_string(),
                    ));
                }
            }

            let standard = match state.get_standard(&certificate.get_standard_id())? {
                Some(standard) => Ok(standard),
                None => Err(ApplyError::InvalidTransaction(format!(
                    "Standard {} does not exist",
                    certificate.get_standard_id()
                ))),
            }?;

            let versions = standard.get_versions().to_vec();
            let new_certificate = make_certificate(
                certificate,
                agent.get_organization_id(),
                versions.last().unwrap().get_version(),
            );
            state.set_certificate(certificate.get_id(), new_certificate)?;
            (
                proto::assertion::Assertion_Type::CERTIFICATE,
                certificate.get_id(),
                None,
            )
        } else if payload.has_new_standard() {
            let new_standard =
                make_standard(payload.get_new_standard(), agent.get_organization_id());
            state.set_standard(payload.get_new_standard().get_standard_id(), new_standard)?;
            (
                proto::assertion::Assertion_Type::STANDARD,
                payload.get_new_standard().get_standard_id(),
                None,
            )
        } else {
            return Err(ApplyError::InvalidTransaction(
                "AssertAction did not contain any valid data".to_string(),
            ));
        };
        // Last step: add assertion to state that references the previous data
        let mut assertion = proto::assertion::Assertion::new();
        assertion.set_id(payload.get_assertion_id().to_string());
        assertion.set_assertor_pub_key(signer_public_key.to_string());
        assertion.set_assertion_type(assertion_type);
        assertion.set_object_id(object_id.to_string());
        // only need data_id if existing_factory_id
        if let Some(data_id) = data_id {
            assertion.set_data_id(data_id.to_string());
        }
        state.set_assertion(payload.get_assertion_id(), assertion)?;
        Ok(())
    }
}

/// Getter helper functions that wrap state getters

/// Helper to get agent from state based on public key
fn get_agent(
    state: &mut CertState,
    signer_public_key: &str,
) -> Result<proto::agent::Agent, ApplyError> {
    match state.get_agent(signer_public_key) {
        Ok(Some(agent)) => Ok(agent),
        Ok(None) => Err(ApplyError::InvalidTransaction(format!(
            "No agent with public key {} exists",
            signer_public_key
        ))),
        Err(err) => Err(err),
    }
}

/// Helper to get organization from state based on id
fn get_organization(
    state: &mut CertState,
    organization_id: &str,
) -> Result<proto::organization::Organization, ApplyError> {
    match state.get_organization(organization_id) {
        Ok(Some(organization)) => Ok(organization),
        Ok(None) => Err(ApplyError::InvalidTransaction(format!(
            "No organization with ID {} exists",
            organization_id
        ))),
        Err(err) => Err(err),
    }
}

/// Helper to check whether the agent has the proper authorization
fn check_authorization(
    organization: &proto::organization::Organization,
    signer_public_key: &str,
    role: proto::organization::Organization_Authorization_Role,
) -> Result<(), ApplyError> {
    let is_role = organization
        .get_authorizations()
        .iter()
        .find(|authorization| {
            authorization.get_public_key() == signer_public_key && authorization.get_role() == role
        });
    if is_role.is_none() {
        return Err(ApplyError::InvalidTransaction(format!(
            "Agent is not authorized as a{} for organization with ID: {}",
            match role {
                ADMIN => "n admin",
                TRANSACTOR => " transactor",
                _ => "n unset role",
            },
            organization.get_id()
        )));
    }
    Ok(())
}

/// Helper to check whether the agent is a member of an organization
fn check_agent_has_org(agent: &proto::agent::Agent) -> Result<(), ApplyError> {
    if agent.get_organization_id().is_empty() {
        return Err(ApplyError::InvalidTransaction(format!(
            "Agent is not associated with an organization: {}",
            agent.get_organization_id(),
        )));
    }
    Ok(())
}

/// Helper to check whether the organization is the expected type
fn check_org_type(
    organization: &proto::organization::Organization,
    org_type: proto::organization::Organization_Type,
) -> Result<(), ApplyError> {
    if organization.get_organization_type() != org_type {
        return Err(ApplyError::InvalidTransaction(format!(
            "Organization {} is type {:?} but this action can only be performed by type {:?}",
            organization.get_id(),
            organization.get_organization_type(),
            org_type
        )));
    }
    Ok(())
}

fn make_organization(
    payload: &proto::payload::CreateOrganizationAction,
    signer_public_key: &str,
) -> proto::organization::Organization {
    let mut new_organization = proto::organization::Organization::new();
    new_organization.set_id(payload.get_id().to_string());
    new_organization.set_name(payload.get_name().to_string());
    new_organization.set_organization_type(payload.get_organization_type());
    new_organization.set_contacts(protobuf::RepeatedField::from_vec(
        payload.get_contacts().to_vec(),
    ));

    let mut admin_authorization = proto::organization::Organization_Authorization::new();
    admin_authorization.set_public_key(signer_public_key.to_string());
    admin_authorization.set_role(ADMIN);

    let mut transactor_authorization = proto::organization::Organization_Authorization::new();
    transactor_authorization.set_public_key(signer_public_key.to_string());
    transactor_authorization.set_role(TRANSACTOR);

    new_organization.set_authorizations(::protobuf::RepeatedField::from_vec(vec![
        admin_authorization,
        transactor_authorization,
    ]));

    if payload.get_organization_type() == proto::organization::Organization_Type::FACTORY {
        let mut factory_details = proto::organization::Factory::new();
        factory_details.set_address(payload.get_address().clone());
        new_organization.set_factory_details(factory_details);
    }
    new_organization
}

fn make_certificate(
    payload: &proto::payload::IssueCertificateAction,
    certifying_body_id: &str,
    standard_version: &str,
) -> proto::certificate::Certificate {
    // Create certificate
    let mut new_certificate = proto::certificate::Certificate::new();
    new_certificate.set_id(payload.get_id().to_string());
    new_certificate.set_certifying_body_id(certifying_body_id.to_string());
    new_certificate.set_factory_id(payload.get_factory_id().to_string());
    new_certificate.set_standard_id(payload.get_standard_id().to_string());
    new_certificate.set_standard_version(standard_version.to_string());
    new_certificate.set_certificate_data(::protobuf::RepeatedField::from_vec(
        payload.get_certificate_data().to_vec(),
    ));
    new_certificate.set_valid_from(payload.get_valid_from());
    new_certificate.set_valid_to(payload.get_valid_to());

    new_certificate
}

fn make_standard(
    payload: &proto::payload::CreateStandardAction,
    org_id: &str,
) -> proto::standard::Standard {
    let mut new_standard_version = proto::standard::Standard_StandardVersion::new();
    new_standard_version.set_version(payload.version.clone());
    new_standard_version.set_description(payload.description.clone());
    new_standard_version.set_link(payload.link.clone());
    new_standard_version.set_approval_date(payload.approval_date.clone());

    let mut new_standard = proto::standard::Standard::new();
    new_standard.set_id(payload.standard_id.clone());
    new_standard.set_name(payload.name.clone());
    new_standard.set_organization_id(org_id.to_string());
    new_standard.set_versions(protobuf::RepeatedField::from_vec(vec![
        new_standard_version,
    ]));
    new_standard
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
            Action::CreateAssertion(payload) => {
                self.create_assertion(&payload, &mut state, signer_public_key)
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
    const INGESTION_ID: &str = "ingestion_id";
    const CERT_ID: &str = "test_cert";
    const REQUEST_ID: &str = "test_request";
    const STANDARD_ID: &str = "test_standard";
    const ASSERTION_ID_1: &str = "test_assertion_1";
    const ASSERTION_ID_2: &str = "test_assertion_2";
    const ASSERTION_ID_3: &str = "test_assertion_3";

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
    /// Test that CreateAgentAction is invalid if an agent already exists
    fn test_create_agent_handler_agent_already_exists() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);
        let transaction_handler = CertTransactionHandler::new();
        let action = make_agent_create_action();

        transaction_handler
            .create_agent(&action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let result = transaction_handler.create_agent(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "Agent already exists: {}",
                    PUBLIC_KEY_1
                ),))
            )
        )
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
    fn test_create_organization_handler_organization_already_exists() {
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

        transaction_handler
            .create_organization(&action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let result = transaction_handler.create_organization(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "Organization already exists: {}",
                    STANDARDS_BODY_ID
                ),))
            )
        )
    }

    #[test]
    /// Test that CreateOrganizationAction fails when no agent is associated with the supplied public key
    fn test_create_organization_handler_no_agent_with_public_key() {
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

        let result = transaction_handler.create_organization(
            &action,
            &mut state,
            "non_existent_agent_pub_key",
        );

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "No agent with public key non_existent_agent_pub_key exists",
                ))
            )
        )
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
    /// Test that UpdateOrganizationAction fails when no agent is associated with the supplied public key
    fn test_update_organization_handler_no_agent_with_public_key() {
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

        let result = transaction_handler.update_organization(
            &action,
            &mut state,
            "non_existent_agent_pub_key",
        );

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "No agent with public key non_existent_agent_pub_key exists",
                ))
            )
        );
    }

    #[test]
    /// Test that UpdateOrganizationAction fails when unassociated agent updates the organization
    fn test_update_organization_handler_agent_not_associated_with_organization() {
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
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_2)
            .unwrap();

        let action = make_organization_update_action();

        let result = transaction_handler.update_organization(&action, &mut state, PUBLIC_KEY_2);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "Agent is not associated with an organization: ",
                ))
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
        let authorization = organization
            .get_authorizations()
            .iter()
            .find(|auth| auth.get_public_key() == PUBLIC_KEY_2 && auth.get_role() == TRANSACTOR);

        assert!(authorization.is_some());
    }

    #[test]
    /// Test if AuthorizeAgentAction fails if there is no agent with the public key to authorize
    fn test_authorize_agent_handler_no_agent_with_public_key() {
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

        //make authorization action without adding an agent
        let action = make_authorize_agent_action("non_existent_agent_pub_key");

        let result = transaction_handler.authorize_agent(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "No agent with public key non_existent_agent_pub_key exists",
                ))
            )
        );
    }

    #[test]
    /// Test if AuthorizeAgentAction fails if there is no agent with the public key to authorize
    fn test_authorize_agent_handler_agent_not_associated_with_organization() {
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
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_2)
            .unwrap();

        //make authorization action without adding an agent
        let action = make_authorize_agent_action(PUBLIC_KEY_2);

        let result = transaction_handler.authorize_agent(&action, &mut state, PUBLIC_KEY_2);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "Agent is not associated with an organization: ",
                ))
            )
        );
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

        assert_eq!(certificate, make_certificate(CERT_ORG_ID));
    }

    #[test]
    /// Test that IssueCertificateAction fails because a certificate has already been issued
    fn test_issue_certificate_handler_certificate_already_exists() {
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

        transaction_handler
            .issue_certificate(&action, &mut state, PUBLIC_KEY_3)
            .unwrap();

        //issue cert again
        let result = transaction_handler.issue_certificate(&action, &mut state, PUBLIC_KEY_3);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "Certificate already exists: {}",
                    CERT_ID
                ),))
            )
        );
    }

    #[test]
    /// Test that IssueCertificateAction fails because there is no agent with public key to accredit the cert body
    fn test_issue_certificate_handler_no_agent_with_public_key() {
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

        let result = transaction_handler.issue_certificate(
            &action,
            &mut state,
            "non_existent_agent_pub_key",
        );

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "No agent with public key non_existent_agent_pub_key exists",
                ))
            )
        );
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

        assert_eq!(standard, make_standard(STANDARDS_BODY_ID));
    }

    #[test]
    fn test_create_standard_handler_standard_already_exists() {
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

        transaction_handler
            .create_standard(&action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let result = transaction_handler.create_standard(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from("Standard already exists: test",))
            )
        );
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

        let action = make_standard_update_action("test_change");

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
    /// Test that UpdateStandardAction fails because standard to update does not exist
    fn test_update_standard_handler_standard_does_not_exist() {
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

        //update standard without creating it
        let action = make_standard_update_action("test_change");

        let result = transaction_handler.update_standard(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "Standard {} does not exist",
                    STANDARD_ID
                ),))
            )
        );
    }

    #[test]
    /// Test that UpdateStandardAction fails if standard version already exists
    fn test_update_standard_handler_version_already_exists() {
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

        let action = make_standard_update_action("test");

        let result = transaction_handler.update_standard(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "Version already exists. Version test",
                ))
            )
        );
    }

    #[test]
    /// Test that UpdateStandardAction fails if there is no agent with the public key to update the standard
    fn test_update_standard_handler_no_agent_with_pub_key() {
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

        let action = make_standard_update_action("test_change");

        let result =
            transaction_handler.update_standard(&action, &mut state, "non_existent_agent_pub_key");

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "No agent with public key non_existent_agent_pub_key exists",
                ))
            )
        );
    }

    #[test]
    /// Test that UpdateStandardAction fails because agent is not associated with org
    fn test_update_standard_handler_agent_not_associated_with_organization() {
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

        //add agent
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_2)
            .unwrap();

        //update standard without creating it
        let action = make_standard_update_action("test_change");

        let result = transaction_handler.update_standard(&action, &mut state, PUBLIC_KEY_2);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "Agent is not associated with an organization: ",
                ))
            )
        );
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

    #[test]
    /// Test that if AssertAction for a new Factory is valid an Ok is returned and both an Assertion and an Organization are added to state
    fn test_assert_action_new_factory_handler_valid() {
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
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let assert_action = make_assert_action_new_factory(ASSERTION_ID_1);
        assert!(transaction_handler
            .create_assertion(&assert_action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let assertion = state
            .get_assertion(ASSERTION_ID_1)
            .expect("Failed to fetch Assertion")
            .expect("No Assertion found");

        assert_eq!(
            assertion,
            make_assertion(
                PUBLIC_KEY_1,
                ASSERTION_ID_1,
                proto::assertion::Assertion_Type::FACTORY,
                FACTORY_ID
            )
        );

        let factory = state
            .get_organization(FACTORY_ID)
            .expect("Failed to fetch Asserted Factory")
            .expect("No Asserted Factory found");

        assert_eq!(
            factory,
            make_organization(
                FACTORY_ID,
                proto::organization::Organization_Type::FACTORY,
                PUBLIC_KEY_1,
            )
        );
    }

    #[test]
    /// Test that if AssertAction for a new Certificate is valid an Ok is returned and both an Assertion and a Certificate are added to state
    fn test_assert_action_new_certificate_handler_valid() {
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
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let standard_assert_action = make_assert_action_new_standard(ASSERTION_ID_1);
        transaction_handler
            .create_assertion(&standard_assert_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let factory_assert_action = make_assert_action_new_factory(ASSERTION_ID_2);
        transaction_handler
            .create_assertion(&factory_assert_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let assert_action = make_assert_action_new_certificate(ASSERTION_ID_3);
        assert!(transaction_handler
            .create_assertion(&assert_action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let assertion = state
            .get_assertion(ASSERTION_ID_3)
            .expect("Failed to fetch Assertion")
            .expect("No Assertion found");

        assert_eq!(
            assertion,
            make_assertion(
                PUBLIC_KEY_1,
                ASSERTION_ID_3,
                proto::assertion::Assertion_Type::CERTIFICATE,
                CERT_ID
            )
        );

        let certificate = state
            .get_certificate(CERT_ID)
            .expect("Failed to fetch Asserted Certificate")
            .expect("No Asserted Certificate found");

        assert_eq!(certificate, make_certificate(INGESTION_ID));
    }

    #[test]
    /// Test that if AssertAction for a new Standard is valid an Ok is returned and both an Assertion and a Standard are added to state
    fn test_assert_action_new_standard_handler_valid() {
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
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let assert_action = make_assert_action_new_standard(ASSERTION_ID_1);
        assert!(transaction_handler
            .create_assertion(&assert_action, &mut state, PUBLIC_KEY_1)
            .is_ok());

        let assertion = state
            .get_assertion(ASSERTION_ID_1)
            .expect("Failed to fetch Assertion")
            .expect("No Assertion found");

        assert_eq!(
            assertion,
            make_assertion(
                PUBLIC_KEY_1,
                ASSERTION_ID_1,
                proto::assertion::Assertion_Type::STANDARD,
                STANDARD_ID
            )
        );

        let standard = state
            .get_standard(STANDARD_ID)
            .expect("Failed to fetch Asserted Certificate")
            .expect("No Asserted Certificate found");

        assert_eq!(standard, make_standard(INGESTION_ID));
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
        admin_authorization.set_role(ADMIN);

        let mut transactor_authorization = proto::organization::Organization_Authorization::new();
        transactor_authorization.set_public_key(signer_public_key.to_string());
        transactor_authorization.set_role(TRANSACTOR);

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
        admin_authorization.set_role(ADMIN);

        let mut transactor_authorization = proto::organization::Organization_Authorization::new();
        transactor_authorization.set_public_key(signer_public_key.to_string());
        transactor_authorization.set_role(TRANSACTOR);

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

    fn make_certificate(cert_org_id: &str) -> proto::certificate::Certificate {
        let mut new_certificate = proto::certificate::Certificate::new();
        new_certificate.set_id(CERT_ID.to_string());
        new_certificate.set_certifying_body_id(cert_org_id.to_string());
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

    fn make_standard(org_id: &str) -> proto::standard::Standard {
        let mut new_standard_version = proto::standard::Standard_StandardVersion::new();
        new_standard_version.set_version("test".to_string());
        new_standard_version.set_description("test".to_string());
        new_standard_version.set_link("test".to_string());
        new_standard_version.set_approval_date(1);

        let mut new_standard = proto::standard::Standard::new();
        new_standard.set_id(STANDARD_ID.to_string());
        new_standard.set_name("test".to_string());
        new_standard.set_organization_id(org_id.to_string());
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

    fn make_assertion(
        pub_key: &str,
        assertion_id: &str,
        assertion_type: proto::assertion::Assertion_Type,
        object_id: &str,
    ) -> proto::assertion::Assertion {
        let mut new_assertion = proto::assertion::Assertion::new();
        new_assertion.set_id(assertion_id.to_string());
        new_assertion.set_assertor_pub_key(pub_key.to_string());
        new_assertion.set_assertion_type(assertion_type);
        new_assertion.set_object_id(object_id.to_string());

        new_assertion
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
        new_auth_action.set_role(TRANSACTOR);
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

    fn make_standard_update_action(version: &str) -> UpdateStandardAction {
        let mut standard_update_action = UpdateStandardAction::new();
        standard_update_action.set_standard_id(STANDARD_ID.to_string());
        standard_update_action.set_version(version.to_string());
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

    fn make_assert_action_new_factory(id: &str) -> AssertAction {
        let mut assert_action = AssertAction::new();
        let mut factory_assertion = AssertAction_FactoryAssertion::new();
        factory_assertion.set_factory(make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        ));
        assert_action.set_new_factory(factory_assertion);
        assert_action.set_assertion_id(id.to_string());
        assert_action
    }

    fn make_assert_action_new_certificate(id: &str) -> AssertAction {
        let mut assert_action = AssertAction::new();
        assert_action.set_new_certificate(make_issue_certificate_action());
        assert_action.set_assertion_id(id.to_string());
        assert_action
    }

    fn make_assert_action_new_standard(id: &str) -> AssertAction {
        let mut assert_action = AssertAction::new();
        assert_action.set_new_standard(make_standard_create_action());
        assert_action.set_assertion_id(id.to_string());
        assert_action
    }
}
