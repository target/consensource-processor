/*
 * ConsensourceTransactionHandler
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
use state::ConsensourceState;

use transaction_handler::{agent, assertion, certificate, factory, organization, standard};

pub struct ConsensourceTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl ConsensourceTransactionHandler {
    pub fn new() -> ConsensourceTransactionHandler {
        ConsensourceTransactionHandler {
            family_name: addressing::FAMILY_NAMESPACE.to_string(),
            family_versions: vec![addressing::FAMILY_VERSION.to_string()],
            namespaces: vec![addressing::get_family_namespace_prefix()],
        }
    }

    /// Creates a new Agent and submits it to state
    /// ```
    /// # Errors
    /// Returns an error if:
    ///   - Signer public key already associated with an agent
    ///   - It fails to submit the new Agent to state.
    /// ```
    pub fn create_agent(
        &self,
        payload: &proto::payload::CreateAgentAction,
        state: &mut ConsensourceState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        agent::create(payload, state, signer_public_key)
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
        state: &mut ConsensourceState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        organization::create(payload, state, signer_public_key)
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
        state: &mut ConsensourceState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        organization::update(payload, state, signer_public_key)
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
        state: &mut ConsensourceState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        agent::authorize(payload, state, signer_public_key)
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
    ///    - the request does not exist
    ///    - the request does not have status set to IN_PROGRESS
    ///   - the factory the certificate is for does not exist. x
    ///   - it fails to submit the new Certificate to state.
    /// ```
    pub fn issue_certificate(
        &self,
        payload: &proto::payload::IssueCertificateAction,
        state: &mut ConsensourceState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        certificate::issue(payload, state, signer_public_key)
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
        state: &mut ConsensourceState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        factory::open_request(payload, state, signer_public_key)
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
        state: &mut ConsensourceState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        factory::change_request_status(payload, state, signer_public_key)
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
        state: &mut ConsensourceState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        standard::create(payload, state, signer_public_key)
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
        state: &mut ConsensourceState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        standard::update(payload, state, signer_public_key)
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
        state: &mut ConsensourceState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        standard::accredit_certifying_body(payload, state, signer_public_key)
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
        state: &mut ConsensourceState,
        signer_public_key: &str,
    ) -> Result<(), ApplyError> {
        assertion::create(payload, state, signer_public_key)
    }
}

impl TransactionHandler for ConsensourceTransactionHandler {
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
        let mut state = ConsensourceState::new(context);

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
    let handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
    /// Test that OpenRequestAction fails if there is no agent with provided public key
    fn test_open_request_handler_no_agent_with_public_key() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();

        let action = make_open_request_action();

        let result =
            transaction_handler.open_request(&action, &mut state, "non_existent_agent_pub_key");

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
    /// Test that OpenRequestAction fails if there is no organization
    fn test_open_request_handler_no_organization_with_id_exists() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();

        //add agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let action = make_open_request_action();

        let result = transaction_handler.open_request(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from("No organization with ID  exists",))
            )
        )
    }

    #[test]
    /// Test that OpenRequestAction fails if the org is not a factory
    fn test_open_request_handler_organization_is_not_a_factory() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();

        //add agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_1)
            .unwrap();
        //add org
        let org_action = make_organization_create_action(
            "not_even_a_factory",
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        transaction_handler
            .create_organization(&org_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let action = make_open_request_action();

        let result = transaction_handler.open_request(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
      format!("{:?}", result.unwrap_err()),
      format!(
        "{:?}",
        ApplyError::InvalidTransaction(String::from(
          format!(
            "Organization not_even_a_factory is type {:?} but this action can only be performed by type {:?}",
            proto::organization::Organization_Type::STANDARDS_BODY,
            proto::organization::Organization_Type::FACTORY
          )
        ,))
      )
    )
    }

    #[test]
    /// Test that OpenRequestAction fails ir request is already open/exists
    fn test_open_request_handler_request_already_exists() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        transaction_handler
            .open_request(&action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let result = transaction_handler.open_request(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "Request already exists: test_request",
                ))
            )
        )
    }

    #[test]
    /// Test that OpenRequestAction fails if no standard exists
    fn test_open_request_handler_no_standard_exists() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        let action = make_open_request_action();

        let result = transaction_handler.open_request(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "No standard with ID {} exists",
                    STANDARD_ID,
                ),))
            )
        )
    }

    #[test]
    /// Test that if ChangeRequestStatusAction is valid an OK is returned and the Request is updated in state
    fn test_change_request_status_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
    /// Test that ChangeRequestStatusAction fails because the request does not exist
    fn test_change_request_status_handler_request_does_not_exist() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();

        let action = make_change_request_action();

        let result = transaction_handler.change_request_status(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "Request does not exist: {}",
                    REQUEST_ID
                ),))
            )
        );
    }

    #[test]
    /// Test that ChangeRequestStatusAction fails because there is no agent public key
    fn test_change_request_status_handler_no_agent_public_key() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        let result = transaction_handler.change_request_status(
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
    /// Test that ChangeRequestStatusAction fails because an agent is not authorized
    fn test_change_request_status_handler_agent_is_not_authorized() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        let result = transaction_handler.change_request_status(&action, &mut state, PUBLIC_KEY_2);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "Agent {} is not authorized to update request {}",
                    STANDARDS_BODY_ID, FACTORY_ID
                ),))
            )
        );
    }

    #[test]
    /// Test that ChangeRequestStatusAction fails because closed requests cannot be modified
    fn test_change_request_status_handler_cannot_modify_closed_requests() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        let change_action = make_change_request_close_action();

        transaction_handler
            .change_request_status(&change_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let close_action = make_change_request_close_action();

        let result =
            transaction_handler.change_request_status(&close_action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "Once CLOSED or CERTIFIED, the request status can not be modified again.
        Status: CLOSED"
                ),))
            )
        );
    }

    #[test]
    /// Test that ChangeRequestStatusAction fails because certified requests cannot be modified
    fn test_change_request_status_handler_cannot_modify_certified_requests() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        let change_action = make_change_request_certified_action();

        transaction_handler
            .change_request_status(&change_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let close_action = make_change_request_close_action();

        let result =
            transaction_handler.change_request_status(&close_action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "Once CLOSED or CERTIFIED, the request status can not be modified again.
        Status: CERTIFIED"
                ),))
            )
        );
    }

    #[test]
    /// Test that if AccreditCertifyingBodyAction is valid an OK is returned and a new Accreditation is added to state
    fn test_accredit_certifying_body_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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
    /// Test that AccreditCertifyingBodyAction fails because there is no agent with public key exists
    fn test_accredit_certifying_body_handler_no_agent_with_public_key() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        let result = transaction_handler.accredit_certifying_body(
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
    /// Test that AccreditCertifyingBodyAction fails because agent is not associated with an organization
    fn test_accredit_certifying_body_handler_agent_not_associated_with_organization() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        //add agent
        let agent_action = make_agent_create_action();
        transaction_handler
            .create_agent(&agent_action, &mut state, PUBLIC_KEY_3)
            .unwrap();

        let action = make_accredit_certifying_body_action();

        let result =
            transaction_handler.accredit_certifying_body(&action, &mut state, PUBLIC_KEY_3);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "Agent is not associated with an organization: "
                ))
            )
        )
    }

    #[test]
    /// Test that AccreditCertifyingBodyAction fails because non standards body organizations cannot perform accreditations
    fn test_accredit_certifying_body_handler_organization_type_cannot_perform_accreditation() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        let result =
            transaction_handler.accredit_certifying_body(&action, &mut state, PUBLIC_KEY_2);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
            "Organization {} is type {:?} but this action can only be performed by type {:?}",
            CERT_ORG_ID,
            proto::organization::Organization_Type::CERTIFYING_BODY,
            proto::organization::Organization_Type::STANDARDS_BODY
          )))
            )
        )
    }

    #[test]
    /// Test that AccreditCertifyingBodyAction fails because no standard was ever created
    fn test_accredit_certifying_body_handler_no_standard_with_id_exists() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        //skip adding standard

        let action = make_accredit_certifying_body_action();

        let result =
            transaction_handler.accredit_certifying_body(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "No standard with ID {} exists",
                    STANDARD_ID
                )))
            )
        )
    }

    #[test]
    /// Test that AccreditCertifyingBodyAction fails because the accredited standard already exists
    fn test_accredit_certifying_body_handler_accredited_standard_already_exists() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        transaction_handler
            .accredit_certifying_body(&action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let result =
            transaction_handler.accredit_certifying_body(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "Accreditation for Standard {}, version {} already exists",
                    STANDARD_ID, "test"
                )))
            )
        )
    }

    #[test]
    /// Test that AccreditCertifyingBodyAction fails because the accreditation dates are invalid
    fn test_accredit_certifying_body_handler_invalid_dates() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();
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

        let action = make_accredit_certifying_body_invalid_date_action();

        let result =
            transaction_handler.accredit_certifying_body(&action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "Invalid dates. Valid to must be after valid from",
                ))
            )
        )
    }

    #[test]
    /// Test that if AssertAction for a new Factory is valid an Ok is returned and both an Assertion and an Organization are added to state
    fn test_assert_action_new_factory_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();

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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();

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
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();

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

    #[test]
    /// Test that AssertAction fails because the assertion with the specified ID already exists
    fn test_assert_action_handler_assertion_already_exists() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();

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

        transaction_handler
            .create_assertion(&assert_action, &mut state, PUBLIC_KEY_1)
            .unwrap();

        let result = transaction_handler.create_assertion(&assert_action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(format!(
                    "Assertion with ID {} already exists",
                    ASSERTION_ID_1
                )))
            )
        )
    }

    #[test]
    /// Test that AssertAction fails because certificate dates are invalid
    fn test_assert_action_handler_assertion_contains_invalid_dates() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();

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

        let assert_action = make_assert_action_new_certificate_with_invalid_dates(ASSERTION_ID_3);

        let result = transaction_handler.create_assertion(&assert_action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "Invalid dates. Valid to must be after valid from"
                ))
            )
        )
    }

    #[test]
    /// Test that AssertAction fails because certificate source is unset
    fn test_assert_action_handler_assertion_certificate_contains_no_source() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();

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

        let assert_action = make_assert_action_new_certificate_with_no_source(ASSERTION_ID_3);

        let result = transaction_handler.create_assertion(&assert_action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "The `IssueCertificateAction_Source` of a Certificate Assertion must be
            `INDEPENDENT` to indicate no request was made"
                ))
            )
        )
    }

    #[test]
    /// Test that AssertAction fails because the specified standard does not exist
    fn test_assert_action_new_standard_handler_standard_does_not_exist() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let transaction_handler = ConsensourceTransactionHandler::new();

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

        let assert_action =
            make_assert_action_new_certificate_with_non_existent_standard(ASSERTION_ID_3);

        let result = transaction_handler.create_assertion(&assert_action, &mut state, PUBLIC_KEY_1);

        assert!(result.is_err());

        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            format!(
                "{:?}",
                ApplyError::InvalidTransaction(String::from(
                    "Standard non_existent_standard does not exist"
                ))
            )
        )
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

    fn make_issue_certificate_action_with_invalid_dates() -> IssueCertificateAction {
        let mut issuance_action = IssueCertificateAction::new();
        issuance_action.set_id(CERT_ID.to_string());
        issuance_action.set_source(IssueCertificateAction_Source::INDEPENDENT);
        issuance_action.set_standard_id(STANDARD_ID.to_string());
        issuance_action.set_factory_id(FACTORY_ID.to_string());
        issuance_action.set_valid_from(2);
        issuance_action.set_valid_to(1);
        issuance_action
    }

    fn make_issue_certificate_action_with_no_source() -> IssueCertificateAction {
        let mut issuance_action = IssueCertificateAction::new();
        issuance_action.set_id(CERT_ID.to_string());
        issuance_action.set_source(IssueCertificateAction_Source::UNSET_SOURCE);
        issuance_action.set_standard_id(STANDARD_ID.to_string());
        issuance_action.set_factory_id(FACTORY_ID.to_string());
        issuance_action.set_valid_from(1);
        issuance_action.set_valid_to(2);
        issuance_action
    }

    fn make_issue_certificate_action_non_existent_standard() -> IssueCertificateAction {
        let mut issuance_action = IssueCertificateAction::new();
        issuance_action.set_id(CERT_ID.to_string());
        issuance_action.set_source(IssueCertificateAction_Source::INDEPENDENT);
        issuance_action.set_standard_id("non_existent_standard".to_string());
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

    fn make_change_request_close_action() -> ChangeRequestStatusAction {
        let mut change_request_action = ChangeRequestStatusAction::new();
        change_request_action.set_request_id(REQUEST_ID.to_string());
        change_request_action.set_status(proto::request::Request_Status::CLOSED);
        change_request_action
    }

    fn make_change_request_certified_action() -> ChangeRequestStatusAction {
        let mut change_request_action = ChangeRequestStatusAction::new();
        change_request_action.set_request_id(REQUEST_ID.to_string());
        change_request_action.set_status(proto::request::Request_Status::CERTIFIED);
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

    fn make_accredit_certifying_body_invalid_date_action() -> AccreditCertifyingBodyAction {
        let mut accredit_action = AccreditCertifyingBodyAction::new();
        accredit_action.set_certifying_body_id(CERT_ORG_ID.to_string());
        accredit_action.set_standard_id(STANDARD_ID.to_string());
        accredit_action.set_valid_from(2);
        accredit_action.set_valid_to(1);
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

    fn make_assert_action_new_certificate_with_invalid_dates(id: &str) -> AssertAction {
        let mut assert_action = AssertAction::new();
        assert_action.set_new_certificate(make_issue_certificate_action_with_invalid_dates());
        assert_action.set_assertion_id(id.to_string());
        assert_action
    }

    fn make_assert_action_new_certificate_with_no_source(id: &str) -> AssertAction {
        let mut assert_action = AssertAction::new();
        assert_action.set_new_certificate(make_issue_certificate_action_with_no_source());
        assert_action.set_assertion_id(id.to_string());
        assert_action
    }

    fn make_assert_action_new_certificate_with_non_existent_standard(id: &str) -> AssertAction {
        let mut assert_action = AssertAction::new();
        assert_action.set_new_certificate(make_issue_certificate_action_non_existent_standard());
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
