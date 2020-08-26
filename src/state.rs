/*
 * ConsensourceState
 */

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        use sabre_sdk::ApplyError;
        use sabre_sdk::TransactionContext;
    } else {
        use sawtooth_sdk::processor::handler::ApplyError;
        use sawtooth_sdk::processor::handler::TransactionContext;
    }
}

use common::addressing::{
    make_agent_address, make_assertion_address, make_certificate_address,
    make_organization_address, make_request_address, make_standard_address,
};
use common::proto::{
    agent::{Agent, AgentContainer},
    assertion::{Assertion, AssertionContainer},
    certificate::{Certificate, CertificateContainer},
    organization::{Organization, OrganizationContainer},
    request::{Request, RequestContainer},
    standard::{Standard, StandardContainer},
};

/// Sawtooth State accessors for messages
///
/// This is a generic trait for implementing state getters and setters for protobuf messages.
/// Contains two methods, `get_state` and `set_state` that both need to be supplied a
/// TransactionContext
pub trait StateInteractor: Sized + protobuf::Message {
    /// Given a TransactionContext and id of an object will return the object if it exists in state
    fn get_state(
        context: &mut dyn TransactionContext,
        id: &str,
    ) -> Result<Option<Self>, ApplyError>;
    /// When called on an object with a TransactionContext and object id will submit to state
    fn set_state(&self, context: &mut dyn TransactionContext, id: &str) -> Result<(), ApplyError>;
}

macro_rules! interactor {
    ($val_type:path, $address_func:path, $container_type:ty, $key_field:ident) => {
        impl ::state::StateInteractor for $val_type {
            fn get_state(
                context: &mut dyn TransactionContext,
                id: &str,
            ) -> Result<Option<$val_type>, ApplyError> {
                let address = $address_func(id);
                let state_data = context.get_state_entry(&address)?;
                match state_data {
                    Some(data) => {
                        let objects: $container_type =
                            ::protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                                ApplyError::InvalidTransaction(format!(
                                    "Cannot deserialize {}",
                                    ::std::any::type_name::<$container_type>()
                                ))
                            })?;
                        for object in objects.get_entries() {
                            if object.$key_field == id {
                                return Ok(Some(object.clone()));
                            }
                        }
                        Ok(None)
                    }
                    None => Ok(None),
                }
            }
            fn set_state(
                &self,
                context: &mut dyn TransactionContext,
                id: &str,
            ) -> Result<(), ApplyError> {
                let address = $address_func(id);
                let state_data = context.get_state_entry(&address)?;
                let mut objects: $container_type = match state_data {
                    Some(data) => {
                        ::protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                            ApplyError::InvalidTransaction(format!(
                                "Cannot deserialize {}",
                                ::std::any::type_name::<$container_type>()
                            ))
                        })?
                    }
                    // If there is nothing at that memory address in state, make a new container, and create a new object
                    None => <$container_type>::new(),
                };
                // Use an iterator to find the index of an object's ID that matches the object attempting to be created
                if let Some((i, _)) = objects
                    .entries
                    .iter()
                    .enumerate()
                    .find(|(_i, object)| object.$key_field == id)
                {
                    // If that object already exists, set object_slice to that object
                    let object_slice = objects.entries.as_mut_slice();
                    object_slice[i] = self.clone();
                } else {
                    // Push new and unique object to the container
                    objects.entries.push(self.clone());
                    objects.entries.sort_by_key(|a| a.clone().$key_field);
                }
                let serialized = ::protobuf::Message::write_to_bytes(&objects).map_err(|_err| {
                    ApplyError::InvalidTransaction(String::from("Cannot serialize container"))
                })?;
                // Insert serialized container to an address in the merkle tree
                context.set_state_entry(address, serialized)?;
                Ok(())
            }
        }
    };
}
//invoke macro to implement state setters and getters
interactor!(Agent, make_agent_address, AgentContainer, public_key);
interactor!(
    Organization,
    make_organization_address,
    OrganizationContainer,
    id
);
interactor!(
    Certificate,
    make_certificate_address,
    CertificateContainer,
    id
);
interactor!(Request, make_request_address, RequestContainer, id);
interactor!(Standard, make_standard_address, StandardContainer, id);
interactor!(Assertion, make_assertion_address, AssertionContainer, id);

pub struct ConsensourceState<'a> {
    context: &'a mut dyn TransactionContext,
}

impl<'a> ConsensourceState<'a> {
    // Create new instance of ConsensourceState
    pub fn new(context: &'a mut dyn TransactionContext) -> ConsensourceState {
        ConsensourceState { context }
    }

    /// Fetches and deserializes an Agent's data from state
    /// ```
    /// # Errors
    /// Return an error if it fails to deserialize the Agent's data
    /// ```
    pub fn get_agent(&mut self, agent_public_key: &str) -> Result<Option<Agent>, ApplyError> {
        Agent::get_state(self.context, agent_public_key)
    }

    /// Fetches and deserializes an Organization's data from state
    /// ```
    /// # Errors
    /// Return an error if it fails to deserialize the Organization's data
    /// ```
    pub fn get_organization(
        &mut self,
        organization_id: &str,
    ) -> Result<Option<Organization>, ApplyError> {
        Organization::get_state(self.context, organization_id)
    }

    /// Fetches and deserializes a Certificate's data from state
    /// ```
    /// # Errors
    /// Return an error if it fails to deserialize the Certificate's data
    /// ```
    pub fn get_certificate(
        &mut self,
        certificate_id: &str,
    ) -> Result<Option<Certificate>, ApplyError> {
        Certificate::get_state(self.context, certificate_id)
    }

    /// Fetches and deserializes a Request data from state
    /// ```
    /// # Errors
    /// Return an error if it fails to deserialize the Request's data
    /// ```
    pub fn get_request(&mut self, request_id: &str) -> Result<Option<Request>, ApplyError> {
        Request::get_state(self.context, request_id)
    }

    /// Fetches and deserializes a Standard data from state
    /// ```
    /// # Errors
    /// Return an error if it fails to deserialize the Standard's data
    /// ```
    pub fn get_standard(&mut self, standard_id: &str) -> Result<Option<Standard>, ApplyError> {
        Standard::get_state(self.context, standard_id)
    }

    /// Fetches and deserializes Assertion data from state
    /// ```
    /// # Errors
    /// Return an error if it fails to deserialize the Assertion's data
    /// ```
    pub fn get_assertion(&mut self, assertion_id: &str) -> Result<Option<Assertion>, ApplyError> {
        Assertion::get_state(self.context, assertion_id)
    }

    /// As the addressing scheme does not guarantee uniquesness, this adds an Agent into a Agent Container
    /// which works like a hashbucket, serializes the container and puts it into state,
    /// ```
    /// # Errors
    /// Returns an error if it fails to serialize the container or fails to set it to state
    /// ```
    pub fn set_agent(&mut self, agent_public_key: &str, agent: Agent) -> Result<(), ApplyError> {
        agent.set_state(self.context, agent_public_key)
    }

    /// As the addressing scheme does not guarantee uniquesness, this adds an Organization into a Organization Container
    /// which works like a hashbucket, serializes the container and puts it into state,
    /// ```
    /// # Errors
    /// Returns an error if it fails to serialize the container or fails to set it to state
    /// ```
    pub fn set_organization(
        &mut self,
        organization_id: &str,
        organization: Organization,
    ) -> Result<(), ApplyError> {
        organization.set_state(self.context, organization_id)
    }

    /// As the addressing scheme does not guarantee uniquesness, this adds a Certificate into a Certificate Container
    /// which works like a hashbucket, serializes the container and puts it into state,
    /// ```
    /// # Errors
    /// Returns an error if it fails to serialize the container or fails to set it to state
    /// ```
    pub fn set_certificate(
        &mut self,
        certificate_id: &str,
        certificate: Certificate,
    ) -> Result<(), ApplyError> {
        certificate.set_state(self.context, certificate_id)
    }

    /// As the addressing scheme does not guarantee uniquesness, this adds a Request into a Request Container
    /// which works like a hashbucket, serializes the container and puts it into state,
    /// ```
    /// # Errors
    /// Returns an error if it fails to serialize the container or fails to set it to state
    /// ```
    pub fn set_request(&mut self, request_id: &str, request: Request) -> Result<(), ApplyError> {
        request.set_state(self.context, request_id)
    }

    /// As the addressing scheme does not guarantee uniquesness, this adds a Standard into a Standard Container
    /// which works like a hashbucket, serializes the container and puts it into state,
    /// ```
    /// # Errors
    /// Returns an error if it fails to serialize the container or fails to set it to state
    /// ```
    pub fn set_standard(
        &mut self,
        standard_id: &str,
        standard: Standard,
    ) -> Result<(), ApplyError> {
        standard.set_state(self.context, standard_id)
    }

    /// As the addressing scheme does not guarantee uniquesness, this adds an Assertion into an Assertion Container
    /// which works like a hashbucket, serializes the container and puts it into state,
    /// ```
    /// # Errors
    /// Returns an error if it fails to serialize the container or fails to set it to state
    /// ```
    pub fn set_assertion(
        &mut self,
        assertion_id: &str,
        assertion: Assertion,
    ) -> Result<(), ApplyError> {
        assertion.set_state(self.context, assertion_id)
    }

    pub fn remove_assertion(&mut self, assertion_id: &str) -> Result<(), ApplyError> {
        let address = make_assertion_address(assertion_id);
        let state_data = self.context.get_state_entry(&address)?;
        let mut assertions: AssertionContainer = match state_data {
            Some(data) => protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                ApplyError::InvalidTransaction("Cannot deserialize Assertions".to_string())
            })?,
            None => AssertionContainer::new(),
        };
        let filtered_assertions = assertions
            .entries
            .iter()
            .filter(|a| a.id != assertion_id)
            .collect::<Vec<_>>();
        if filtered_assertions.is_empty() {
            self.context
                .delete_state_entries(&[address])
                .map_err(|err| ApplyError::InternalError(format!("{}", err)))?;
        } else {
            assertions.entries.retain(|a| a.id != assertion_id);
            let serialized = protobuf::Message::write_to_bytes(&assertions).map_err(|_err| {
                ApplyError::InvalidTransaction(String::from("Cannot serialize container"))
            })?;
            self.context.set_state_entry(address, serialized)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::collections::HashMap;

    use sawtooth_sdk::processor::handler::{ContextError, TransactionContext};

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
    // Test that if an agent does not exist in state, None is returned
    fn test_get_agent_none() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        let result = state.get_agent("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if an agent exist in state, Some(agent) is returned
    fn test_get_agent_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        assert!(state.set_agent("test", make_agent("test")).is_ok());
        let result = state.get_agent("test").unwrap();
        assert_eq!(result, Some(make_agent("test")));
    }

    #[test]
    // Test that if an organization does not exist in state, None is returned
    fn test_get_organization_none() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        let result = state.get_organization("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if an organization exist in state, Some(organization) is returned
    fn test_get_organization_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        assert!(state
            .set_organization("test", make_organization("test"))
            .is_ok());
        let result = state.get_organization("test").unwrap();
        assert_eq!(result, Some(make_organization("test")));
    }

    #[test]
    // Test that if a certificate does not exist in state, None is returned
    fn test_get_certificate_none() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        let result = state.get_certificate("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if a certificate exist in state, Some(certificate) is returned
    fn test_get_certificate_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        assert!(state
            .set_certificate("test", make_certificate("test"))
            .is_ok());
        let result = state.get_certificate("test").unwrap();
        assert_eq!(result, Some(make_certificate("test")));
    }

    #[test]
    // Test that if a request does not exist in state, None is returned
    fn test_get_request_none() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        let result = state.get_request("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if a request exist in state, Some(request) is returned
    fn test_get_request_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        assert!(state.set_request("test", make_request("test")).is_ok());
        let result = state.get_request("test").unwrap();
        assert_eq!(result, Some(make_request("test")));
    }

    #[test]
    // Test that if a standard does not exist in state, None is returned
    fn test_get_standard_none() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        let result = state.get_standard("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if a standard exist in state, Some(standard) is returned
    fn test_get_standard_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        assert!(state.set_standard("test", make_standard("test")).is_ok());
        let result = state.get_standard("test").unwrap();
        assert_eq!(result, Some(make_standard("test")));
    }

    #[test]
    // Test that if an assertion does not exist in state, None is returned
    fn test_get_assertion_none() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        let result = state.get_assertion("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if an assertion exists in state, Some(assertion) is returned
    fn test_get_assertion_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        assert!(state.set_assertion("test", make_assertion("test")).is_ok());
        let result = state.get_assertion("test").unwrap();
        assert_eq!(result, Some(make_assertion("test")));
    }

    fn make_agent(public_key: &str) -> Agent {
        let mut new_agent = Agent::new();
        new_agent.set_public_key(public_key.to_string());
        new_agent.set_name("test".to_string());
        new_agent.set_timestamp(1);

        new_agent
    }

    fn make_organization(org_id: &str) -> Organization {
        let mut new_org = Organization::new();
        new_org.set_id(org_id.to_string());
        new_org.set_name("test".to_string());
        new_org
            .set_organization_type(common::proto::organization::Organization_Type::STANDARDS_BODY);

        let mut new_contact = common::proto::organization::Organization_Contact::new();
        new_contact.set_name("test".to_string());
        new_contact.set_phone_number("test".to_string());
        new_contact.set_language_code("test".to_string());
        new_org.set_contacts(protobuf::RepeatedField::from_vec(vec![new_contact]));

        new_org
    }

    fn make_certificate(cert_id: &str) -> Certificate {
        let mut new_certificate = Certificate::new();
        new_certificate.set_id(cert_id.to_string());
        new_certificate.set_certifying_body_id("test_cert_body".to_string());
        new_certificate.set_factory_id("test_factory".to_string());
        new_certificate.set_standard_id("test_standard".to_string());
        new_certificate.set_standard_version("test".to_string());

        new_certificate
    }

    fn make_request(request_id: &str) -> Request {
        let mut request = Request::new();
        request.set_id(request_id.to_string());
        request.set_status(common::proto::request::Request_Status::OPEN);
        request.set_standard_id("test_standard".to_string());
        request.set_factory_id("test_org".to_string());
        request.set_request_date(1);

        request
    }

    fn make_standard(standard_id: &str) -> Standard {
        let mut new_standard_version = common::proto::standard::Standard_StandardVersion::new();
        new_standard_version.set_version("test".to_string());
        new_standard_version.set_description("test".to_string());
        new_standard_version.set_link("test".to_string());
        new_standard_version.set_approval_date(1);

        let mut new_standard = Standard::new();
        new_standard.set_id(standard_id.to_string());
        new_standard.set_name("test".to_string());
        new_standard.set_organization_id("test_org".to_string());
        new_standard.set_versions(protobuf::RepeatedField::from_vec(vec![
            new_standard_version,
        ]));

        new_standard
    }

    fn make_assertion(assertion_id: &str) -> Assertion {
        let mut assertion = Assertion::new();
        assertion.set_id(assertion_id.to_string());
        assertion.set_assertor_pub_key("test".to_string());
        assertion.set_assertion_type(common::proto::assertion::Assertion_Type::FACTORY);
        assertion.set_object_id("test".to_string());

        assertion
    }
}
