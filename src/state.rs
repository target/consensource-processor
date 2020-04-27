/*
 * CertState
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

use common::addressing;

use common::proto;
use protobuf;

pub struct CertState<'a> {
    context: &'a mut dyn TransactionContext,
}

impl<'a> CertState<'a> {
    // Create new instance of CertState
    pub fn new(context: &'a mut dyn TransactionContext) -> CertState {
        CertState { context }
    }

    /// Fetches and deserializes an Agent's data from state
    /// ```
    /// # Erros
    /// Return an error if it fails to deserialize the Agent's data
    /// ```
    pub fn get_agent(
        &mut self,
        agent_public_key: &str,
    ) -> Result<Option<proto::agent::Agent>, ApplyError> {
        let address = addressing::make_agent_address(agent_public_key);
        let state_data = self.context.get_state_entry(&address)?;
        match state_data {
            Some(data) => {
                let agents: proto::agent::AgentContainer =
                    protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                        ApplyError::InvalidTransaction(String::from(
                            "Cannot deserialize agent container",
                        ))
                    })?;

                for agent in agents.get_entries() {
                    if agent.public_key == agent_public_key {
                        return Ok(Some(agent.clone()));
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Fetches and deserializes an Organization's data from state
    /// ```
    /// # Erros
    /// Return an error if it fails to deserialize the Organization's data
    /// ```
    pub fn get_organization(
        &mut self,
        organization_id: &str,
    ) -> Result<Option<proto::organization::Organization>, ApplyError> {
        let address = addressing::make_organization_address(organization_id);
        let state_data = self.context.get_state_entry(&address)?;
        match state_data {
            Some(data) => {
                let organizations: proto::organization::OrganizationContainer =
                    protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                        ApplyError::InvalidTransaction(String::from(
                            "Cannot deserialize organization container",
                        ))
                    })?;

                for organization in organizations.get_entries() {
                    if organization.id == organization_id {
                        return Ok(Some(organization.clone()));
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Fetches and deserializes a Certificate's data from state
    /// ```
    /// # Erros
    /// Return an error if it fails to deserialize the Certificate's data
    /// ```
    pub fn get_certificate(
        &mut self,
        certificate_id: &str,
    ) -> Result<Option<proto::certificate::Certificate>, ApplyError> {
        let address = addressing::make_certificate_address(certificate_id);
        let state_data = self.context.get_state_entry(&address)?;
        match state_data {
            Some(data) => {
                let certificates: proto::certificate::CertificateContainer =
                    protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                        ApplyError::InvalidTransaction(String::from(
                            "Cannot deserialize certificate container",
                        ))
                    })?;

                for certificate in certificates.get_entries() {
                    if certificate.id == certificate_id {
                        return Ok(Some(certificate.clone()));
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Fetches and deserializes a Request data from state
    /// ```
    /// # Erros
    /// Return an error if it fails to deserialize the Request's data
    /// ```
    pub fn get_request(
        &mut self,
        request_id: &str,
    ) -> Result<Option<proto::request::Request>, ApplyError> {
        let address = addressing::make_request_address(request_id);
        let state_data = self.context.get_state_entry(&address)?;
        match state_data {
            Some(data) => {
                let open_requests: proto::request::RequestContainer =
                    protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                        ApplyError::InvalidTransaction(String::from(
                            "Cannot deserialize Request container",
                        ))
                    })?;

                for open_request in open_requests.get_entries() {
                    if open_request.id == request_id {
                        return Ok(Some(open_request.clone()));
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Fetches and deserializes a Standard data from state
    /// ```
    /// # Erros
    /// Return an error if it fails to deserialize the Standard's data
    /// ```
    pub fn get_standard(
        &mut self,
        standard_id: &str,
    ) -> Result<Option<proto::standard::Standard>, ApplyError> {
        let address = addressing::make_standard_address(standard_id);
        let state_data = self.context.get_state_entry(&address)?;
        match state_data {
            Some(data) => {
                let standards: proto::standard::StandardContainer =
                    protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                        ApplyError::InvalidTransaction(String::from(
                            "Cannot deserialize Standard container",
                        ))
                    })?;

                for standard in standards.get_entries() {
                    if standard.id == standard_id {
                        return Ok(Some(standard.clone()));
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Fetches and deserializes Assertion data from state
    /// ```
    /// # Errors
    /// Return an error if it fails to deserialize the Assertion's data
    /// ```
    pub fn get_assertion(
        &mut self,
        assertion_id: &str,
    ) -> Result<Option<proto::assertion::Assertion>, ApplyError> {
        let address = addressing::make_assertion_address(assertion_id);
        let state_data = self.context.get_state_entry(&address)?;
        match state_data {
            Some(data) => {
                let assertions: proto::assertion::AssertionContainer =
                    protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                        ApplyError::InvalidTransaction(String::from(
                            "Cannot deserialize Assertion container",
                        ))
                    })?;

                for assertion in assertions.get_entries() {
                    if assertion.id == assertion_id {
                        return Ok(Some(assertion.clone()));
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// As the addressing scheme does not guarantee uniquesness, this adds an Agent into a Agent Container
    /// which works like a hashbucket, serializes the container and puts it into state,
    /// ```
    /// # Errors
    /// Returns an error if it fails to serialize the container or fails to set it to state
    /// ```
    pub fn set_agent(
        &mut self,
        agent_public_key: &str,
        agent: proto::agent::Agent,
    ) -> Result<(), ApplyError> {
        let address = addressing::make_agent_address(agent_public_key);
        let state_data = self.context.get_state_entry(&address)?;
        let mut agents: proto::agent::AgentContainer = match state_data {
            Some(data) => protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                ApplyError::InvalidTransaction(String::from("Cannot deserialize agent container"))
            })?,
            // If there nothing at that memory address in state, make a new container, and create a new agent
            None => proto::agent::AgentContainer::new(),
        };

        // Use an iterator to find the index of an agent pub key that matches the agent attempting to be created
        if let Some((i, _)) = agents
            .entries
            .iter()
            .enumerate()
            .find(|(_i, agent)| agent.public_key == agent_public_key)
        {
            // If that agent already exists, set agents_slice to that agent
            let agent_slice = agents.entries.as_mut_slice();
            agent_slice[i] = agent;
        } else {
            // Push new and unique agent to the AgentContainer
            agents.entries.push(agent);
            agents.entries.sort_by_key(|a| a.clone().public_key);
        }

        let serialized = protobuf::Message::write_to_bytes(&agents).map_err(|_err| {
            ApplyError::InvalidTransaction(String::from("Cannot serialize agent container"))
        })?;

        // Insert serialized AgentContainer to an address in the merkle tree
        self.context.set_state_entry(address, serialized)?;
        Ok(())
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
        organization: proto::organization::Organization,
    ) -> Result<(), ApplyError> {
        let address = addressing::make_organization_address(organization_id);
        let state_data = self.context.get_state_entry(&address)?;
        let mut organizations: proto::organization::OrganizationContainer = match state_data {
            Some(data) => protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                ApplyError::InvalidTransaction(String::from(
                    "Cannot deserialize organization container",
                ))
            })?,
            // If there is nothing at that memory address in state, make a new container, and create a new organization
            None => proto::organization::OrganizationContainer::new(),
        };

        // Use an iterator to find the index of an organization's ID that matches the organization attempting to be created
        if let Some((i, _)) = organizations
            .entries
            .iter()
            .enumerate()
            .find(|(_i, organization)| organization.id == organization_id)
        {
            // If that organization already exists, set organization_slice to that organization
            let organization_slice = organizations.entries.as_mut_slice();
            organization_slice[i] = organization;
        } else {
            // Push new and unique organization to the OrganizationContainer
            organizations.entries.push(organization);
            organizations.entries.sort_by_key(|o| o.clone().id);
        }

        let serialized = protobuf::Message::write_to_bytes(&organizations).map_err(|_err| {
            ApplyError::InvalidTransaction(String::from("Cannot serialize organization container"))
        })?;

        // Insert serialized OrganizationContainer to an address in the merkle tree
        self.context.set_state_entry(address, serialized)?;
        Ok(())
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
        certificate: proto::certificate::Certificate,
    ) -> Result<(), ApplyError> {
        let address = addressing::make_certificate_address(certificate_id);
        let state_data = self.context.get_state_entry(&address)?;
        let mut certificates: proto::certificate::CertificateContainer = match state_data {
            Some(data) => protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                ApplyError::InvalidTransaction(String::from(
                    "Cannot deserialize certificate container",
                ))
            })?,
            // If there nothing at that memory address in state, make a new container, and create a new certificate
            None => proto::certificate::CertificateContainer::new(),
        };

        // Use an iterator to find the index of an certificate's ID that matches the certificate attempting to be created
        if let Some((i, _)) = certificates
            .entries
            .iter()
            .enumerate()
            .find(|(_i, certificate)| certificate.id == certificate_id)
        {
            // If that certificate already exists, set certificate_slice to that certificate
            let certificate_slice = certificates.entries.as_mut_slice();
            certificate_slice[i] = certificate;
        } else {
            // Push new and unique certificate to the CertificateContainer
            certificates.entries.push(certificate);
            certificates.entries.sort_by_key(|o| o.clone().id);
        }

        let serialized = protobuf::Message::write_to_bytes(&certificates).map_err(|_err| {
            ApplyError::InvalidTransaction(String::from("Cannot serialize certificate container"))
        })?;

        // Insert serialized CertificateContainer to an address in the merkle tree
        self.context.set_state_entry(address, serialized)?;
        Ok(())
    }

    /// As the addressing scheme does not guarantee uniquesness, this adds a Request into a Request Container
    /// which works like a hashbucket, serializes the container and puts it into state,
    /// ```
    /// # Errors
    /// Returns an error if it fails to serialize the container or fails to set it to state
    /// ```
    pub fn set_request(
        &mut self,
        request_id: &str,
        request: proto::request::Request,
    ) -> Result<(), ApplyError> {
        let address = addressing::make_request_address(request_id);
        let state_data = self.context.get_state_entry(&address)?;
        let mut requests: proto::request::RequestContainer = match state_data {
            Some(data) => protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                ApplyError::InvalidTransaction(String::from("Cannot deserialize request container"))
            })?,
            // If there nothing at that memory address in state, make a new container, and create a new request
            None => proto::request::RequestContainer::new(),
        };

        // Use an iterator to find the index of a request_id that matches the request_id attempting to be created
        if let Some((i, _)) = requests
            .entries
            .iter()
            .enumerate()
            .find(|(_i, request)| request.id == request_id)
        {
            // If that request already exists, set requests_slice to that request
            let request_slice = requests.entries.as_mut_slice();
            request_slice[i] = request;
        } else {
            // Push new and unique request to the RequestContainer
            requests.entries.push(request);
            requests.entries.sort_by_key(|a| a.clone().id);
        }

        let serialized = protobuf::Message::write_to_bytes(&requests).map_err(|_err| {
            ApplyError::InvalidTransaction(String::from("Cannot serialize request container"))
        })?;

        // Insert serialized RequestContainer to an address in the merkle tree
        self.context.set_state_entry(address, serialized)?;
        Ok(())
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
        standard: proto::standard::Standard,
    ) -> Result<(), ApplyError> {
        let address = addressing::make_standard_address(standard_id);
        let state_data = self.context.get_state_entry(&address)?;
        let mut standards: proto::standard::StandardContainer = match state_data {
            Some(data) => protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                ApplyError::InvalidTransaction(String::from(
                    "Cannot deserialize standard container",
                ))
            })?,
            // If there nothing at that memory address in state, make a new container, and create a new standard
            None => proto::standard::StandardContainer::new(),
        };

        // Use an iterator to find the index of a standard_id that matches the standard_id attempting to be created
        if let Some((i, _)) = standards
            .entries
            .iter()
            .enumerate()
            .find(|(_i, standard)| standard.id == standard_id)
        {
            // If that request already exists, set requests_slice to that request
            let standard_slice = standards.entries.as_mut_slice();
            standard_slice[i] = standard;
        } else {
            // Push new and unique request to the StandardContainer
            standards.entries.push(standard);
            standards.entries.sort_by_key(|a| a.clone().id);
        }

        let serialized = protobuf::Message::write_to_bytes(&standards).map_err(|_err| {
            ApplyError::InvalidTransaction(String::from("Cannot serialize standard container"))
        })?;

        // Insert serialized StandardContainer to an address in the merkle tree
        self.context.set_state_entry(address, serialized)?;
        Ok(())
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
        assertion: proto::assertion::Assertion,
    ) -> Result<(), ApplyError> {
        let address = addressing::make_assertion_address(assertion_id);
        let state_data = self.context.get_state_entry(&address)?;
        let mut assertions: proto::assertion::AssertionContainer = match state_data {
            Some(data) => protobuf::parse_from_bytes(data.as_slice()).map_err(|_err| {
                ApplyError::InvalidTransaction(String::from(
                    "Cannot deserialize assertion container",
                ))
            })?,
            // If there nothing at that memory address in state, make a new container, and create a new assertion
            None => proto::assertion::AssertionContainer::new(),
        };

        // Use an iterator to find the index of a assertion_id that matches the assertion_id attempting to be created
        if let Some((i, _)) = assertions
            .entries
            .iter()
            .enumerate()
            .find(|(_i, assertion)| assertion.id == assertion_id)
        {
            // If that assertion already exists, set assertion_slice to that assertion
            let assertion_slice = assertions.entries.as_mut_slice();
            assertion_slice[i] = assertion;
        } else {
            // Push new and unique request to the AssertionContainer
            assertions.entries.push(assertion);
            assertions.entries.sort_by_key(|a| a.clone().id);
        }

        let serialized = protobuf::Message::write_to_bytes(&assertions).map_err(|_err| {
            ApplyError::InvalidTransaction(String::from("Cannot serialize assertion container"))
        })?;

        // Insert serialized AssertionContainer to an address in the merkle tree
        self.context.set_state_entry(address, serialized)?;
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
        let mut state = CertState::new(&mut transaction_context);

        let result = state.get_agent("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if an agent exist in state, Some(agent) is returned
    fn test_get_agent_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);

        assert!(state.set_agent("test", make_agent("test")).is_ok());
        let result = state.get_agent("test").unwrap();
        assert_eq!(result, Some(make_agent("test")));
    }

    #[test]
    // Test that if an organization does not exist in state, None is returned
    fn test_get_organization_none() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);

        let result = state.get_organization("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if an organization exist in state, Some(organization) is returned
    fn test_get_organization_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);

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
        let mut state = CertState::new(&mut transaction_context);

        let result = state.get_certificate("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if a certificate exist in state, Some(certificate) is returned
    fn test_get_certificate_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);

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
        let mut state = CertState::new(&mut transaction_context);

        let result = state.get_request("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if a request exist in state, Some(request) is returned
    fn test_get_request_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);

        assert!(state.set_request("test", make_request("test")).is_ok());
        let result = state.get_request("test").unwrap();
        assert_eq!(result, Some(make_request("test")));
    }

    #[test]
    // Test that if a standard does not exist in state, None is returned
    fn test_get_standard_none() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);

        let result = state.get_standard("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if a standard exist in state, Some(standard) is returned
    fn test_get_standard_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);

        assert!(state.set_standard("test", make_standard("test")).is_ok());
        let result = state.get_standard("test").unwrap();
        assert_eq!(result, Some(make_standard("test")));
    }

    #[test]
    // Test that if an assertion does not exist in state, None is returned
    fn test_get_assertion_none() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);

        let result = state.get_assertion("test").unwrap();
        assert!(result.is_none())
    }

    #[test]
    // Test that if an assertion exists in state, Some(assertion) is returned
    fn test_get_assertion_some() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = CertState::new(&mut transaction_context);

        assert!(state.set_assertion("test", make_assertion("test")).is_ok());
        let result = state.get_assertion("test").unwrap();
        assert_eq!(result, Some(make_assertion("test")));
    }

    fn make_agent(public_key: &str) -> proto::agent::Agent {
        let mut new_agent = proto::agent::Agent::new();
        new_agent.set_public_key(public_key.to_string());
        new_agent.set_name("test".to_string());
        new_agent.set_timestamp(1);

        new_agent
    }

    fn make_organization(org_id: &str) -> proto::organization::Organization {
        let mut new_org = proto::organization::Organization::new();
        new_org.set_id(org_id.to_string());
        new_org.set_name("test".to_string());
        new_org.set_organization_type(proto::organization::Organization_Type::STANDARDS_BODY);

        let mut new_contact = proto::organization::Organization_Contact::new();
        new_contact.set_name("test".to_string());
        new_contact.set_phone_number("test".to_string());
        new_contact.set_language_code("test".to_string());
        new_org.set_contacts(protobuf::RepeatedField::from_vec(vec![new_contact]));

        new_org
    }

    fn make_certificate(cert_id: &str) -> proto::certificate::Certificate {
        let mut new_certificate = proto::certificate::Certificate::new();
        new_certificate.set_id(cert_id.to_string());
        new_certificate.set_certifying_body_id("test_cert_body".to_string());
        new_certificate.set_factory_id("test_factory".to_string());
        new_certificate.set_standard_id("test_standard".to_string());
        new_certificate.set_standard_version("test".to_string());

        new_certificate
    }

    fn make_request(request_id: &str) -> proto::request::Request {
        let mut request = proto::request::Request::new();
        request.set_id(request_id.to_string());
        request.set_status(proto::request::Request_Status::OPEN);
        request.set_standard_id("test_standard".to_string());
        request.set_factory_id("test_org".to_string());
        request.set_request_date(1);

        request
    }

    fn make_standard(standard_id: &str) -> proto::standard::Standard {
        let mut new_standard_version = proto::standard::Standard_StandardVersion::new();
        new_standard_version.set_version("test".to_string());
        new_standard_version.set_description("test".to_string());
        new_standard_version.set_link("test".to_string());
        new_standard_version.set_approval_date(1);

        let mut new_standard = proto::standard::Standard::new();
        new_standard.set_id(standard_id.to_string());
        new_standard.set_name("test".to_string());
        new_standard.set_organization_id("test_org".to_string());
        new_standard.set_versions(protobuf::RepeatedField::from_vec(vec![
            new_standard_version,
        ]));

        new_standard
    }

    fn make_assertion(assertion_id: &str) -> proto::assertion::Assertion {
        let mut assertion = proto::assertion::Assertion::new();
        assertion.set_id(assertion_id.to_string());
        assertion.set_assertor_pub_key("test".to_string());
        assertion.set_assertion_type(proto::assertion::Assertion_Type::FACTORY);
        assertion.set_object_id("test".to_string());

        assertion
    }
}
