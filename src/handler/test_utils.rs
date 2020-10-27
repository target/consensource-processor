#![allow(dead_code)]

use common::proto;
use common::proto::organization::Organization_Authorization_Role::{ADMIN, TRANSACTOR};
use common::proto::payload::*;

use sawtooth_sdk::processor::handler::{ContextError, TransactionContext};

use std::cell::RefCell;
use std::collections::HashMap;

pub const PUBLIC_KEY_1: &str = "test_public_key_1";
pub const PUBLIC_KEY_2: &str = "test_public_key_2";
pub const PUBLIC_KEY_3: &str = "test_public_key_3";
pub const CERT_ORG_ID: &str = "test_cert_org";
pub const FACTORY_ID: &str = "test_factory";
pub const STANDARDS_BODY_ID: &str = "test_standards_body";
pub const INGESTION_ID: &str = "ingestion_id";
pub const CERT_ID: &str = "test_cert";
pub const REQUEST_ID: &str = "test_request";
pub const STANDARD_ID: &str = "test_standard";
pub const ASSERTION_ID_1: &str = "test_assertion_1";
pub const ASSERTION_ID_2: &str = "test_assertion_2";
pub const ASSERTION_ID_3: &str = "test_assertion_3";

/// A MockTransactionContext that can be used for testing
#[derive(Default, Debug)]
pub struct MockTransactionContext {
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
    fn delete_state_entries(&self, addresses: &[String]) -> Result<Vec<String>, ContextError> {
        let mut deleted_addr: Vec<String> = vec![];
        for addr in addresses {
            self.state.borrow_mut().remove(addr);
            deleted_addr.push(addr.to_string());
        }
        Ok(deleted_addr)
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

pub fn make_agent(pub_key: &str) -> proto::agent::Agent {
    let mut new_agent = proto::agent::Agent::new();
    new_agent.set_public_key(pub_key.to_string());
    new_agent.set_name("test".to_string());

    new_agent
}

pub fn make_organization(
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

pub fn make_organization_update(
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

pub fn make_certificate(cert_org_id: &str) -> proto::certificate::Certificate {
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

pub fn make_request() -> proto::request::Request {
    let mut request = proto::request::Request::new();
    request.set_id(REQUEST_ID.to_string());
    request.set_status(proto::request::Request_Status::OPEN);
    request.set_standard_id(STANDARD_ID.to_string());
    request.set_factory_id(FACTORY_ID.to_string());
    request.set_request_date(1);

    request
}

pub fn make_request_update() -> proto::request::Request {
    let mut request = proto::request::Request::new();
    request.set_id(REQUEST_ID.to_string());
    request.set_status(proto::request::Request_Status::IN_PROGRESS);
    request.set_standard_id(STANDARD_ID.to_string());
    request.set_factory_id(FACTORY_ID.to_string());
    request.set_request_date(1);

    request
}

pub fn make_standard(org_id: &str) -> proto::standard::Standard {
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

pub fn make_standard_update() -> proto::standard::Standard {
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

pub fn make_assertion(
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

pub fn make_agent_create_action() -> CreateAgentAction {
    let mut new_agent_action = CreateAgentAction::new();
    new_agent_action.set_name("test".to_string());
    new_agent_action
}

pub fn make_organization_create_action(
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

pub fn make_organization_update_action() -> UpdateOrganizationAction {
    let mut org_update_action = UpdateOrganizationAction::new();
    let mut new_contact = proto::organization::Organization_Contact::new();
    new_contact.set_name("test_change".to_string());
    new_contact.set_phone_number("test_change".to_string());
    new_contact.set_language_code("test_change".to_string());
    org_update_action.set_contacts(protobuf::RepeatedField::from_vec(vec![new_contact]));
    org_update_action
}

pub fn make_authorize_agent_action(pub_key: &str) -> AuthorizeAgentAction {
    let mut new_auth_action = AuthorizeAgentAction::new();
    new_auth_action.set_public_key(pub_key.to_string());
    new_auth_action.set_role(TRANSACTOR);
    new_auth_action
}

pub fn make_issue_certificate_action() -> IssueCertificateAction {
    let mut issuance_action = IssueCertificateAction::new();
    issuance_action.set_id(CERT_ID.to_string());
    issuance_action.set_source(IssueCertificateAction_Source::INDEPENDENT);
    issuance_action.set_standard_id(STANDARD_ID.to_string());
    issuance_action.set_factory_id(FACTORY_ID.to_string());
    issuance_action.set_valid_from(1);
    issuance_action.set_valid_to(2);
    issuance_action
}

pub fn make_issue_certificate_action_with_invalid_dates() -> IssueCertificateAction {
    let mut issuance_action = IssueCertificateAction::new();
    issuance_action.set_id(CERT_ID.to_string());
    issuance_action.set_source(IssueCertificateAction_Source::INDEPENDENT);
    issuance_action.set_standard_id(STANDARD_ID.to_string());
    issuance_action.set_factory_id(FACTORY_ID.to_string());
    issuance_action.set_valid_from(2);
    issuance_action.set_valid_to(1);
    issuance_action
}

pub fn make_issue_certificate_action_with_no_source() -> IssueCertificateAction {
    let mut issuance_action = IssueCertificateAction::new();
    issuance_action.set_id(CERT_ID.to_string());
    issuance_action.set_source(IssueCertificateAction_Source::UNSET_SOURCE);
    issuance_action.set_standard_id(STANDARD_ID.to_string());
    issuance_action.set_factory_id(FACTORY_ID.to_string());
    issuance_action.set_valid_from(1);
    issuance_action.set_valid_to(2);
    issuance_action
}

pub fn make_issue_certificate_action_non_existent_standard() -> IssueCertificateAction {
    let mut issuance_action = IssueCertificateAction::new();
    issuance_action.set_id(CERT_ID.to_string());
    issuance_action.set_source(IssueCertificateAction_Source::INDEPENDENT);
    issuance_action.set_standard_id("non_existent_standard".to_string());
    issuance_action.set_factory_id(FACTORY_ID.to_string());
    issuance_action.set_valid_from(1);
    issuance_action.set_valid_to(2);
    issuance_action
}

pub fn make_standard_create_action() -> CreateStandardAction {
    let mut new_standard_action = CreateStandardAction::new();
    new_standard_action.set_standard_id(STANDARD_ID.to_string());
    new_standard_action.set_name("test".to_string());
    new_standard_action.set_version("test".to_string());
    new_standard_action.set_description("test".to_string());
    new_standard_action.set_link("test".to_string());
    new_standard_action.set_approval_date(1);
    new_standard_action
}

pub fn make_standard_update_action(version: &str) -> UpdateStandardAction {
    let mut standard_update_action = UpdateStandardAction::new();
    standard_update_action.set_standard_id(STANDARD_ID.to_string());
    standard_update_action.set_version(version.to_string());
    standard_update_action.set_description("test_change".to_string());
    standard_update_action.set_link("test_change".to_string());
    standard_update_action.set_approval_date(1);
    standard_update_action
}

pub fn make_open_request_action() -> OpenRequestAction {
    let mut new_request_action = OpenRequestAction::new();
    new_request_action.set_id(REQUEST_ID.to_string());
    new_request_action.set_standard_id(STANDARD_ID.to_string());
    new_request_action.set_request_date(1);
    new_request_action
}

pub fn make_change_request_action() -> ChangeRequestStatusAction {
    let mut change_request_action = ChangeRequestStatusAction::new();
    change_request_action.set_request_id(REQUEST_ID.to_string());
    change_request_action.set_status(proto::request::Request_Status::IN_PROGRESS);
    change_request_action
}

pub fn make_change_request_close_action() -> ChangeRequestStatusAction {
    let mut change_request_action = ChangeRequestStatusAction::new();
    change_request_action.set_request_id(REQUEST_ID.to_string());
    change_request_action.set_status(proto::request::Request_Status::CLOSED);
    change_request_action
}

pub fn make_change_request_certified_action() -> ChangeRequestStatusAction {
    let mut change_request_action = ChangeRequestStatusAction::new();
    change_request_action.set_request_id(REQUEST_ID.to_string());
    change_request_action.set_status(proto::request::Request_Status::CERTIFIED);
    change_request_action
}

pub fn make_accredit_certifying_body_action() -> AccreditCertifyingBodyAction {
    let mut accredit_action = AccreditCertifyingBodyAction::new();
    accredit_action.set_certifying_body_id(CERT_ORG_ID.to_string());
    accredit_action.set_standard_id(STANDARD_ID.to_string());
    accredit_action.set_valid_from(1);
    accredit_action.set_valid_to(2);
    accredit_action
}

pub fn make_accredit_certifying_body_invalid_date_action() -> AccreditCertifyingBodyAction {
    let mut accredit_action = AccreditCertifyingBodyAction::new();
    accredit_action.set_certifying_body_id(CERT_ORG_ID.to_string());
    accredit_action.set_standard_id(STANDARD_ID.to_string());
    accredit_action.set_valid_from(2);
    accredit_action.set_valid_to(1);
    accredit_action
}

pub fn make_assert_action_new_factory(id: &str) -> AssertAction {
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

pub fn make_assert_action_new_certificate(id: &str) -> AssertAction {
    let mut assert_action = AssertAction::new();
    assert_action.set_new_certificate(make_issue_certificate_action());
    assert_action.set_assertion_id(id.to_string());
    assert_action
}

pub fn make_assert_action_new_certificate_with_invalid_dates(id: &str) -> AssertAction {
    let mut assert_action = AssertAction::new();
    assert_action.set_new_certificate(make_issue_certificate_action_with_invalid_dates());
    assert_action.set_assertion_id(id.to_string());
    assert_action
}

pub fn make_assert_action_new_certificate_with_no_source(id: &str) -> AssertAction {
    let mut assert_action = AssertAction::new();
    assert_action.set_new_certificate(make_issue_certificate_action_with_no_source());
    assert_action.set_assertion_id(id.to_string());
    assert_action
}

pub fn make_assert_action_new_certificate_with_non_existent_standard(id: &str) -> AssertAction {
    let mut assert_action = AssertAction::new();
    assert_action.set_new_certificate(make_issue_certificate_action_non_existent_standard());
    assert_action.set_assertion_id(id.to_string());
    assert_action
}

pub fn make_assert_action_new_standard(id: &str) -> AssertAction {
    let mut assert_action = AssertAction::new();
    assert_action.set_new_standard(make_standard_create_action());
    assert_action.set_assertion_id(id.to_string());
    assert_action
}

pub fn make_transfer_assertion_action_factory(id: &str) -> TransferAssertionAction {
    let mut transfer_assertion_action = TransferAssertionAction::new();
    transfer_assertion_action.set_assertion_id(id.to_string());
    transfer_assertion_action
}
