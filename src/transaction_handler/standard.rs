cfg_if! {
  if #[cfg(target_arch = "wasm32")] {
    use sabre_sdk::ApplyError;
  } else {
    use sawtooth_sdk::processor::handler::ApplyError;
  }
}

use common::proto;
use common::proto::organization::Organization_Authorization_Role::TRANSACTOR;
use state::ConsensourceState;

use transaction_handler::{agent, organization};

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
pub fn create(
    payload: &proto::payload::CreateStandardAction,
    state: &mut ConsensourceState,
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
    let agt = agent::get(state, signer_public_key)?;

    agent::has_organization(&agt)?;

    // Validate org existence
    let org = organization::get(state, agt.get_organization_id())?;

    organization::check_type(&org, proto::organization::Organization_Type::STANDARDS_BODY)?;

    // Validate agent is authorized
    organization::check_authorization(&org, signer_public_key, TRANSACTOR)?;

    let new_standard = make_proto(payload, &org.get_id());

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
pub fn update(
    payload: &proto::payload::UpdateStandardAction,
    state: &mut ConsensourceState,
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
    let agt = agent::get(state, signer_public_key)?;

    agent::has_organization(&agt)?;

    // Validate org existence
    let org = organization::get(state, agt.get_organization_id())?;

    organization::check_type(&org, proto::organization::Organization_Type::STANDARDS_BODY)?;

    // Validate agent is authorized
    organization::check_authorization(&org, signer_public_key, TRANSACTOR)?;

    // Validade standard was created by agent's organizatio
    if agt.get_organization_id() != standard.get_organization_id() {
        return Err(ApplyError::InvalidTransaction(format!(
            "Organization {} did not create the certification standard {}",
            org.get_name(),
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
    payload: &proto::payload::AccreditCertifyingBodyAction,
    state: &mut ConsensourceState,
    signer_public_key: &str,
) -> Result<(), ApplyError> {
    // Verify the signer
    let agt = agent::get(state, signer_public_key)?;

    // Verify the signer is associated with a Standards Body
    agent::has_organization(&agt)?;

    let agent_organization = organization::get(state, agt.get_organization_id())?;

    organization::check_type(
        &agent_organization,
        proto::organization::Organization_Type::STANDARDS_BODY,
    )?;

    // Verify the signer is an authorized transactor within their organization
    organization::check_authorization(&agent_organization, signer_public_key, TRANSACTOR)?;

    // Verify the certifying_body_id is associated with a Certifying body
    let mut certifying_body = organization::get(state, payload.get_certifying_body_id())?;

    organization::check_type(
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
    if agt.get_organization_id() != standard.get_organization_id() {
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
    certifying_body_details.set_accreditations(protobuf::RepeatedField::from_vec(accreditations));

    certifying_body.set_certifying_body_details(certifying_body_details);

    // Put updated CertifyingBody in state
    state.set_organization(payload.get_certifying_body_id(), certifying_body)?;

    Ok(())
}

pub fn make_proto(
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

#[cfg(test)]
mod tests {
    use super::*;

    use transaction_handler::test_utils::*;

    #[test]
    /// Test that if CreateStandardAction is valid an OK is returned and a new Standard is added to state
    fn test_create_standard_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_standard_create_action();

        assert!(create(&action, &mut state, PUBLIC_KEY_1).is_ok());

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_standard_create_action();

        create(&action, &mut state, PUBLIC_KEY_1).unwrap();

        let result = create(&action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        create(&standard_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_standard_update_action("test_change");

        assert!(update(&action, &mut state, PUBLIC_KEY_1).is_ok());

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        //update standard without creating it
        let action = make_standard_update_action("test_change");

        let result = update(&action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        create(&standard_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_standard_update_action("test");

        let result = update(&action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        create(&standard_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_standard_update_action("test_change");

        let result = update(&action, &mut state, "non_existent_agent_pub_key");

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        create(&standard_action, &mut state, PUBLIC_KEY_1).unwrap();

        //add agent
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();

        //update standard without creating it
        let action = make_standard_update_action("test_change");

        let result = update(&action, &mut state, PUBLIC_KEY_2);

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
    /// Test that if AccreditCertifyingBodyAction is valid an OK is returned and a new Accreditation is added to state
    fn test_accredit_certifying_body_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add certifying org
        let org_action = make_organization_create_action(
            CERT_ORG_ID,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard = make_standard_create_action();
        create(&standard, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_accredit_certifying_body_action();

        assert!(accredit_certifying_body(&action, &mut state, PUBLIC_KEY_1).is_ok());

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add certifying org
        let org_action = make_organization_create_action(
            CERT_ORG_ID,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard = make_standard_create_action();
        create(&standard, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_accredit_certifying_body_action();

        let result = accredit_certifying_body(&action, &mut state, "non_existent_agent_pub_key");

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add certifying org
        let org_action = make_organization_create_action(
            CERT_ORG_ID,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard = make_standard_create_action();
        create(&standard, &mut state, PUBLIC_KEY_1).unwrap();

        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_3).unwrap();

        let action = make_accredit_certifying_body_action();

        let result = accredit_certifying_body(&action, &mut state, PUBLIC_KEY_3);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add certifying org
        let org_action = make_organization_create_action(
            CERT_ORG_ID,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard = make_standard_create_action();
        create(&standard, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_accredit_certifying_body_action();

        let result = accredit_certifying_body(&action, &mut state, PUBLIC_KEY_2);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add certifying org
        let org_action = make_organization_create_action(
            CERT_ORG_ID,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();

        //skip adding standard

        let action = make_accredit_certifying_body_action();

        let result = accredit_certifying_body(&action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add certifying org
        let org_action = make_organization_create_action(
            CERT_ORG_ID,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard = make_standard_create_action();
        create(&standard, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_accredit_certifying_body_action();

        accredit_certifying_body(&action, &mut state, PUBLIC_KEY_1).unwrap();

        let result = accredit_certifying_body(&action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add certifying org
        let org_action = make_organization_create_action(
            CERT_ORG_ID,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard = make_standard_create_action();
        create(&standard, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_accredit_certifying_body_invalid_date_action();

        let result = accredit_certifying_body(&action, &mut state, PUBLIC_KEY_1);

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
}
