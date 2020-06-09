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

use transaction_handler::{agent, certificate, organization, standard};

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
pub fn create(
    payload: &proto::payload::AssertAction,
    state: &mut ConsensourceState,
    signer_public_key: &str,
) -> Result<(), ApplyError> {
    // Verify the signer
    let agt = agent::get(state, signer_public_key)?;
    // Check agent's organization
    agent::has_organization(&agt)?;

    let org = organization::get(state, agt.get_organization_id())?;

    organization::check_type(&org, proto::organization::Organization_Type::INGESTION)?;

    // Validate that agent is a transactor
    organization::check_authorization(&org, signer_public_key, TRANSACTOR)?;

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
            organization::make_proto(&factory_assertion.get_factory(), signer_public_key);
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
                organization::get(state, &certificate.get_factory_id())?;
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
        let new_certificate = certificate::make_proto(
            certificate,
            agt.get_organization_id(),
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
            standard::make_proto(payload.get_new_standard(), agt.get_organization_id());
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

#[cfg(test)]
mod tests {
    use super::*;

    use transaction_handler::test_utils::*;

    #[test]
    /// Test that if AssertAction for a new Certificate is valid an Ok is returned and both an Assertion and a Certificate are added to state
    fn test_assert_action_new_certificate_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        //add org
        let org_action = make_organization_create_action(
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let standard_assert_action = make_assert_action_new_standard(ASSERTION_ID_1);
        create(&standard_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

        let factory_assert_action = make_assert_action_new_factory(ASSERTION_ID_2);
        create(&factory_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

        let assert_action = make_assert_action_new_certificate(ASSERTION_ID_3);
        assert!(create(&assert_action, &mut state, PUBLIC_KEY_1).is_ok());

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

        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        //add org
        let org_action = make_organization_create_action(
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let assert_action = make_assert_action_new_standard(ASSERTION_ID_1);
        assert!(create(&assert_action, &mut state, PUBLIC_KEY_1).is_ok());

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

        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        //add org
        let org_action = make_organization_create_action(
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let assert_action = make_assert_action_new_factory(ASSERTION_ID_1);

        create(&assert_action, &mut state, PUBLIC_KEY_1).unwrap();

        let result = create(&assert_action, &mut state, PUBLIC_KEY_1);

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

        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        //add org
        let org_action = make_organization_create_action(
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let standard_assert_action = make_assert_action_new_standard(ASSERTION_ID_1);
        create(&standard_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

        let factory_assert_action = make_assert_action_new_factory(ASSERTION_ID_2);
        create(&factory_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

        let assert_action = make_assert_action_new_certificate_with_invalid_dates(ASSERTION_ID_3);

        let result = create(&assert_action, &mut state, PUBLIC_KEY_1);

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

        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        //add org
        let org_action = make_organization_create_action(
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let standard_assert_action = make_assert_action_new_standard(ASSERTION_ID_1);
        create(&standard_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

        let factory_assert_action = make_assert_action_new_factory(ASSERTION_ID_2);
        create(&factory_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

        let assert_action = make_assert_action_new_certificate_with_no_source(ASSERTION_ID_3);

        let result = create(&assert_action, &mut state, PUBLIC_KEY_1);

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

        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        //add org
        let org_action = make_organization_create_action(
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let standard_assert_action = make_assert_action_new_standard(ASSERTION_ID_1);
        create(&standard_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

        let factory_assert_action = make_assert_action_new_factory(ASSERTION_ID_2);
        create(&factory_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

        let assert_action =
            make_assert_action_new_certificate_with_non_existent_standard(ASSERTION_ID_3);

        let result = create(&assert_action, &mut state, PUBLIC_KEY_1);

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

    #[test]
    /// Test that if AssertAction for a new Factory is valid an Ok is returned and both an Assertion and an Organization are added to state
    fn test_assert_action_new_factory_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        //add org
        let org_action = make_organization_create_action(
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let assert_action = make_assert_action_new_factory(ASSERTION_ID_1);
        assert!(create(&assert_action, &mut state, PUBLIC_KEY_1).is_ok());

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
}
