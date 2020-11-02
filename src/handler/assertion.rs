cfg_if! {
  if #[cfg(target_arch = "wasm32")] {
    use sabre_sdk::ApplyError;
  } else {
    use sawtooth_sdk::processor::handler::ApplyError;
  }
}

use common::addressing::make_assertion_address;
use common::proto;
use common::proto::organization::Organization_Authorization_Role::{ADMIN, TRANSACTOR};
use state::ConsensourceState;

use handler::{agent, certificate, organization, standard};

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
    assertion.set_address(make_assertion_address(payload.get_assertion_id()));
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

pub fn transfer(
    payload: &proto::payload::TransferAssertionAction,
    state: &mut ConsensourceState,
    signer_public_key: &str,
) -> Result<(), ApplyError> {
    // Verify the signer
    let mut agt = agent::get(state, signer_public_key)?;

    // Get the organization to be claimed from the assertion id
    let assertion_id = payload.get_assertion_id();
    let assertion = match state.get_assertion(assertion_id) {
        Ok(Some(assertion)) => Ok(assertion),
        Ok(None) => Err(ApplyError::InvalidTransaction(format!(
            "No assertion with ID {} exists",
            assertion_id
        ))),
        Err(err) => Err(err),
    }?;

    match assertion.get_assertion_type() {
        proto::assertion::Assertion_Type::FACTORY => {
            // Check for a preexisting association with another org
            if !agt.get_organization_id().is_empty() {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Agent is already associated with organization {}",
                    agt.get_organization_id(),
                )));
            }

            let org_id = assertion.get_object_id();
            let mut org = organization::get(state, org_id)?;

            // Check organization type of the assertion being claimed
            organization::check_type(&org, proto::organization::Organization_Type::FACTORY)?;

            // Check if the factory has already been claimed by signing agent
            let auths = org.get_authorizations();
            if auths
                .iter()
                .any(|a| a.get_public_key() == signer_public_key)
            {
                return Err(ApplyError::InvalidTransaction(format!(
                    "Organization {} has already been claimed by agent {} (you)",
                    org.get_name(),
                    signer_public_key
                )));
            }

            // Set organization for the claiming agent
            agt.set_organization_id(String::from(org_id));

            // Authorize agent for org. Using the '.set_authorization'
            // function resets and updates an organization's authorizations
            let mut admin_authorization = proto::organization::Organization_Authorization::new();
            admin_authorization.set_public_key(signer_public_key.to_string());
            admin_authorization.set_role(ADMIN);

            let mut transactor_authorization =
                proto::organization::Organization_Authorization::new();
            transactor_authorization.set_public_key(signer_public_key.to_string());
            transactor_authorization.set_role(TRANSACTOR);

            org.set_authorizations(::protobuf::RepeatedField::from_vec(vec![
                admin_authorization,
                transactor_authorization,
            ]));

            // Update agent and factory organization state
            state.set_agent(signer_public_key, agt)?;
            state.set_organization(org_id, org)?;
        }
        proto::assertion::Assertion_Type::CERTIFICATE => {
            let mut certificate = match state.get_certificate(assertion.get_object_id()) {
                Ok(Some(cert)) => Ok(cert),
                Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                    "Asserted Certificate with id {} does not exist",
                    assertion.get_object_id()
                ))),
                Err(err) => Err(err),
            }?;
            let cert_org = organization::get(state, agt.get_organization_id())?;
            organization::check_type(
                &cert_org,
                proto::organization::Organization_Type::CERTIFYING_BODY,
            )?;
            // TODO: should there be a check to see if the auditor is accredited to this standard?
            // update cert_body_id to their org_id
            certificate.set_certifying_body_id(agt.get_organization_id().to_string());
            state.set_certificate(&certificate.id, certificate.clone())?;
        }
        proto::assertion::Assertion_Type::STANDARD => {
            let mut standard = match state.get_standard(assertion.get_object_id()) {
                Ok(Some(standard)) => Ok(standard),
                Ok(None) => Err(ApplyError::InvalidTransaction(format!(
                    "Asserted Standard with id {} does not exist",
                    assertion.get_object_id()
                ))),
                Err(err) => Err(err),
            }?;
            let standards_org = organization::get(state, agt.get_organization_id())?;
            organization::check_type(
                &standards_org,
                proto::organization::Organization_Type::STANDARDS_BODY,
            )?;
            // update standards_body_id to their org_id
            standard.set_organization_id(agt.get_organization_id().to_string());
            state.set_standard(&standard.id, standard.clone())?;
        }
        proto::assertion::Assertion_Type::UNSET_TYPE => {
            return Err(ApplyError::InvalidTransaction(
                "Transfer of ownership for assertion of type UNSET_TYPE is not  supported"
                    .to_string(),
            ))
        }
    }

    // Update state to delete assertion
    state.delete_assertion(assertion_id)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use handler::test_utils::*;

    #[test]
    /// Test that if AssertAction for a new Certificate is valid an Ok is returned and both an Assertion and a Certificate are added to state
    fn test_assert_action_new_certificate_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        // add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        // add org
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

        // add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        // add org
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

        // add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        // add org
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

        // add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        // add org
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

        // add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        // add org
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

        // add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        // add org
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

        // add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        // add org
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

    #[test]
    /// Test that TransferAssertionAction for a FACTORY assertion is valid.
    /// The factory assertion should be removed from state.
    fn test_transfer_assertion_action_for_factory() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        // add ingestion agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        // add ingestion org
        let org_action = make_organization_create_action(
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        // assert a factory organization
        let factory_assert_action = make_assert_action_new_factory(ASSERTION_ID_1);
        create(&factory_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

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
            .expect("Failed to fetch asserted factory")
            .expect("No asserted factory found");

        assert_eq!(
            factory,
            make_organization(
                FACTORY_ID,
                proto::organization::Organization_Type::FACTORY,
                PUBLIC_KEY_1
            )
        );

        // add transfer agent
        let second_agent_action = make_agent_create_action();
        agent::create(&second_agent_action, &mut state, PUBLIC_KEY_2).unwrap();

        // make transfer assertion action
        let factory_transfer_assertion_action = make_transfer_assertion_action(ASSERTION_ID_1);

        assert!(transfer(&factory_transfer_assertion_action, &mut state, PUBLIC_KEY_2).is_ok());

        // check that factory assertion is no longer in state
        assert!(state
            .get_assertion(ASSERTION_ID_1)
            .expect("Failed to fetch Assertion")
            .is_none());

        // check if the transfer agent now belongs to the factory
        let second_agent = agent::get(&mut state, PUBLIC_KEY_2).unwrap();
        assert_eq!(second_agent.get_organization_id(), FACTORY_ID);
    }

    #[test]
    /// Test that TransferAssertionAction for a CERTIFICATE assertion is valid.
    /// The certificate assertion should be removed from state.
    fn test_transfer_assertion_action_for_certificate() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        // add ingestion agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        // add ingestion org
        let org_action = make_organization_create_action(
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        // assert a standard organization
        let standard_assert_action = make_assert_action_new_standard(ASSERTION_ID_1);
        create(&standard_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

        // assert a factory organization
        let factory_assert_action = make_assert_action_new_factory(ASSERTION_ID_2);
        create(&factory_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

        // assert a certificate organization
        let cert_assert_action = make_assert_action_new_certificate(ASSERTION_ID_3);
        create(&cert_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

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

        let cert = state
            .get_certificate(CERT_ID)
            .expect("Failed to fetch asserted certificate")
            .expect("No asserted certificate found");

        assert_eq!(cert, make_certificate(INGESTION_ID));

        // add transfer agent
        let second_agent_action = make_agent_create_action();
        agent::create(&second_agent_action, &mut state, PUBLIC_KEY_2).unwrap();

        // add transfer agent certifying body
        let cert_org_action = make_organization_create_action(
            CERT_ORG_ID,
            proto::organization::Organization_Type::CERTIFYING_BODY,
        );
        organization::create(&cert_org_action, &mut state, PUBLIC_KEY_2).unwrap();

        // make transfer assertion action
        let transfer_assertion_action = make_transfer_assertion_action(ASSERTION_ID_3);
        let result = transfer(&transfer_assertion_action, &mut state, PUBLIC_KEY_2);
        println!("{:?}", result);
        assert!(result.is_ok());

        // check that certificate assertion is no longer in state
        assert!(state
            .get_assertion(ASSERTION_ID_3)
            .expect("Failed to fetch Assertion")
            .is_none());

        // check if the cert now belongs to the transfer agent's cert org
        let cert_after_transfer = state
            .get_certificate(CERT_ID)
            .expect("Failed to fetch certificate")
            .expect("No certificate found");

        assert_eq!(cert_after_transfer.get_certifying_body_id(), CERT_ORG_ID);
    }

    #[test]
    /// Test that TransferAssertionAction for a STANDARD assertion is valid.
    /// The standard assertion should be removed from state.
    fn test_transfer_assertion_action_for_standard() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);

        // add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        // add org
        let org_action = make_organization_create_action(
            INGESTION_ID,
            proto::organization::Organization_Type::INGESTION,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        // assert a standard organization
        let standard_assert_action = make_assert_action_new_standard(ASSERTION_ID_1);
        create(&standard_assert_action, &mut state, PUBLIC_KEY_1).unwrap();

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
            .expect("Failed to fetch asserted standard")
            .expect("No asserted standard found");

        assert_eq!(standard, make_standard(INGESTION_ID));

        // add transfer agent
        let second_agent_action = make_agent_create_action();
        agent::create(&second_agent_action, &mut state, PUBLIC_KEY_2).unwrap();

        // add transfer agent standards body
        let cert_org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&cert_org_action, &mut state, PUBLIC_KEY_2).unwrap();

        // make transfer assertion action
        let transfer_assertion_action = make_transfer_assertion_action(ASSERTION_ID_1);

        assert!(transfer(&transfer_assertion_action, &mut state, PUBLIC_KEY_2).is_ok());

        // check that standard assertion is no longer in state
        assert!(state
            .get_assertion(ASSERTION_ID_1)
            .expect("Failed to fetch Assertion")
            .is_none());

        // check if the transfered standard now belongs to the second agent's org
        let standard_after_transfer = state
            .get_standard(STANDARD_ID)
            .expect("Failed to fetch standard")
            .expect("No standard found");

        assert_eq!(
            standard_after_transfer.get_organization_id(),
            STANDARDS_BODY_ID
        );
    }
}
