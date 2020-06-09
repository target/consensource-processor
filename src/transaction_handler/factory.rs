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
    payload: &proto::payload::OpenRequestAction,
    state: &mut ConsensourceState,
    signer_public_key: &str,
) -> Result<(), ApplyError> {
    // Validate that the signer associated with a factory
    let agt = agent::get(state, signer_public_key)?;
    let org = organization::get(state, agt.get_organization_id())?;

    organization::check_type(&org, proto::organization::Organization_Type::FACTORY)?;

    // Validate that agent is a transactor
    organization::check_authorization(&org, signer_public_key, TRANSACTOR)?;

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
    request.set_factory_id(agt.get_organization_id().to_string());
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
    payload: &proto::payload::ChangeRequestStatusAction,
    state: &mut ConsensourceState,
    signer_public_key: &str,
) -> Result<(), ApplyError> {
    // Verify that the request does exist
    let mut request = match state.get_request(&payload.request_id) {
        Ok(Some(request)) => Ok(request),
        Ok(None) => Err(ApplyError::InvalidTransaction(format!(
            "Request does not exist: {}",
            payload.request_id
        ))),
        Err(err) => Err(err),
    }?;

    // Validate that the signer associated with a factory
    let agt = agent::get(state, signer_public_key)?;
    let org = organization::get(state, agt.get_organization_id())?;

    // Validate that agent is a transactor
    organization::check_authorization(&org, signer_public_key, TRANSACTOR)?;

    if request.get_factory_id() != agt.get_organization_id() {
        return Err(ApplyError::InvalidTransaction(format!(
            "Agent {} is not authorized to update request {}",
            agt.get_organization_id(),
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

#[cfg(test)]
mod tests {
    use super::*;

    use transaction_handler::standard;
    use transaction_handler::test_utils::*;

    #[test]
    /// Test that if OpenRequestAction is valid an OK is returned and a new Request is added to state
    fn test_open_request_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        standard::create(&standard_action, &mut state, PUBLIC_KEY_2).unwrap();

        let action = make_open_request_action();

        assert!(open_request(&action, &mut state, PUBLIC_KEY_1).is_ok());

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

        let action = make_open_request_action();

        let result = open_request(&action, &mut state, "non_existent_agent_pub_key");

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

        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_open_request_action();

        let result = open_request(&action, &mut state, PUBLIC_KEY_1);

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

        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            "not_even_a_factory",
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_open_request_action();

        let result = open_request(&action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        standard::create(&standard_action, &mut state, PUBLIC_KEY_2).unwrap();

        let action = make_open_request_action();

        open_request(&action, &mut state, PUBLIC_KEY_1).unwrap();

        let result = open_request(&action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();

        let action = make_open_request_action();

        let result = open_request(&action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        standard::create(&standard_action, &mut state, PUBLIC_KEY_2).unwrap();

        let request_action = make_open_request_action();
        open_request(&request_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_change_request_action();

        assert!(change_request_status(&action, &mut state, PUBLIC_KEY_1).is_ok());

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

        let action = make_change_request_action();

        let result = change_request_status(&action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        standard::create(&standard_action, &mut state, PUBLIC_KEY_2).unwrap();

        let request_action = make_open_request_action();
        open_request(&request_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_change_request_action();

        let result = change_request_status(&action, &mut state, "non_existent_agent_pub_key");

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        standard::create(&standard_action, &mut state, PUBLIC_KEY_2).unwrap();

        let request_action = make_open_request_action();
        open_request(&request_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_change_request_action();

        let result = change_request_status(&action, &mut state, PUBLIC_KEY_2);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        standard::create(&standard_action, &mut state, PUBLIC_KEY_2).unwrap();

        let request_action = make_open_request_action();
        open_request(&request_action, &mut state, PUBLIC_KEY_1).unwrap();

        let change_action = make_change_request_close_action();

        change_request_status(&change_action, &mut state, PUBLIC_KEY_1).unwrap();

        let close_action = make_change_request_close_action();

        let result = change_request_status(&close_action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            FACTORY_ID,
            proto::organization::Organization_Type::FACTORY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standards org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_2).unwrap();
        //add standard
        let standard_action = make_standard_create_action();
        standard::create(&standard_action, &mut state, PUBLIC_KEY_2).unwrap();

        let request_action = make_open_request_action();
        open_request(&request_action, &mut state, PUBLIC_KEY_1).unwrap();

        let change_action = make_change_request_certified_action();

        change_request_status(&change_action, &mut state, PUBLIC_KEY_1).unwrap();

        let close_action = make_change_request_close_action();

        let result = change_request_status(&close_action, &mut state, PUBLIC_KEY_1);

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
}
