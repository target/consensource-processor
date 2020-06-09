cfg_if! {
  if #[cfg(target_arch = "wasm32")] {
    use sabre_sdk::ApplyError;
  } else {
    use sawtooth_sdk::processor::handler::ApplyError;
  }
}

use common::proto;
use common::proto::organization::Organization_Authorization_Role::ADMIN;
use state::ConsensourceState;

use handler::organization;

/// Creates a new Agent and submits it to state
/// ```
/// # Errors
/// Returns an error if:
///   - Signer public key already associated with an agent
///   - It fails to submit the new Agent to state.
/// ```
pub fn create(
    payload: &proto::payload::CreateAgentAction,
    state: &mut ConsensourceState,
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
    let new_agent = make_proto(payload, signer_public_key);

    // Put agent in state
    state.set_agent(signer_public_key, new_agent)?;

    Ok(())
}

/// Gets an existing Agent and submits it to state
/// ```
/// # Errors
/// Returns an error if:
///   - Signer public key is not associated with any agent
/// ```
pub fn get(
    state: &mut ConsensourceState,
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
pub fn authorize(
    payload: &proto::payload::AuthorizeAgentAction,
    state: &mut ConsensourceState,
    signer_public_key: &str,
) -> Result<(), ApplyError> {
    // Validate an agent associated with the signer public key exists
    let signer_agent = get(state, signer_public_key)?;

    // Validate signer is associated with an organization
    has_organization(&signer_agent)?;

    // Validate the organization the signer is associated with exists
    let mut organization = organization::get(state, signer_agent.get_organization_id())?;

    // Validate signer agent is an ADMIN
    organization::check_authorization(&organization, signer_public_key, ADMIN)?;

    // Validate agent to be authorized exists.
    let mut agent_to_be_authorized = get(state, payload.get_public_key())?;

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

/// Helper to check whether the agent is a member of an organization
pub fn has_organization(agent: &proto::agent::Agent) -> Result<(), ApplyError> {
    if agent.get_organization_id().is_empty() {
        return Err(ApplyError::InvalidTransaction(format!(
            "Agent is not associated with an organization: {}",
            agent.get_organization_id(),
        )));
    }
    Ok(())
}

pub fn make_proto(
    payload: &proto::payload::CreateAgentAction,
    signer_public_key: &str,
) -> proto::agent::Agent {
    let mut new_agent = proto::agent::Agent::new();
    new_agent.set_public_key(signer_public_key.to_string());
    new_agent.set_name(payload.get_name().to_string());
    new_agent.set_timestamp(payload.get_timestamp());
    new_agent
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::proto::organization::Organization_Authorization_Role::TRANSACTOR;
    use handler::test_utils::*;

    #[test]
    /// Test that if CreateAgentAction is valid an OK is returned and a new Agent is added to state
    fn test_create_agent_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        let action = make_agent_create_action();

        assert!(create(&action, &mut state, PUBLIC_KEY_1).is_ok());

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
        let action = make_agent_create_action();

        create(&action, &mut state, PUBLIC_KEY_1).unwrap();

        let result = create(&action, &mut state, PUBLIC_KEY_1);

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
    /// Test that if AuthorizeAgentAction is valid an OK is returned and a new Authorization is added to state
    fn test_authorize_agent_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        //add agent
        let agent_action = make_agent_create_action();
        create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add second agent
        let second_agent_action = make_agent_create_action();
        create(&second_agent_action, &mut state, PUBLIC_KEY_2).unwrap();

        let action = make_authorize_agent_action(PUBLIC_KEY_2);

        assert!(authorize(&action, &mut state, PUBLIC_KEY_1).is_ok());

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
        //add agent
        let agent_action = make_agent_create_action();
        create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        //make authorization action without adding an agent
        let action = make_authorize_agent_action("non_existent_agent_pub_key");

        let result = authorize(&action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        organization::create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        //add second agent
        create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();

        //make authorization action without adding an agent
        let action = make_authorize_agent_action(PUBLIC_KEY_2);

        let result = authorize(&action, &mut state, PUBLIC_KEY_2);

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
}
