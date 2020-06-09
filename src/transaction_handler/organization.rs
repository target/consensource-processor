cfg_if! {
  if #[cfg(target_arch = "wasm32")] {
    use sabre_sdk::ApplyError;
  } else {
    use sawtooth_sdk::processor::handler::ApplyError;
  }
}

use common::proto;
use common::proto::organization::Organization_Authorization_Role::{ADMIN, TRANSACTOR};
use state::ConsensourceState;

use transaction_handler::agent;

/// Creates a new Organization and submits it to state
///
/// ```
/// # Errors
/// Returns an error if
///   - an Organization already exists with the same ID
///   - an Agent with the signer public key does not exist
///   - the Agent submitting the transaction is already associated with an organization
///   - it fails to submit the new Organization to state.\
/// ```
pub fn create(
    payload: &proto::payload::CreateOrganizationAction,
    state: &mut ConsensourceState,
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
    let mut agent = agent::get(state, signer_public_key)?;

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
    let new_organization = make_proto(&payload, signer_public_key);

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
pub fn update(
    payload: &proto::payload::UpdateOrganizationAction,
    state: &mut ConsensourceState,
    signer_public_key: &str,
) -> Result<(), ApplyError> {
    // Check agent
    let agent = agent::get(state, signer_public_key)?;

    // Check agent's organization
    agent::has_organization(&agent)?;

    let mut organization = get(state, agent.get_organization_id())?;

    // Validate agent is authorized
    check_authorization(&organization, signer_public_key, ADMIN)?;

    // Handle updates
    if payload.has_address() {
        check_type(
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

/// Gets an existing Organization and submits it to state
///
/// ```
/// # Errors
/// Returns an error if
///   - No Organization with the ID exists
/// ```
pub fn get(
    state: &mut ConsensourceState,
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
pub fn check_authorization(
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

/// Helper to check whether the organization is the expected type
pub fn check_type(
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

pub fn make_proto(
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

#[cfg(test)]
mod tests {
    use super::*;

    use transaction_handler::test_utils::*;

    #[test]
    /// Test that if CreateOrganizationAction is valid an OK is returned and a new Organization is added to state
    fn test_create_organization_handler_valid() {
        let mut transaction_context = MockTransactionContext::default();
        let mut state = ConsensourceState::new(&mut transaction_context);
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );

        assert!(create(&action, &mut state, PUBLIC_KEY_1).is_ok());

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );

        create(&action, &mut state, PUBLIC_KEY_1).unwrap();

        let result = create(&action, &mut state, PUBLIC_KEY_1);

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );

        let result = create(&action, &mut state, "non_existent_agent_pub_key");

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_organization_update_action();

        assert!(update(&action, &mut state, PUBLIC_KEY_1).is_ok());

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
        //add agent
        let agent_action = make_agent_create_action();
        agent::create(&agent_action, &mut state, PUBLIC_KEY_1).unwrap();
        //add org
        let org_action = make_organization_create_action(
            STANDARDS_BODY_ID,
            proto::organization::Organization_Type::STANDARDS_BODY,
        );
        create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        let action = make_organization_update_action();

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
    /// Test that UpdateOrganizationAction fails when unassociated agent updates the organization
    fn test_update_organization_handler_agent_not_associated_with_organization() {
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
        create(&org_action, &mut state, PUBLIC_KEY_1).unwrap();

        //add second agent
        agent::create(&agent_action, &mut state, PUBLIC_KEY_2).unwrap();

        let action = make_organization_update_action();

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
}
