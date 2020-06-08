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

/// Helper to create organization in state
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

/// Helper to update organization from state
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

/// Helper to get organization from state based on id
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
