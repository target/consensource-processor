cfg_if! {
  if #[cfg(target_arch = "wasm32")] {
    use sabre_sdk::ApplyError;
  } else {
    use sawtooth_sdk::processor::handler::ApplyError;
  }
}

use common::proto;
use common::proto::organization::Organization_Authorization_Role::ADMIN;
use state::CertState;

use transaction_handler::organization;

/// Helper to create agent in state
pub fn create(
    payload: &proto::payload::CreateAgentAction,
    state: &mut CertState,
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

/// Helper to get agent from state based on public key
pub fn get(
    state: &mut CertState,
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

pub fn authorize(
    payload: &proto::payload::AuthorizeAgentAction,
    state: &mut CertState,
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
