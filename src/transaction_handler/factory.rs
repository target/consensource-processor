cfg_if! {
  if #[cfg(target_arch = "wasm32")] {
    use sabre_sdk::ApplyError;
  } else {
    use sawtooth_sdk::processor::handler::ApplyError;
  }
}

use common::proto;
use common::proto::organization::Organization_Authorization_Role::TRANSACTOR;
use state::CertState;

use transaction_handler::{agent, organization};

pub fn open_request(
    payload: &proto::payload::OpenRequestAction,
    state: &mut CertState,
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

pub fn change_request_status(
    payload: &proto::payload::ChangeRequestStatusAction,
    state: &mut CertState,
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
