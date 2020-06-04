cfg_if! {
  if #[cfg(target_arch = "wasm32")] {
    use sabre_sdk::ApplyError;
  } else {
    use sawtooth_sdk::processor::handler::ApplyError;
  }
}

use common::proto;
use common::proto::organization::Organization_Authorization_Role::{ADMIN, TRANSACTOR};
use state::CertState;

use transaction_handler::{agent, organization};

pub fn issue(
    payload: &proto::payload::IssueCertificateAction,
    state: &mut CertState,
    signer_public_key: &str,
) -> Result<(), ApplyError> {
    // Verify that certificate ID is not already associated with a Certificate object
    match state.get_certificate(payload.get_id()) {
        Ok(Some(_)) => Err(ApplyError::InvalidTransaction(format!(
            "Certificate already exists: {}",
            payload.get_id()
        ))),
        Ok(None) => Ok(()),
        Err(err) => Err(err),
    }?;

    // Validate signer public key and agent
    let agt = agent::get(state, signer_public_key)?;

    agent::has_organization(&agt)?;

    // Validate org existence
    let org = organization::get(state, agt.get_organization_id())?;

    organization::check_type(
        &org,
        proto::organization::Organization_Type::CERTIFYING_BODY,
    )?;

    // Validate agent is authorized
    organization::check_authorization(&org, signer_public_key, TRANSACTOR)?;

    // Validate current issue date
    let valid_from = payload.get_valid_from();
    let valid_to = payload.get_valid_to();
    if valid_to < valid_from {
        return Err(ApplyError::InvalidTransaction(
            "Invalid dates. Valid to must be after valid from".to_string(),
        ));
    }

    let (factory_id, standard_id) = match payload.get_source() {
        proto::payload::IssueCertificateAction_Source::FROM_REQUEST => {
            let request = match state.get_request(payload.get_request_id())? {
                Some(request) => Ok(request),
                None => Err(ApplyError::InvalidTransaction(format!(
                    "Request does not exist: {}",
                    payload.get_request_id()
                ))),
            }?;

            if request.get_status() != proto::request::Request_Status::IN_PROGRESS {
                return Err(ApplyError::InvalidTransaction(format!(
          "The request with id {} has its status set to {:?}. Only requests with status set to IN_PROGRESS can be certified.",
          request.get_id(),
          request.get_status()
        )));
            }

            // update status of request
            let mut updated_request = request.clone();
            updated_request.set_status(proto::request::Request_Status::CERTIFIED);
            state.set_request(payload.get_request_id(), updated_request)?;

            Ok((
                request.get_factory_id().to_string(),
                request.get_standard_id().to_string(),
            ))
        }
        proto::payload::IssueCertificateAction_Source::INDEPENDENT => {
            organization::get(state, &payload.get_factory_id())?;
            Ok((
                payload.get_factory_id().to_string(),
                payload.get_standard_id().to_string(),
            ))
        }
        proto::payload::IssueCertificateAction_Source::UNSET_SOURCE => {
            Err(ApplyError::InvalidTransaction(String::from(
                "Issue Certificate source must be set. It can be
        FROM_REQUEST if the there is an request associated with the
        action, or INDEPENDENT if there is not request associated.",
            )))
        }
    }?;

    // Get standard version from organization's cert_body_details
    let certifying_body_details = org.get_certifying_body_details();
    let accreditations = certifying_body_details.get_accreditations().to_vec();
    if accreditations
        .iter()
        .find(|accreditation| accreditation.get_standard_id() == standard_id)
        .is_none()
    {
        return Err(ApplyError::InvalidTransaction(format!(
            "Certifying body is not accredited for Standard {}",
            standard_id
        )));
    }
    let latest_standard_version = accreditations.last().unwrap();

    // Create certificate
    let mut new_certificate = proto::certificate::Certificate::new();
    new_certificate.set_id(payload.get_id().to_string());
    new_certificate.set_certifying_body_id(agt.get_organization_id().to_string());
    new_certificate.set_factory_id(factory_id);
    new_certificate.set_standard_id(standard_id);
    new_certificate
        .set_standard_version(latest_standard_version.get_standard_version().to_string());
    new_certificate.set_certificate_data(::protobuf::RepeatedField::from_vec(
        payload.get_certificate_data().to_vec(),
    ));
    new_certificate.set_valid_from(valid_from);
    new_certificate.set_valid_to(valid_to);

    // Put certificate in state
    state.set_certificate(payload.get_id(), new_certificate)?;

    Ok(())
}

pub fn make_proto(
    payload: &proto::payload::IssueCertificateAction,
    certifying_body_id: &str,
    standard_version: &str,
) -> proto::certificate::Certificate {
    // Create certificate
    let mut new_certificate = proto::certificate::Certificate::new();
    new_certificate.set_id(payload.get_id().to_string());
    new_certificate.set_certifying_body_id(certifying_body_id.to_string());
    new_certificate.set_factory_id(payload.get_factory_id().to_string());
    new_certificate.set_standard_id(payload.get_standard_id().to_string());
    new_certificate.set_standard_version(standard_version.to_string());
    new_certificate.set_certificate_data(::protobuf::RepeatedField::from_vec(
        payload.get_certificate_data().to_vec(),
    ));
    new_certificate.set_valid_from(payload.get_valid_from());
    new_certificate.set_valid_to(payload.get_valid_to());

    new_certificate
}
