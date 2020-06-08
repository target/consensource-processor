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
