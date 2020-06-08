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

pub fn create(
    payload: &proto::payload::CreateStandardAction,
    state: &mut ConsensourceState,
    signer_public_key: &str,
) -> Result<(), ApplyError> {
    // Verify that name is not already associated with a Standard object
    match state.get_standard(&payload.standard_id) {
        Ok(Some(_)) => Err(ApplyError::InvalidTransaction(format!(
            "Standard already exists: {}",
            payload.name
        ))),
        Ok(None) => Ok(()),
        Err(err) => Err(err),
    }?;

    // Validate signer public key and agent
    let agt = agent::get(state, signer_public_key)?;

    agent::has_organization(&agt)?;

    // Validate org existence
    let org = organization::get(state, agt.get_organization_id())?;

    organization::check_type(&org, proto::organization::Organization_Type::STANDARDS_BODY)?;

    // Validate agent is authorized
    organization::check_authorization(&org, signer_public_key, TRANSACTOR)?;

    let new_standard = make_proto(payload, &org.get_id());

    // Put new standard in state
    state.set_standard(&payload.standard_id, new_standard)?;

    Ok(())
}

pub fn update(
    payload: &proto::payload::UpdateStandardAction,
    state: &mut ConsensourceState,
    signer_public_key: &str,
) -> Result<(), ApplyError> {
    // Verify that name is not already associated with a Standard object
    let mut standard = match state.get_standard(&payload.standard_id)? {
        Some(standard) => Ok(standard),
        None => Err(ApplyError::InvalidTransaction(format!(
            "Standard {} does not exist",
            payload.standard_id
        ))),
    }?;

    let mut versions = standard.get_versions().to_vec();

    if versions
        .iter()
        .any(|version| version.version == payload.version)
    {
        return Err(ApplyError::InvalidTransaction(format!(
            "Version already exists. Version {}",
            payload.version
        )));
    }

    // Validate signer public key and agent
    let agt = agent::get(state, signer_public_key)?;

    agent::has_organization(&agt)?;

    // Validate org existence
    let org = organization::get(state, agt.get_organization_id())?;

    organization::check_type(&org, proto::organization::Organization_Type::STANDARDS_BODY)?;

    // Validate agent is authorized
    organization::check_authorization(&org, signer_public_key, TRANSACTOR)?;

    // Validade standard was created by agent's organizatio
    if agt.get_organization_id() != standard.get_organization_id() {
        return Err(ApplyError::InvalidTransaction(format!(
            "Organization {} did not create the certification standard {}",
            org.get_name(),
            standard.get_name()
        )));
    }

    let mut new_standard_version = proto::standard::Standard_StandardVersion::new();
    new_standard_version.set_version(payload.version.clone());
    new_standard_version.set_description(payload.description.clone());
    new_standard_version.set_link(payload.link.clone());
    new_standard_version.set_approval_date(payload.approval_date.clone());

    versions.push(new_standard_version);

    standard.set_versions(protobuf::RepeatedField::from_vec(versions));

    // Put updated standard in state
    state.set_standard(&standard.id.clone(), standard)?;

    Ok(())
}

pub fn accredit_certifying_body(
    payload: &proto::payload::AccreditCertifyingBodyAction,
    state: &mut ConsensourceState,
    signer_public_key: &str,
) -> Result<(), ApplyError> {
    // Verify the signer
    let agt = agent::get(state, signer_public_key)?;

    // Verify the signer is associated with a Standards Body
    agent::has_organization(&agt)?;

    let agent_organization = organization::get(state, agt.get_organization_id())?;

    organization::check_type(
        &agent_organization,
        proto::organization::Organization_Type::STANDARDS_BODY,
    )?;

    // Verify the signer is an authorized transactor within their organization
    organization::check_authorization(&agent_organization, signer_public_key, TRANSACTOR)?;

    // Verify the certifying_body_id is associated with a Certifying body
    let mut certifying_body = organization::get(state, payload.get_certifying_body_id())?;

    organization::check_type(
        &certifying_body,
        proto::organization::Organization_Type::CERTIFYING_BODY,
    )?;

    // Verify the name is associated with an existing standard
    let standard = match state.get_standard(&payload.get_standard_id()) {
        Ok(Some(standard)) => Ok(standard),
        Ok(None) => Err(ApplyError::InvalidTransaction(format!(
            "No standard with ID {} exists",
            payload.get_standard_id()
        ))),
        Err(err) => Err(err),
    }?;

    // Verify the agent's organization created the standard
    if agt.get_organization_id() != standard.get_organization_id() {
        return Err(ApplyError::InvalidTransaction(format!(
            "Signer's associated organization did not create the certification standard {}",
            standard.get_name()
        )));
    }

    let mut certifying_body_details = certifying_body.get_certifying_body_details().clone();

    let mut accreditations = certifying_body_details.get_accreditations().to_vec();

    let standard_versions = standard.get_versions().to_vec();
    let latest_standard_version = match standard_versions.last() {
        Some(valid_version) => valid_version,
        None => {
            return Err(ApplyError::InvalidTransaction(format!(
                "Invalid version for Standard {}",
                standard.get_id()
            )));
        }
    };

    let standard_compare =
        |accreditation: &proto::organization::CertifyingBody_Accreditation| -> bool {
            accreditation.get_standard_id() == payload.get_standard_id()
                && accreditation.get_standard_version() == latest_standard_version.get_version()
        };

    if accreditations.iter().any(standard_compare) {
        return Err(ApplyError::InvalidTransaction(format!(
            "Accreditation for Standard {}, version {} already exists",
            payload.get_standard_id(),
            latest_standard_version.get_version().to_string(),
        )));
    }

    // Verify the date
    let valid_from = payload.get_valid_from();
    if valid_from < latest_standard_version.get_approval_date() {
        return Err(ApplyError::InvalidTransaction(
            "Invalid date, Standard is not valid from this date".to_string(),
        ));
    }

    let valid_to = payload.get_valid_to();
    if valid_to < valid_from {
        return Err(ApplyError::InvalidTransaction(
            "Invalid dates. Valid to must be after valid from".to_string(),
        ));
    }

    let mut new_accreditation = proto::organization::CertifyingBody_Accreditation::new();
    new_accreditation.set_standard_id(payload.get_standard_id().to_string());
    new_accreditation.set_standard_version(latest_standard_version.get_version().to_string());
    new_accreditation.set_accreditor_id(agent_organization.get_id().to_string());
    new_accreditation.set_valid_to(payload.get_valid_to());
    new_accreditation.set_valid_from(payload.get_valid_from());

    accreditations.push(new_accreditation);
    certifying_body_details.set_accreditations(protobuf::RepeatedField::from_vec(accreditations));

    certifying_body.set_certifying_body_details(certifying_body_details);

    // Put updated CertifyingBody in state
    state.set_organization(payload.get_certifying_body_id(), certifying_body)?;

    Ok(())
}

pub fn make_proto(
    payload: &proto::payload::CreateStandardAction,
    org_id: &str,
) -> proto::standard::Standard {
    let mut new_standard_version = proto::standard::Standard_StandardVersion::new();
    new_standard_version.set_version(payload.version.clone());
    new_standard_version.set_description(payload.description.clone());
    new_standard_version.set_link(payload.link.clone());
    new_standard_version.set_approval_date(payload.approval_date.clone());

    let mut new_standard = proto::standard::Standard::new();
    new_standard.set_id(payload.standard_id.clone());
    new_standard.set_name(payload.name.clone());
    new_standard.set_organization_id(org_id.to_string());
    new_standard.set_versions(protobuf::RepeatedField::from_vec(vec![
        new_standard_version,
    ]));
    new_standard
}
