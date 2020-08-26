pub mod agent;
pub mod assertion;
pub mod certificate;
pub mod factory;
pub mod organization;
pub mod standard;
pub mod test_utils;

/*
 * ConsensourceTransactionHandler
 */
cfg_if! {
  if #[cfg(target_arch = "wasm32")] {
    use sabre_sdk::ApplyError;
    use sabre_sdk::TransactionContext;
    use sabre_sdk::TransactionHandler;
    use sabre_sdk::TpProcessRequest;
    use sabre_sdk::{WasmPtr, execute_entrypoint};
  } else {
    use sawtooth_sdk::messages::processor::TpProcessRequest;
    use sawtooth_sdk::processor::handler::ApplyError;
    use sawtooth_sdk::processor::handler::TransactionContext;
    use sawtooth_sdk::processor::handler::TransactionHandler;
  }
}

use common::addressing;
use payload::{Action, CertPayload};
use state::ConsensourceState;

pub struct ConsensourceTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl ConsensourceTransactionHandler {
    pub fn new() -> ConsensourceTransactionHandler {
        ConsensourceTransactionHandler {
            family_name: addressing::FAMILY_NAMESPACE.to_string(),
            family_versions: vec![addressing::FAMILY_VERSION.to_string()],
            namespaces: vec![addressing::get_family_namespace_prefix()],
        }
    }
}

impl TransactionHandler for ConsensourceTransactionHandler {
    fn family_name(&self) -> String {
        self.family_name.clone()
    }

    fn family_versions(&self) -> Vec<String> {
        self.family_versions.clone()
    }

    fn namespaces(&self) -> Vec<String> {
        self.namespaces.clone()
    }

    /// Applies the correct transaction logic depending on the payload action type.
    /// It will use helper methods to perform all payload validation that requires
    /// fetching data from state. If the payload is valid it will apply the changes
    /// to state.
    ///
    /// ```
    /// # Errors
    /// Returns an error if the transaction fails
    /// ```
    fn apply(
        &self,
        request: &TpProcessRequest,
        context: &mut dyn TransactionContext,
    ) -> Result<(), ApplyError> {
        let header = request.get_header();
        let signer_public_key = header.get_signer_public_key();

        // Return an action enum as the payload
        let payload = CertPayload::new(request.get_payload())?;
        let mut state = ConsensourceState::new(context);

        match payload.get_action() {
            Action::CreateAgent(payload) => agent::create(&payload, &mut state, signer_public_key),
            Action::CreateOrganization(payload) => {
                organization::create(&payload, &mut state, signer_public_key)
            }
            Action::UpdateOrganization(payload) => {
                organization::update(&payload, &mut state, signer_public_key)
            }
            Action::AuthorizeAgent(payload) => {
                agent::authorize(&payload, &mut state, signer_public_key)
            }
            Action::IssueCertificate(payload) => {
                certificate::issue(&payload, &mut state, signer_public_key)
            }
            Action::CreateStandard(payload) => {
                standard::create(&payload, &mut state, signer_public_key)
            }
            Action::UpdateStandard(payload) => {
                standard::update(&payload, &mut state, signer_public_key)
            }
            Action::OpenRequest(payload) => {
                factory::open_request(&payload, &mut state, signer_public_key)
            }
            Action::ChangeRequestStatus(payload) => {
                factory::change_request_status(&payload, &mut state, signer_public_key)
            }
            Action::AccreditCertifyingBody(payload) => {
                standard::accredit_certifying_body(&payload, &mut state, signer_public_key)
            }
            Action::CreateAssertion(payload) => {
                assertion::create(&payload, &mut state, signer_public_key)
            }
            Action::TransferAssertion(payload) => {
                assertion::transfer(&payload, &mut state, signer_public_key)
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]

// If the TP will be compiled to WASM to be run as a smart contract in Sabre this apply method will be
// used as wrapper for the handler apply method. For Sabre the apply must return a boolean
fn apply(
    request: &TpProcessRequest,
    context: &mut dyn TransactionContext,
) -> Result<bool, ApplyError> {
    let handler = ConsensourceTransactionHandler::new();
    match handler.apply(request, context) {
        Ok(_) => Ok(true),
        Err(err) => Err(err),
    }
}

#[allow(dead_code)]
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe fn entrypoint(payload: WasmPtr, signer: WasmPtr, signature: WasmPtr) -> i32 {
    execute_entrypoint(payload, signer, signature, apply)
}
