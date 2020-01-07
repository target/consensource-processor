# ConsenSource Transaction Processor [![Build Status](https://travis-ci.org/target/consensource-processor.svg?branch=master)](https://travis-ci.org/target/consensource-processor) [![Coverage Status](https://img.shields.io/coveralls/github/target/consensource-processor)](https://coveralls.io/github/target/consensource-processor?branch=master)

The transaction processor contains the business logic for ConsenSource's certificate registry [transaction family](https://sawtooth.hyperledger.org/docs/core/releases/latest/app_developers_guide/overview.html). It implements the [Sawtooth processor class](https://sawtooth.hyperledger.org/docs/core/releases/latest/_autogen/sdk_TP_tutorial_js.html) allowing developers to write out application-specific code for handling certificate registry transactions (or really any family of transactions).

For more information, please read through the [Transaction Processor & Families](https://target.github.io/consensource-docs/docs/developer/application-developers-guide/tp/transaction-processor-and-famlies/) docs.

## Transactions

### CreateAgentAction

The `CreateAgentAction` transaction creates an agent object that is able to sign transactions and perform actions on the behalf of their associated organization. This agent object will be initialized with no associated organization ID.

[CreateAgentAction protobuf](https://github.com/target/consensource-common/blob/master/protos/payload.proto##L40-L47)
```protobuf
message CreateAgentAction {
    // A name identifying the agent.
    string name = 1;

    // Approximately when the agent was registered.
    // Format: UTC timestamp
    uint64 timestamp = 2;
}
```
This transaction is considered invalid if one of the following occurs:
 - Name is not provided
 - Signing public key already associated with an agent


### CreateOrganizationAction

The `CreateOrganizationAction` transaction creates an organization object. An organization may either be an STANDARDS_BODY, CERTIFYING_BODY or a FACTORY depending on the actions the organization will perform, such as creating standards, issuing or requesting certificates. These actions are performed by authorized agents associated with the organization. The organization object created will be initialized with the agent that signed the transaction as an ADMIN within the organization's authorizations list.

[CreateOrganizationAction protobuf](https://github.com/target/consensource-common/blob/master/protos/payload.proto##L49-L64)
```protobuf
message CreateOrganizationAction {
    // UUID of the organization.
    string id = 1;

    // Type of the organization.
    Organization.Type organization_type = 2;

    // Name of the organization.
    string name = 3;

    // Initial contact info for the organization.
    repeated Organization.Contact contacts = 4;

    // Address of the organization (if the organization is a Factory).
    Factory.Address address = 5;
}
```
This transaction will be considered invalid if one of the following occurs:
 - Organization ID, name, and/or organization type are not provided
 - Organization ID already exists
 - Signing public key is not associated with a valid Agent object
 - Agent submitting the transaction already has an associated organization
 - Address is provided if the type is Standards Body or Certifying Body
 - Address is not provided if the type is Factory


### UpdateOrganizationAction

The `UpdateOrganizationAction` transaction modifies the value of an Organization in state. Both the address (for factories) and the contact information may be updated. The values provided will be applied exactly as submitted with the transaction. If one or the other should stay the same, the original values should be supplied.

[UpdateOrganizationAction protobuf](https://github.com/target/consensource-common/blob/master/protos/payload.proto##L66-L72)
```protobuf
message UpdateOrganizationAction {
    // Updated contact info.
    repeated Organization.Contact contacts = 1;

    // Updated address (if Factory).
    Factory.Address address = 2;
}
```
This transaction is considered invalid if one of the following occurs:
 - The signer of the transaction is not listed as an admin of their organization
 - Provided contacts or address objects are not fully filled out
 - Address is provided if the organization is not a factory


### AuthorizeAgentAction

The `AuthorizeAgentAction` transaction creates an entry within an organization's authorizations list for the specified public key with the specified role. This action may only be performed by an agent authorized as an ADMIN by their associated organization.

[AuthorizeAgentAction protobuf](https://github.com/target/consensource-common/blob/master/protos/payload.proto##L74-L83)
```protobuf
message AuthorizeAgentAction {
    // Public key associated with the agent.
    string public_key = 1;

    // Role to update the specified agent entry.
    // Roles grant permissions for an agent to act on behalf of the
    // organization.
    // Whether the agent is an ADMIN or ISSUER.
    Organization.Authorization.Role role = 2;
}
```
This transaction is considered invalid if one of the following occurs:
 - Public key is not provided
 - Role is not provided
 - Signing public key is not associated an Agent
 - Public key provided is not associated an Agent
 - Agent submitting the transaction is not authorized as an ADMIN within their associated organization
 - Public key provided specifies an Agent already associated with an organization
 - Invalid authorization role is provided


### IssueCertificateAction

The `IssueCertificateAction` transaction creates a certificate object that contains information pertaining to the specified factory and their adherence to certain policies. A Certificate object is created by an agent associated with a certifying body.

[IssueCertificateAction protobuf](https://github.com/target/consensource-common/blob/master/protos/payload.proto##L85-L121)
```protobuf
message IssueCertificateAction {
    enum Source {
        UNSET_SOURCE = 0;
        FROM_REQUEST = 1;
        INDEPENDENT= 2;
    }

    // UUID of the certificate.
    string id = 1;

    // ID of the factory that the certificate is being issued to.
    string factory_id = 2;

    // The source that triggered the IssueCertificate Trasaction.
    // If set to FROM_REQUEST, it means the IssueCertificateAction is associated
    // to a request made by a factory. The field request_id must be set.
    //  If set to INDEPENDENT, it means the IssueCertificateAction is not associated
    //  with a request made by a factory. The field factory_id and standard_id must be set.
    Source source = 3;

    // ID of the request (if source is FROM_REQUEST)
    string request_id = 4;

    // Standard that this certificate is for.
    string standard_id = 5;

    // Additional certificate data.
    repeated Certificate.CertificateData certificate_data = 6;

    // Time certificate was issued.
    // Format: UTC timestamp
    uint64 valid_from = 7;

    // Approximately when the certificate will become invalid.
    // Format: UTC timestamp
    uint64 valid_to = 8;
}
```
This transaction is considered invalid if one of the following occurs:
 - ID, factory ID, standard name, valid from timestamp and/or valid to timestamp are not provided
 - Certificate ID is already associated with a Certificate object
 - Factory ID does not reference a valid factory
 - Signing public key is not associated with an agent
 - Agent submitting the transaction is not associated with a certifying body
 - Certifying Body associated with the issuing agent is not accredited to issue the standard
 - Agent submitting the transaction is not an authorized TRANSACTOR within their associated organization
 - Standard name is not associated with an existing standard
 - Invalid dates are provided, pertaining to current date as well as format


### CreateStandardAction

The `CreateStandardAction` transaction creates a new certification standard in state. It will also create a StandardVersion sub-object, which contains details specific to the version of the standard which was supplied. A CreateStandardAction transaction is submitted by an agent associated with a standards body.

[CreateStandardAction protobuf](https://github.com/target/consensource-common/blob/master/protos/payload.proto##L143-162)
```protobuf
message CreateStandardAction {
    // Sha256 of the standard name
    string standard_id = 1;

    // Name of the standard.
    string name = 2;

    // Current version of the standard.
    string version = 3;

    // Short description of the standard.
    string description = 4;

    // Link to the standard's documentation.
    string link = 5;

    // Date the standard is officially issued.
    uint64 approval_date = 6;

}
```
This transaction is considered invalid if one of the following occurs:
 - The standard_id, name, version, description, link, or approval date are not provided
 - The standard_id is already associated with an existing standard
 - The signer is not associated with a standards body
 - The signer is not authorized as a transactor within their organization


### UpdateStandardAction

The `UpdateStandardAction` transaction creates a new standard version in state, under the associated standard object. An UpdateStandardAction transaction is submitted by an agent associated with a standards body.

[UpdateStandardAction protobuf](https://github.com/target/consensource-common/blob/master/protos/payload.proto##L164-L179)
```protobuf
message UpdateStandardAction {
    // Standard that is being updated.
    string standard_id = 1;

    // New version of the standard.
    string version = 2;

    // Short description of the standard.
    string description = 3;

    // Link to the standard's documentation.
    string link = 4;

    // Date the standard is officially issued.
    uint64 approval_date = 5;
}
```
This transaction is considered invalid if one of the following occurs:
 - The standard_id, version, description, link, or approval date are not provided
 - The standard_id is not associated with an existing standard
 - The version is already associated with an existing standard version
 - The signer is not associated with a standards body
 - The signer is not authorized as a transactor within their organization
 - The standard is not associated with the signer's organization



### AccreditCertifyingBodyAction

The `AccreditCertifyingBodyAction` transaction adds an accreditation to a certifying body. An UpdateStandardAction transaction is submitted by an agent associated with a standards body.

[AccreditCertifyingBodyAction protobuf](https://github.com/target/consensource-common/blob/master/protos/payload.proto##L181-L195)
```protobuf
message AccreditCertifyingBodyAction {
    // UUID of the certifying body that is being accredited.
    string certifying_body_id = 1;

    // Standard that the certifying body is being accredited for.
    string standard_id = 2;

    // Time the accreditation was issued.
    // Format: UTC timestamp
    uint64 valid_from = 3;

    // When the accreditation will become invalid.
    // Format: UTC timestamp
    uint64 valid_to = 4;
}
```
This transaction is considered invalid if one of the following occurs:
 - The signer is not associated with a standards body
 - The signer is not authorized as a transactor within their organization
 - The certifying body ID is not associated with a certifying body
 - The name is not associated with an existing standard
 - Invalid dates are provided, pertaining to current date as well as format


### OpenRequestAction

The `OpenRequestAction` transaction opens a request for certification for a factory. This transaction is submitted by an agent associated with a factory and authorized as a TRANSACTOR for their associated factory.

[OpenRequestAction protobuf](https://github.com/target/consensource-common/blob/master/protos/payload.proto##L123-133)
```protobuf
message OpenRequestAction {
    // UUID of the request
    string request_id = 1;

    // Certification standard of which the factory is requesting from an certification body
    Request.Certification_Standard certification_standard = 2;

    // Name of the factory that is opening the request
    string factory_name = 3;

    // Time request was made
    // Format: UTC timestamp
    uint64 request_date = 4;
}
```
This transaction is considered invalid if one of the following occurs:
- The signer is not associated with a factory
- The signer is not authorized as a transactor within their organization
- The id is not unique
- The standards name is not associated with a valid standard
- If any of these fields are empty


### ChangeRequestStatusAction

The `ChangeRequestStatusAction` transaction is performed when a factory's certification request status is changed, such as to CLOSED, IN_PROGRESS, or CERTIFIED. This transaction results from either a factory changing the status to CLOSED or IN_PROGRESS, which would be submitted by an agent associated with the factory and authorized as a TRANSACTOR.

[ChangeRequestStatusAction protobuf](https://github.com/target/consensource-common/blob/master/protos/payload.proto##L135-141)
```protobuf
message ChangeRequestStatusAction {
    // Request for which the status is being changed.
    string request_id = 1;

    // New status of the request.
    Request.Status status = 2;
}
```
This transaction is considered invalid if one of the following occurs:
- The signer is not associated with a factory
- The signer is not authorized as a transactor within their organization
- A request with the provided id does not exist
- The status is not a valid status enum: IN_PROGRESS or CLOSED
- The status is already CLOSED or CERTIFIED
