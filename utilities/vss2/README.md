# VSS - Treasury Validation Services API
This repository is for the collaborative development of a REST API for validating X509 certificates.  The primary use of the API is to validate certificates within the Federal PKI.  

This repository in GSA is sponsored by the GSA Office of Government wide Policy and Federal ICAM / Federal PKI Policy Authority.  This repository is currently Private for government.  This repository will be cleaned and migrated to Public and fully government contributed Open Source after the removal of some vendor proprietary library dependencies, and migration to an open source dependency (outlined in Roadmap). 

## Roadmap
The expected roadmap for this code:

December 2016 - February 2017  
- Deployments to Development, Acceptance, and Production environments within Treasury
- Performance Enhancements & Documentation
- Migration to [Open Source SCVP API](https://github.com/grandamp/SCVPAPI/)
- Migration to a public repository

February 2017 and on
- GET operations on /vss/rest endpoint, allowing retrieval of cached validations
- Incorporation of a noSQL repository or cache

## Current Deployments

Each deployment can be independently tested, or developed against, by visiting the services at their respective locations.

- [Development: vssapi-dev.treasury.gov](https://vssapi-dev.treasury.gov/)
- [Acceptance:  vssapi-acc.treasury.gov](https://vssapi-acc.treasury.gov/)
- [Production:  vssapi.treasury.gov](https://vssapi.treasury.gov/)

The service is only available via TLS 1.2, and the certificates for services are issued from the Treasury PKI.  Details are documented within the Treasury SCVP Profile, in section 4.5.

## How to Contribute
The source repository exists [here](https://github.com/GSA/vss/).

### Public domain

This project is in the worldwide [public domain](LICENSE.md).

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.
