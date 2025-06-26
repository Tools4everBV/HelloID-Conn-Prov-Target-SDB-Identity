# HelloID-Conn-Prov-Target-SDB-Identity

| :information_source: Information                                                                                                                                                                                                                                                                                                                                                       |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |
<br />
<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-SDBHR/blob/main/Logo.png?raw=true" alt="SDB Groep Logo">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-SDB-Identity](#helloid-conn-prov-target-sdb-identity)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Supported  features](#supported--features)
  - [Getting started](#getting-started)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
    - [Account Reference](#account-reference)
  - [Remarks](#remarks)
    - [Supported SCIM Attributes](#supported-scim-attributes)
      - [Supported User Fields](#supported-user-fields)
  - [Development resources](#development-resources)
    - [API endpoints](#api-endpoints)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [Getting help](#getting-help-1)
  - [HelloID docs](#helloid-docs)

## Introduction

- The _'HelloID-Conn-Prov-Target-SDB-Identity'_ connector is a target connector based on scim based API's. http://www.simplecloud.info.

- The SDB Identity Platform serves as the central hub for connecting and managing access to underlying applications. More information about the supported applications can be found in the [API documentation](#api-documentation)


## Supported  features

The following features are available:

| Feature                             | Supported | Actions                                 | Remarks           |
| ----------------------------------- | --------- | --------------------------------------- | ----------------- |
| **Account Lifecycle**               | ✅         | Create, Update, Enable, Disable        | There is no Delete action, the disable acts as a soft delete |
| **Permissions**                     | ✅         | Retrieve, Grant, Revoke                | Static or Dynamic |
| **Resources**                       | ❌         | -                                      |                   |
| **Entitlement Import: Accounts**    | ✅         | -                                      |                   |
| **Entitlement Import: Permissions** | ✅         | -                                      |                   |

## Getting started

### Connection settings

| Setting      | Description                                        |
| ------------ | -------------------------------------------------- |
| ClientID     | The ClientID for the SCIM API                      |
| ClientSecret | The ClientSecret for the SCIM API                  |
| Uri          | The Uri to the SCIM API. <http://some-api> |

### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _{connectorName}_ to a person in _HelloID_.

| Setting                   | Value                             |
| ------------------------- | --------------------------------- |
| Enable correlation        | `True`                            |
| Person correlation field  | `PersonContext.Person.ExternalId` |
| Account correlation field | `employeeNumber`                  |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

### Account Reference

The account reference is populated with the property `id` property from SDB-Identity

## Remarks
- The employee number may only contain numeric values and no letters.
- Usernames should consist of a single, continuous string without spaces.
- The User object returned by the API differs from the one used in the field mapping. As a result, the create, update, and import actions require duplicate mappings to ensure proper data handling.
  
### Supported SCIM Attributes

Not all SCIM attributes are supported; only the fields listed below are available for use.

#### Supported User Fields

- **Email**: The user's email address (only work email addresses are supported).
- **Username**: The user's username (must not include spaces).
- **Name**: The user's full name.
- **Active**: The user's activation status.
- **EmployeeNumber**: The user's employee number (numeric values only).

## Development resources

### API endpoints

The following endpoints are used by the connector

| Endpoint | Description                                          |
| -------- | ---------------------------------------------------- |
| /Users   | Retrieve, Create and Update user information |
| /Groups  | Retrieve group information, Add or Remove users      |

### API documentation

[SDB-Identity Documentation](https://support.sdbgroep.nl/portal/nl/kb/articles/sdb-identity-identity-access-management-iam#Wat_is_Identity_Access_Management_IAM)

## Getting help

> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012557600-Configure-a-custom-PowerShell-source-system) pages_

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
