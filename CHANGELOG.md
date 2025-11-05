# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1](https://github.com/PodioSpaz/ami-copier/compare/v0.3.0...v0.3.1) (2025-11-05)


### Bug Fixes

* use tag-based deduplication to prevent duplicate AMI copies ([6d5c665](https://github.com/PodioSpaz/ami-copier/commit/6d5c665a4f5f719cc076a8ea127d542848f42b8a))
* use tag-based deduplication to prevent duplicate AMI copies ([fbf204e](https://github.com/PodioSpaz/ami-copier/commit/fbf204e14caf7884bcdd310539373b22e7fd1577))

## [0.3.0](https://github.com/PodioSpaz/ami-copier/compare/v0.2.2...v0.3.0) (2025-11-05)


### Features

* add ami_name_tag_template for customizable Name tags ([e097cf8](https://github.com/PodioSpaz/ami-copier/commit/e097cf864bfb9601b7b01399ec48a9e3417daf4e))
* add ami_name_tag_template variable for customizable Name tags ([4cba5bf](https://github.com/PodioSpaz/ami-copier/commit/4cba5bf1381c69204ff8aea08e0765ca5e64b97b))


### Documentation

* document ami_name_tag_template variable ([100c48f](https://github.com/PodioSpaz/ami-copier/commit/100c48fc85cb20aa64dbb4d039a5a668fec8d561))

## [0.2.2](https://github.com/PodioSpaz/ami-copier/compare/v0.2.1...v0.2.2) (2025-11-04)


### Bug Fixes

* remove Encrypted flag from block device mappings during re-registration ([f3cf5b8](https://github.com/PodioSpaz/ami-copier/commit/f3cf5b8e9a6c35a0f84a41c598c6e7524bcb0fdf))
* remove Encrypted flag from block device mappings during re-registration ([1964d14](https://github.com/PodioSpaz/ami-copier/commit/1964d145345ef6598d665396e831cce924e0cc80))

## [0.2.1](https://github.com/PodioSpaz/ami-copier/compare/v0.2.0...v0.2.1) (2025-11-04)


### Bug Fixes

* implement two-step AMI copy process to support gp3 conversion ([8f6306f](https://github.com/PodioSpaz/ami-copier/commit/8f6306f428805fdb2709c226b8a5e1c2d7256ac5))
* implement two-step AMI copy process to support gp3 conversion ([afeec48](https://github.com/PodioSpaz/ami-copier/commit/afeec48528b320d49738fafc48b37624eba9d284))

## [0.2.0](https://github.com/PodioSpaz/ami-copier/compare/v0.1.5...v0.2.0) (2025-11-03)


### Features

* add support for existing Secrets Manager secrets and SSM parameters ([254b34a](https://github.com/PodioSpaz/ami-copier/commit/254b34aeb03d91c26a9f3a1bc8da4bf8ae63aedb))
* support for existing Secrets Manager secrets and SSM parameters ([d11c7ad](https://github.com/PodioSpaz/ami-copier/commit/d11c7ad4bb2c0653596f2975cff61d51ed7ef0d0))


### Bug Fixes

* update outputs.tf to use locals for credential resources ([2b89839](https://github.com/PodioSpaz/ami-copier/commit/2b8983950dfa1e8316682b6959c461dd3543693b))

## [0.1.5](https://github.com/PodioSpaz/ami-copier/compare/v0.1.4...v0.1.5) (2025-10-31)


### Documentation

* add comprehensive Mermaid architecture diagram ([037dbb5](https://github.com/PodioSpaz/ami-copier/commit/037dbb57c6a21ae4cf5a30da4ca7599242fcbb22))
* add Mermaid architecture diagrams to README ([db957fc](https://github.com/PodioSpaz/ami-copier/commit/db957fc9131c9fd89e48059aba8de433467bc0c2))
* improve diagram layout for better readability ([924fd13](https://github.com/PodioSpaz/ami-copier/commit/924fd13ae043faa96529ef30e8d9a5a9b0741953))

## [0.1.4](https://github.com/PodioSpaz/ami-copier/compare/v0.1.3...v0.1.4) (2025-10-30)


### Bug Fixes

* replace event-driven architecture with scheduled polling ([6369c47](https://github.com/PodioSpaz/ami-copier/commit/6369c4795194a39d02321173f315b95486f1e6d1))
* replace event-driven architecture with scheduled polling ([5ae5811](https://github.com/PodioSpaz/ami-copier/commit/5ae5811471d269c0dd5cbbcab532c30253e2b914))

## [0.1.3](https://github.com/PodioSpaz/ami-copier/compare/v0.1.2...v0.1.3) (2025-10-26)


### Documentation

* remove duplicate 0.1.1 changelog entry ([1e232bf](https://github.com/PodioSpaz/ami-copier/commit/1e232bf541831a3f2d88d02d2761f9ef9ac4a86a))

## [0.1.2](https://github.com/PodioSpaz/ami-copier/compare/v0.1.0...v0.1.2) (2025-10-26)


### Documentation

* clarify license statement in README ([25f88ec](https://github.com/PodioSpaz/ami-copier/commit/25f88ec790606f48ebcfb8e291ac82fb64146f3f))
* update version references from v1.0.0 to v0.1.0 ([0536d1d](https://github.com/PodioSpaz/ami-copier/commit/0536d1d1d275bcdbdffa27b210c1ea64eb731cb2))

## [Unreleased]
