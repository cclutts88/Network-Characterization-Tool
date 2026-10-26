BEGIN TRANSACTION;
CREATE TABLE analyst_achievements (
                owner TEXT NOT NULL,
                achievement_id TEXT NOT NULL,
                context_json TEXT NOT NULL DEFAULT '{}',
                unlocked_at TEXT NOT NULL,
                PRIMARY KEY(owner, achievement_id)
            );
CREATE TABLE analyst_auth_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                changed_at TEXT NOT NULL
            );
CREATE TABLE analyst_filter_presets (
                preset_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                page TEXT NOT NULL,
                name TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(owner, page, name)
            );
CREATE TABLE analyst_host_identities (
                   ip TEXT PRIMARY KEY,
                   hostname TEXT NOT NULL,
                   source_filename TEXT NOT NULL,
                   imported_by TEXT NOT NULL,
                   imported_at TEXT NOT NULL,
                   selection_source TEXT NOT NULL DEFAULT 'operator_import',
                   version INTEGER NOT NULL DEFAULT 1
               );
CREATE TABLE analyst_investigation_note_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                note_id TEXT NOT NULL,
                owner TEXT NOT NULL,
                action TEXT NOT NULL,
                version INTEGER NOT NULL,
                actor TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT ''
            );
CREATE TABLE analyst_investigation_notes (
                note_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                parent_id TEXT,
                kind TEXT NOT NULL CHECK(kind IN ('folder', 'note')),
                title TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                context_json TEXT NOT NULL DEFAULT '{}',
                position INTEGER NOT NULL DEFAULT 0,
                version INTEGER NOT NULL DEFAULT 1,
                visibility TEXT NOT NULL DEFAULT 'personal'
                    CHECK(visibility IN ('personal', 'shared')),
                shared_page TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
CREATE TABLE analyst_scan_drafts (
                    owner TEXT PRIMARY KEY,
                    snapshot_json TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
CREATE TABLE analyst_sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(username) REFERENCES analyst_users(username)
            );
CREATE TABLE analyst_shell_preferences (
                owner TEXT PRIMARY KEY,
                snapshot_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );
CREATE TABLE analyst_users (
                username TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                disabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL
            );
CREATE TABLE analyst_view_preferences (
                owner TEXT NOT NULL,
                page TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(owner, page)
            );
CREATE TABLE analyst_workspace_layout_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                layout_id TEXT NOT NULL,
                owner TEXT NOT NULL,
                action TEXT NOT NULL,
                version INTEGER NOT NULL,
                actor TEXT NOT NULL,
                changed_at TEXT NOT NULL
            );
CREATE TABLE analyst_workspace_layouts (
                layout_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                version INTEGER NOT NULL,
                visibility TEXT NOT NULL DEFAULT 'personal',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(owner, name)
            );
CREATE TABLE analyst_workspace_preferences (
                owner TEXT PRIMARY KEY,
                default_layout_id TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
CREATE TABLE app_settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL
                );
CREATE TABLE artifact_backfill (source_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, sha256 TEXT NOT NULL);
CREATE TABLE artifact_compaction_journal (
                compaction_id TEXT NOT NULL,
                item_id TEXT PRIMARY KEY,
                source_path TEXT NOT NULL,
                canonical_path TEXT NOT NULL,
                recovery_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                source_fingerprint_json TEXT NOT NULL,
                canonical_fingerprint_json TEXT NOT NULL,
                state TEXT NOT NULL,
                detail TEXT,
                updated_at TEXT NOT NULL
            );
CREATE TABLE artifact_observation_scope_contexts (
                observation_id TEXT PRIMARY KEY REFERENCES artifact_observations(observation_id) ON DELETE CASCADE,
                run_id TEXT NOT NULL REFERENCES scan_run_scope_contexts(run_id) ON DELETE CASCADE,
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                scope_label TEXT NOT NULL,
                scope_version INTEGER NOT NULL CHECK(scope_version >= 1),
                recorded_at TEXT NOT NULL
            );
CREATE TABLE artifact_observations (
                    observation_id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    source_ref TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    original_filename TEXT,
                    actor TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (sha256) REFERENCES artifact_registry(sha256)
                        ON DELETE CASCADE
                );
CREATE TABLE artifact_registry (
                    sha256 TEXT PRIMARY KEY,
                    size_bytes INTEGER NOT NULL,
                    media_type TEXT NOT NULL DEFAULT 'application/octet-stream',
                    canonical_path TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL
                );
CREATE TABLE artifact_scope_assignments (
                assignment_id TEXT PRIMARY KEY,
                artifact_observation_id TEXT NOT NULL
                    REFERENCES artifact_observations(observation_id),
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                revision INTEGER NOT NULL CHECK(revision >= 1),
                event_kind TEXT NOT NULL CHECK(event_kind IN ('assigned', 'corrected')),
                supersedes_assignment_id TEXT UNIQUE
                    REFERENCES artifact_scope_assignments(assignment_id),
                assignment_mode TEXT NOT NULL DEFAULT 'whole_artifact'
                    CHECK(assignment_mode = 'whole_artifact'),
                actor TEXT NOT NULL
                    CHECK(length(actor) BETWEEN 1 AND 100 AND actor = trim(actor)),
                reason TEXT NOT NULL
                    CHECK(length(reason) BETWEEN 1 AND 500 AND reason = trim(reason)),
                assigned_at TEXT NOT NULL CHECK(
                    length(assigned_at) = 25
                    AND substr(assigned_at, 11, 1) = 'T'
                    AND substr(assigned_at, 20, 6) = '+00:00'
                    AND datetime(assigned_at) IS NOT NULL
                ),
                UNIQUE(artifact_observation_id, revision)
            );
CREATE TABLE assessment_scope_assignment_links (
                assignment_id TEXT NOT NULL
                    REFERENCES artifact_scope_assignments(assignment_id),
                assessment_id TEXT NOT NULL REFERENCES entity_assessments(assessment_id),
                linked_at TEXT NOT NULL CHECK(
                    length(linked_at) = 25
                    AND substr(linked_at, 11, 1) = 'T'
                    AND substr(linked_at, 20, 6) = '+00:00'
                    AND datetime(linked_at) IS NOT NULL
                ),
                linked_by TEXT NOT NULL CHECK(
                    length(linked_by) BETWEEN 1 AND 100 AND linked_by = trim(linked_by)
                ),
                PRIMARY KEY(assignment_id, assessment_id)
            );
CREATE TABLE automated_nmap_scope_corrections (
                correction_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL UNIQUE REFERENCES scan_runs(run_id),
                observation_id TEXT NOT NULL UNIQUE
                    REFERENCES artifact_observations(observation_id),
                prior_intent_id TEXT NOT NULL UNIQUE
                    REFERENCES pipeline_admission_intents(intent_id),
                prior_intent_sha256 TEXT NOT NULL CHECK(length(prior_intent_sha256) = 64),
                corrected_contract_json TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                request_token TEXT NOT NULL UNIQUE,
                requested_at TEXT NOT NULL,
                assignment_id TEXT NOT NULL UNIQUE
                    REFERENCES artifact_scope_assignments(assignment_id),
                job_id TEXT NOT NULL UNIQUE REFERENCES pipeline_jobs(job_id)
            );
CREATE TABLE derived_result_inputs (
                result_id TEXT NOT NULL REFERENCES derived_results(result_id)
                    ON DELETE CASCADE,
                input_role TEXT NOT NULL,
                input_kind TEXT NOT NULL,
                input_identity TEXT NOT NULL,
                input_metadata_json TEXT NOT NULL,
                PRIMARY KEY(result_id, input_role)
            );
CREATE TABLE derived_result_observation_links (
                result_id TEXT NOT NULL,
                input_role TEXT NOT NULL,
                observation_id TEXT NOT NULL REFERENCES artifact_observations(observation_id)
                    ON DELETE CASCADE,
                linked_at TEXT NOT NULL,
                PRIMARY KEY(result_id, input_role, observation_id),
                FOREIGN KEY(result_id, input_role)
                    REFERENCES derived_result_inputs(result_id, input_role)
                    ON DELETE CASCADE
            );
CREATE TABLE derived_results (
                result_id TEXT PRIMARY KEY,
                computation_key TEXT NOT NULL UNIQUE,
                family TEXT NOT NULL,
                analysis_version TEXT NOT NULL,
                payload_schema_version INTEGER NOT NULL
                    CHECK(payload_schema_version >= 1),
                parameters_json TEXT NOT NULL,
                inputs_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                result_sha256 TEXT NOT NULL,
                generated_at TEXT NOT NULL
            );
CREATE TABLE device_analysis_cache (
                    run_id TEXT PRIMARY KEY,
                    analysis_version INTEGER NOT NULL,
                    evidence_fingerprint TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES device_collections(run_id) ON DELETE CASCADE
                );
CREATE TABLE device_collection_authority (
                run_id TEXT PRIMARY KEY,
                state TEXT NOT NULL CHECK(state IN ('preparing', 'active', 'deleted')),
                revision INTEGER NOT NULL CHECK(revision >= 1),
                artifact_observation_id TEXT
                    REFERENCES artifact_observations(observation_id) ON DELETE RESTRICT,
                artifact_sha256 TEXT,
                retained_filename TEXT,
                selection_contract TEXT,
                semantic_manifest_json TEXT,
                semantic_manifest_sha256 TEXT,
                created_at TEXT NOT NULL,
                activated_at TEXT,
                deleted_at TEXT,
                CHECK(
                    state != 'active' OR (
                        artifact_observation_id IS NOT NULL
                        AND artifact_sha256 IS NOT NULL
                        AND retained_filename IS NOT NULL
                        AND selection_contract IS NOT NULL
                        AND semantic_manifest_json IS NOT NULL
                        AND semantic_manifest_sha256 IS NOT NULL
                        AND activated_at IS NOT NULL
                    )
                ),
                CHECK(state != 'deleted' OR deleted_at IS NOT NULL)
            );
CREATE TABLE device_collection_authority_inputs (
                run_id TEXT NOT NULL REFERENCES device_collection_authority(run_id),
                input_role TEXT NOT NULL,
                position INTEGER NOT NULL CHECK(position >= 0),
                source_kind TEXT NOT NULL CHECK(
                    source_kind IN ('artifact_file', 'embedded_section', 'absent')
                ),
                identity TEXT NOT NULL,
                filename TEXT,
                artifact_observation_id TEXT
                    REFERENCES artifact_observations(observation_id) ON DELETE RESTRICT,
                artifact_sha256 TEXT,
                size_bytes INTEGER CHECK(size_bytes IS NULL OR size_bytes >= 0),
                metadata_json TEXT NOT NULL,
                PRIMARY KEY(run_id, input_role, position),
                CHECK(
                    source_kind != 'artifact_file' OR (
                        filename IS NOT NULL
                        AND artifact_observation_id IS NOT NULL
                        AND artifact_sha256 IS NOT NULL
                        AND size_bytes IS NOT NULL
                    )
                )
            );
CREATE TABLE device_collection_profile_roots (
                profile_id TEXT PRIMARY KEY,
                active_name TEXT NOT NULL,
                name_key TEXT NOT NULL,
                active_version INTEGER NOT NULL CHECK(active_version >= 1),
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                archived_at TEXT,
                archived_by TEXT
            );
CREATE TABLE device_collection_profile_versions (
                profile_id TEXT NOT NULL,
                version INTEGER NOT NULL CHECK(version >= 1),
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                settings_json TEXT NOT NULL,
                PRIMARY KEY(profile_id, version),
                FOREIGN KEY(profile_id) REFERENCES device_collection_profile_roots(profile_id)
            );
CREATE TABLE device_collections (
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT,
                    completed_at TEXT,
                    device_address TEXT,
                    device_name TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    status TEXT,
                    evidence_fingerprint TEXT NOT NULL
                );
CREATE TABLE device_command_observations (
                    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    line_number INTEGER,
                    command TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    label TEXT NOT NULL,
                    UNIQUE(run_id, position),
                    FOREIGN KEY (run_id) REFERENCES device_collections(run_id) ON DELETE CASCADE
                );
CREATE TABLE device_contact_attempts (
                run_id TEXT NOT NULL,
                attempt_number INTEGER NOT NULL CHECK(attempt_number >= 1),
                owner_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'preparing', 'contact_starting', 'contact_active',
                    'complete', 'cancelled', 'failed', 'abandoned',
                    'needs_attention'
                )),
                contact_phase TEXT NOT NULL CHECK(contact_phase IN (
                    'preparing', 'contact_starting', 'contact_active',
                    'contact_stopped', 'uncertain', 'complete'
                )),
                run_lease_key TEXT NOT NULL,
                run_lease_id TEXT NOT NULL,
                run_lease_epoch INTEGER NOT NULL CHECK(run_lease_epoch >= 1),
                capacity_lease_key TEXT NOT NULL,
                capacity_lease_id TEXT NOT NULL,
                capacity_lease_epoch INTEGER NOT NULL CHECK(capacity_lease_epoch >= 1),
                started_at TEXT NOT NULL,
                contact_started_at TEXT,
                contact_stopped_at TEXT,
                completed_at TEXT,
                status_reason TEXT,
                PRIMARY KEY(run_id, attempt_number),
                FOREIGN KEY(run_id) REFERENCES device_contact_runs(run_id)
                    ON DELETE RESTRICT
            );
CREATE TABLE device_contact_controls (
                control_id TEXT PRIMARY KEY CHECK(length(control_id) = 32),
                run_id TEXT NOT NULL,
                control_kind TEXT NOT NULL CHECK(control_kind IN (
                    'cancel_requested', 'admin_closed'
                )),
                requested_at TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES device_contact_runs(run_id)
                    ON DELETE RESTRICT
            );
CREATE TABLE device_contact_publications (
                publication_id TEXT PRIMARY KEY CHECK(length(publication_id) = 32),
                run_id TEXT NOT NULL,
                attempt_number INTEGER NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('prepared', 'files_moved', 'committed')),
                files_json TEXT NOT NULL,
                prepared_at TEXT NOT NULL,
                files_moved_at TEXT,
                committed_at TEXT,
                UNIQUE(run_id, attempt_number),
                FOREIGN KEY(run_id, attempt_number)
                    REFERENCES device_contact_attempts(run_id, attempt_number)
            );
CREATE TABLE device_contact_reviews (
                review_id TEXT PRIMARY KEY CHECK(length(review_id) = 32),
                run_id TEXT NOT NULL,
                attempt_number INTEGER NOT NULL,
                reviewed_at TEXT NOT NULL,
                reviewed_by TEXT NOT NULL,
                former_processes_stopped INTEGER NOT NULL CHECK(former_processes_stopped = 1),
                files_stable INTEGER NOT NULL CHECK(files_stable = 1),
                file_review_json TEXT NOT NULL,
                disposition TEXT NOT NULL CHECK(disposition IN ('cancelled', 'failed')),
                reason TEXT NOT NULL,
                FOREIGN KEY(run_id, attempt_number)
                    REFERENCES device_contact_attempts(run_id, attempt_number)
            );
CREATE TABLE device_contact_runs (
                run_id TEXT PRIMARY KEY CHECK(length(run_id) = 32),
                operation_kind TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                request_json TEXT NOT NULL,
                request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
                state TEXT NOT NULL CHECK(state IN (
                    'waiting', 'preparing', 'contact_starting', 'contact_active',
                    'complete', 'cancelled', 'failed', 'needs_attention'
                )),
                contact_phase TEXT NOT NULL CHECK(contact_phase IN (
                    'not_started', 'preparing', 'contact_starting',
                    'contact_active', 'contact_stopped', 'uncertain', 'complete'
                )),
                cancellation_requested INTEGER NOT NULL DEFAULT 0
                    CHECK(cancellation_requested IN (0, 1)),
                retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count IN (0, 1)),
                active_attempt_number INTEGER,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                status_reason TEXT,
                terminal_manifest_json TEXT,
                presentation_synced INTEGER NOT NULL DEFAULT 0
                    CHECK(presentation_synced IN (0, 1))
            );
CREATE TABLE device_evidence_catalog (
            run_id TEXT PRIMARY KEY,
            device_key TEXT NOT NULL,
            completed_at TEXT,
            created_at TEXT,
            status TEXT NOT NULL,
            operation TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            authority_revision INTEGER NOT NULL,
            selection_contract TEXT NOT NULL,
            semantic_manifest_sha256 TEXT NOT NULL
        );
CREATE TABLE device_evidence_catalog_dirty (
            run_id TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            marked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
CREATE TABLE device_evidence_catalog_meta (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            schema_version INTEGER NOT NULL,
            reconciled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
CREATE TABLE device_interface_assessments (
                assessment_id TEXT PRIMARY KEY,
                assignment_id TEXT NOT NULL UNIQUE
                    REFERENCES device_scope_assignments(assignment_id),
                run_id TEXT NOT NULL,
                authority_revision INTEGER NOT NULL,
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                configuration_observation_id TEXT NOT NULL
                    REFERENCES artifact_observations(observation_id),
                configuration_sha256 TEXT NOT NULL,
                configuration_size_bytes INTEGER NOT NULL CHECK(configuration_size_bytes >= 0),
                configuration_filename TEXT NOT NULL,
                summary_result_id TEXT NOT NULL REFERENCES derived_results(result_id),
                extractor_version TEXT NOT NULL,
                coverage_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );
CREATE TABLE device_interface_receipts (
                receipt_id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL REFERENCES device_interface_assessments(assessment_id),
                interface_name TEXT NOT NULL,
                address TEXT NOT NULL,
                prefix_length INTEGER NOT NULL,
                address_family TEXT NOT NULL CHECK(address_family IN ('ipv4', 'ipv6')),
                routing_context TEXT,
                routing_context_status TEXT NOT NULL CHECK(
                    routing_context_status IN ('known', 'default', 'unresolved')
                ),
                source_line_number INTEGER NOT NULL CHECK(source_line_number >= 1),
                source_line TEXT NOT NULL,
                source_syntax TEXT NOT NULL,
                facts_json TEXT NOT NULL,
                UNIQUE(assessment_id, source_line_number, interface_name, address, prefix_length)
            );
CREATE TABLE device_scope_assignments (
                assignment_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                authority_revision INTEGER NOT NULL CHECK(authority_revision >= 1),
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                revision INTEGER NOT NULL CHECK(revision >= 1),
                event_kind TEXT NOT NULL CHECK(event_kind IN ('assigned', 'corrected')),
                supersedes_assignment_id TEXT UNIQUE
                    REFERENCES device_scope_assignments(assignment_id),
                actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 100 AND actor = trim(actor)),
                reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 500 AND reason = trim(reason)),
                assigned_at TEXT NOT NULL,
                UNIQUE(run_id, authority_revision, revision)
            );
CREATE TABLE device_vlan_admission_intents (
            intent_id TEXT PRIMARY KEY,
            assignment_id TEXT NOT NULL UNIQUE
                REFERENCES device_scope_assignments(assignment_id),
            policy_version INTEGER NOT NULL CHECK(policy_version >= 1),
            source_observation_id TEXT NOT NULL
                REFERENCES artifact_observations(observation_id),
            scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
            actor TEXT NOT NULL,
            request_token TEXT NOT NULL UNIQUE,
            contract_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending', 'admitted', 'blocked')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            admitted_job_id TEXT UNIQUE REFERENCES pipeline_jobs(job_id),
            activity_state TEXT NOT NULL CHECK(
                activity_state IN ('waiting', 'retrying', 'paused', 'complete', 'blocked')
            ),
            last_error TEXT,
            CHECK(
                (state = 'pending' AND admitted_job_id IS NULL
                    AND activity_state IN ('waiting', 'retrying', 'paused'))
                OR (state = 'admitted' AND admitted_job_id IS NOT NULL
                    AND activity_state = 'complete' AND last_error IS NULL)
                OR (state = 'blocked' AND admitted_job_id IS NULL
                    AND activity_state = 'blocked'
                    AND length(trim(last_error)) >= 1)
            )
        );
CREATE TABLE device_vlan_assessments (
            assessment_id TEXT PRIMARY KEY,
            assignment_id TEXT NOT NULL
                REFERENCES device_scope_assignments(assignment_id),
            run_id TEXT NOT NULL,
            authority_revision INTEGER NOT NULL CHECK(authority_revision >= 1),
            assignment_revision INTEGER NOT NULL CHECK(assignment_revision >= 1),
            scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
            configuration_observation_id TEXT NOT NULL
                REFERENCES artifact_observations(observation_id),
            configuration_sha256 TEXT NOT NULL CHECK(length(configuration_sha256) = 64),
            configuration_size_bytes INTEGER NOT NULL CHECK(configuration_size_bytes >= 0),
            configuration_filename TEXT NOT NULL,
            summary_result_id TEXT NOT NULL REFERENCES derived_results(result_id),
            extractor_version TEXT NOT NULL,
            collection_contract TEXT NOT NULL,
            source_contract_json TEXT NOT NULL,
            coverage_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE(assignment_id, extractor_version, collection_contract)
        );
CREATE TABLE device_vlan_receipts (
            receipt_id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL REFERENCES device_vlan_assessments(assessment_id),
            source_observation_id TEXT NOT NULL
                REFERENCES artifact_observations(observation_id),
            source_role TEXT NOT NULL CHECK(
                source_role IN ('configuration', 'raw_output', 'configuration_and_raw_output')
            ),
            source_filename TEXT NOT NULL,
            device_context TEXT NOT NULL,
            bridge_context TEXT,
            vlan_id INTEGER NOT NULL CHECK(vlan_id BETWEEN 0 AND 4095),
            vlan_name TEXT,
            interface_name TEXT,
            membership_relation TEXT NOT NULL CHECK(
                membership_relation IN (
                    'declaration', 'declared_member', 'access', 'native', 'allowed',
                    'tagged', 'untagged', 'pvid'
                )
            ),
            evidence_state TEXT NOT NULL CHECK(
                evidence_state IN ('configured', 'observed')
            ),
            source_line_number INTEGER NOT NULL CHECK(source_line_number >= 1),
            source_line TEXT NOT NULL,
            related_line_number INTEGER CHECK(related_line_number IS NULL OR related_line_number >= 1),
            related_source_line TEXT,
            source_command TEXT,
            source_section TEXT,
            source_syntax TEXT NOT NULL,
            facts_json TEXT NOT NULL,
            UNIQUE(
                assessment_id, source_observation_id, source_line_number,
                membership_relation, vlan_id, device_context,
                interface_name, bridge_context
            )
        );
CREATE TABLE endpoint_entities (
                entity_id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL,
                address TEXT NOT NULL,
                UNIQUE(scope_id, address)
            );
CREATE TABLE endpoint_receipts (
                assessment_id TEXT NOT NULL REFERENCES entity_assessments(assessment_id),
                host_id TEXT NOT NULL REFERENCES endpoint_entities(entity_id),
                facts_json TEXT NOT NULL,
                PRIMARY KEY(assessment_id, host_id)
            );
CREATE TABLE entity_assessments (
                assessment_id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL,
                artifact_observation_id TEXT NOT NULL
                    REFERENCES artifact_observations(observation_id),
                parser_version TEXT NOT NULL,
                assessed_at TEXT,
                recorded_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                UNIQUE(scope_id, artifact_observation_id, parser_version)
            );
CREATE TABLE global_no_strike_history (
                    revision INTEGER PRIMARY KEY,
                    entries_json TEXT NOT NULL,
                    action TEXT NOT NULL,
                    changed_at TEXT NOT NULL,
                    changed_by TEXT NOT NULL
                );
CREATE TABLE host_os_inference_review_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                identity_key TEXT NOT NULL,
                inference_signature TEXT NOT NULL,
                inference_json TEXT NOT NULL,
                status TEXT NOT NULL,
                analyst TEXT NOT NULL,
                reason TEXT NOT NULL,
                changed_at TEXT NOT NULL
            );
CREATE TABLE host_os_inference_reviews (
                identity_key TEXT PRIMARY KEY,
                ip TEXT,
                mac TEXT,
                inference_signature TEXT NOT NULL,
                inference_json TEXT NOT NULL,
                status TEXT NOT NULL,
                analyst TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
CREATE TABLE host_os_override_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                identity_key TEXT NOT NULL,
                action TEXT NOT NULL,
                ip TEXT,
                mac TEXT,
                os_name TEXT,
                analyst TEXT NOT NULL,
                reason TEXT NOT NULL,
                scanner_os_at_change TEXT,
                changed_at TEXT NOT NULL
            );
CREATE TABLE host_os_overrides (
                identity_key TEXT PRIMARY KEY,
                ip TEXT,
                mac TEXT,
                os_name TEXT NOT NULL,
                analyst TEXT NOT NULL,
                reason TEXT NOT NULL,
                scanner_os_at_change TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
CREATE TABLE imports (
                sha256 TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                analysis_json TEXT NOT NULL
            , metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE mission_environment_audit (
                audit_id TEXT PRIMARY KEY,
                record_kind TEXT NOT NULL CHECK(record_kind IN ('tool', 'scope')),
                record_key TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK(sequence >= 1),
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                previous_version INTEGER NOT NULL CHECK(previous_version >= 0),
                new_version INTEGER NOT NULL CHECK(new_version >= 1),
                before_json TEXT NOT NULL,
                after_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE(record_kind, record_key, sequence)
            );
CREATE TABLE mission_environment_tools (
                tool_key TEXT PRIMARY KEY CHECK(tool_key IN (
                    'nmap', 'arkime', 'kibana', 'device_config'
                )),
                availability TEXT NOT NULL CHECK(availability IN (
                    'available', 'unavailable', 'unknown'
                )),
                version_text TEXT NOT NULL,
                access_method TEXT NOT NULL,
                notes TEXT NOT NULL,
                version INTEGER NOT NULL CHECK(version >= 1),
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );
CREATE TABLE mission_scope_contexts (
                scope_id TEXT PRIMARY KEY REFERENCES network_scopes(scope_id),
                nmap_coverage TEXT NOT NULL CHECK(nmap_coverage IN (
                    'available', 'partial', 'unavailable', 'unknown'
                )),
                arkime_coverage TEXT NOT NULL CHECK(arkime_coverage IN (
                    'available', 'partial', 'unavailable', 'unknown'
                )),
                kibana_coverage TEXT NOT NULL CHECK(kibana_coverage IN (
                    'available', 'partial', 'unavailable', 'unknown'
                )),
                config_coverage TEXT NOT NULL CHECK(config_coverage IN (
                    'available', 'partial', 'unavailable', 'unknown'
                )),
                nmap_authorization TEXT NOT NULL CHECK(nmap_authorization IN (
                    'authorized', 'prohibited', 'unknown'
                )),
                device_evidence TEXT NOT NULL CHECK(device_evidence IN (
                    'full_configuration', 'partial_configuration',
                    'command_output_only', 'analyst_known_manual',
                    'unavailable', 'unknown'
                )),
                blind_spots_json TEXT NOT NULL,
                notes TEXT NOT NULL,
                version INTEGER NOT NULL CHECK(version >= 1),
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );
CREATE TABLE nct_schema_migrations (
            migration_id TEXT PRIMARY KEY,
            target_schema_version INTEGER NOT NULL,
            originating_build_id TEXT NOT NULL,
            originating_build_commit TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('started', 'completed', 'failed')),
            attempts INTEGER NOT NULL CHECK(attempts >= 1),
            first_started_at TEXT NOT NULL,
            last_started_at TEXT NOT NULL,
            completed_at TEXT,
            before_schema_fingerprint TEXT NOT NULL,
            after_schema_fingerprint TEXT,
            error_summary TEXT
        );
INSERT INTO "nct_schema_migrations" VALUES('nct-foundation-data-contract-v1',1,'0.16.0-range-test-20261019-phase4-r5','b908834cb60327a640e9987fddff036c4df9fb75','completed',1,'2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','af3ea5d49ba0744fcf5faf4821f5844658d4a0a6566b6948dfd56c7a5da17687','af3ea5d49ba0744fcf5faf4821f5844658d4a0a6566b6948dfd56c7a5da17687',NULL);
INSERT INTO "nct_schema_migrations" VALUES('nct-work-coordination-v2',2,'0.16.0-range-test-20261019-phase4-r5','b908834cb60327a640e9987fddff036c4df9fb75','completed',1,'2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','af3ea5d49ba0744fcf5faf4821f5844658d4a0a6566b6948dfd56c7a5da17687','af3ea5d49ba0744fcf5faf4821f5844658d4a0a6566b6948dfd56c7a5da17687',NULL);
INSERT INTO "nct_schema_migrations" VALUES('nct-scheduled-occurrences-v3',3,'0.16.0-range-test-20261019-phase4-r5','b908834cb60327a640e9987fddff036c4df9fb75','completed',1,'2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','af3ea5d49ba0744fcf5faf4821f5844658d4a0a6566b6948dfd56c7a5da17687','af3ea5d49ba0744fcf5faf4821f5844658d4a0a6566b6948dfd56c7a5da17687',NULL);
INSERT INTO "nct_schema_migrations" VALUES('nct-device-contact-fencing-v4',4,'0.16.0-range-test-20261019-phase4-r5','b908834cb60327a640e9987fddff036c4df9fb75','completed',1,'2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','af3ea5d49ba0744fcf5faf4821f5844658d4a0a6566b6948dfd56c7a5da17687','af3ea5d49ba0744fcf5faf4821f5844658d4a0a6566b6948dfd56c7a5da17687',NULL);
INSERT INTO "nct_schema_migrations" VALUES('nct-mission-environment-v5',5,'0.16.0-range-test-20261019-phase4-r5','b908834cb60327a640e9987fddff036c4df9fb75','completed',1,'2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','af3ea5d49ba0744fcf5faf4821f5844658d4a0a6566b6948dfd56c7a5da17687','af3ea5d49ba0744fcf5faf4821f5844658d4a0a6566b6948dfd56c7a5da17687',NULL);
INSERT INTO "nct_schema_migrations" VALUES('nct-scoped-vlan-evidence-v6',6,'0.16.0-range-test-20261019-phase4-r5','b908834cb60327a640e9987fddff036c4df9fb75','completed',1,'2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','2026-10-26T03:40:55+00:00','af3ea5d49ba0744fcf5faf4821f5844658d4a0a6566b6948dfd56c7a5da17687','b4f07fa059e889cd80af945187fdb81af1b5812e9d41b3eabf4c8e32e33dafeb',NULL);
CREATE TABLE nct_schema_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            schema_contract_version INTEGER NOT NULL,
            schema_version INTEGER NOT NULL,
            data_layout_contract TEXT NOT NULL,
            migration_plan_digest TEXT NOT NULL,
            schema_fingerprint TEXT,
            originating_build_id TEXT NOT NULL,
            originating_build_commit TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
INSERT INTO "nct_schema_state" VALUES(1,6,6,'nct-data-layout-v1','da2c081d9b3f0eda8af48496b3417e5a260fa2dd4b1030418750e5ce03c3025a','b4f07fa059e889cd80af945187fdb81af1b5812e9d41b3eabf4c8e32e33dafeb','0.16.0-range-test-20261019-phase4-r5','b908834cb60327a640e9987fddff036c4df9fb75','2026-10-26T03:40:55+00:00');
CREATE TABLE network_environment_settings (
                setting TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                changed_by TEXT NOT NULL
            );
CREATE TABLE network_scope_audit (
                audit_id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                sequence INTEGER NOT NULL,
                event TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                previous_version INTEGER,
                new_version INTEGER NOT NULL,
                before_json TEXT,
                after_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE(scope_id, sequence)
            );
CREATE TABLE network_scopes (
                scope_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                label_key TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                version INTEGER NOT NULL CHECK(version >= 1),
                active INTEGER NOT NULL CHECK(active IN (0, 1)),
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                archived_at TEXT,
                archived_by TEXT,
                legacy INTEGER NOT NULL DEFAULT 0 CHECK(legacy IN (0, 1))
            );
CREATE TABLE network_semantics (
                role TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                device_name TEXT NOT NULL DEFAULT '',
                device_address TEXT NOT NULL DEFAULT '',
                interface_name TEXT NOT NULL DEFAULT '',
                changed_at TEXT NOT NULL,
                changed_by TEXT NOT NULL
            );
CREATE TABLE network_wan_interfaces (
                role TEXT NOT NULL,
                node_id TEXT NOT NULL,
                interface_name TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (role, interface_name)
            );
CREATE TABLE pipeline_admission_intents (
                intent_id TEXT PRIMARY KEY,
                intent_kind TEXT NOT NULL CHECK (intent_kind IN ('manual_nmap_scope', 'automated_nmap_scope', 'manual_device_summary', 'collected_device_summary', 'device_interface_observation')),
                source_kind TEXT NOT NULL,
                source_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                observation_id TEXT,
                assignment_id TEXT,
                scope_id TEXT,
                actor TEXT NOT NULL,
                request_token TEXT NOT NULL UNIQUE,
                contract_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK (
                    state IN ('pending', 'admitted', 'needs_scope', 'blocked')
                ),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                admitted_job_id TEXT,
                resolved_assignment_id TEXT,
                activity_state TEXT NOT NULL CHECK (
                    activity_state IN (
                        'waiting', 'retrying', 'paused', 'complete',
                        'needs_scope', 'blocked'
                    )
                ),
                last_error TEXT,
                UNIQUE (intent_kind, source_id)
            );
CREATE TABLE pipeline_intake_sources (
                source_kind TEXT NOT NULL,
                source_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                marked_by TEXT NOT NULL,
                marked_at TEXT NOT NULL,
                PRIMARY KEY (source_kind, source_id)
            );
CREATE TABLE pipeline_job_attempts (
                attempt_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL REFERENCES pipeline_jobs(job_id) ON DELETE RESTRICT,
                attempt_number INTEGER NOT NULL CHECK(attempt_number >= 1),
                state TEXT NOT NULL CHECK(state IN (
                    'queued', 'running', 'completed', 'failed', 'interrupted'
                )),
                claim_token TEXT,
                lease_owner TEXT,
                lease_epoch INTEGER NOT NULL DEFAULT 0 CHECK(lease_epoch >= 0),
                lease_expires_at TEXT,
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                outcome TEXT CHECK(outcome IS NULL OR outcome IN ('created', 'reused')),
                result_id TEXT,
                output_kind TEXT,
                output_id TEXT,
                error TEXT,
                UNIQUE(job_id, attempt_number)
            );
CREATE TABLE pipeline_job_migrations (
                migration_id TEXT PRIMARY KEY,
                legacy_jobs_count INTEGER NOT NULL,
                legacy_requests_count INTEGER NOT NULL,
                legacy_attempts_count INTEGER NOT NULL,
                legacy_jobs_digest TEXT NOT NULL,
                legacy_requests_digest TEXT NOT NULL,
                legacy_attempts_digest TEXT NOT NULL,
                completed_at TEXT NOT NULL
            );
CREATE TABLE pipeline_job_requests (
                request_token TEXT PRIMARY KEY,
                job_id TEXT NOT NULL REFERENCES pipeline_jobs(job_id) ON DELETE RESTRICT,
                request_kind TEXT NOT NULL CHECK(request_kind IN ('initial', 'retry')),
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL
            );
CREATE TABLE pipeline_jobs (
                job_id TEXT PRIMARY KEY,
                job_key TEXT NOT NULL UNIQUE,
                job_type TEXT NOT NULL,
                source_run_id TEXT,
                source_observation_id TEXT NOT NULL,
                source_status TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                source_size_bytes INTEGER NOT NULL CHECK(source_size_bytes >= 0),
                target_family TEXT,
                target_analysis_version TEXT,
                target_payload_schema_version INTEGER,
                target_parameters_json TEXT,
                target_computation_key TEXT,
                target_result_id TEXT,
                source_kind TEXT NOT NULL DEFAULT 'scan_run',
                source_ref TEXT,
                definition_json TEXT NOT NULL DEFAULT '{}',
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL
            );
CREATE TABLE reach_exposure_reports (
                saved_network_id TEXT PRIMARY KEY,
                target_name TEXT NOT NULL,
                target_cidr TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                generated_by TEXT NOT NULL DEFAULT '',
                port_snapshot_json TEXT NOT NULL,
                report_json TEXT NOT NULL
            );
CREATE TABLE saved_network_scope_associations (
                association_id TEXT PRIMARY KEY,
                saved_network_id TEXT NOT NULL REFERENCES saved_networks(saved_network_id),
                scope_id TEXT REFERENCES network_scopes(scope_id),
                revision INTEGER NOT NULL CHECK(revision >= 1),
                event TEXT NOT NULL CHECK(event IN ('assigned', 'changed', 'cleared')),
                predecessor_id TEXT REFERENCES saved_network_scope_associations(association_id),
                actor TEXT NOT NULL CHECK(length(trim(actor)) > 0),
                reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
                recorded_at TEXT NOT NULL,
                CHECK(
                    (event = 'cleared' AND scope_id IS NULL) OR
                    (event IN ('assigned', 'changed') AND scope_id IS NOT NULL)
                ),
                UNIQUE(saved_network_id, revision)
            );
CREATE TABLE saved_networks (
                    saved_network_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    cidr TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL DEFAULT '',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                );
CREATE TABLE scan_foundation_processing_attempts (
                attempt_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES scan_runs(run_id),
                observation_id TEXT NOT NULL REFERENCES artifact_observations(observation_id),
                assignment_id TEXT NOT NULL REFERENCES artifact_scope_assignments(assignment_id),
                actor TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL
                    CHECK(status IN ('running', 'complete', 'error', 'interrupted')),
                error TEXT
            );
CREATE TABLE scan_history_groups (
                group_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                cidr TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                tags_json TEXT NOT NULL,
                scan_count INTEGER NOT NULL,
                latest_created_at TEXT NOT NULL,
                latest_run_id TEXT NOT NULL,
                latest_scan_at TEXT NOT NULL,
                latest_scan_name TEXT,
                latest_host_count INTEGER
            );
CREATE TABLE scan_history_index_dirty (
                run_id TEXT PRIMARY KEY,
                changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE
            );
CREATE TABLE scan_history_index_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                version INTEGER NOT NULL
            );
CREATE TABLE scan_history_memberships (
                run_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                cidr TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                tags_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                latest_scan_at TEXT NOT NULL,
                latest_scan_name TEXT,
                host_count INTEGER,
                PRIMARY KEY (run_id, group_id),
                FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE
            );
CREATE TABLE scan_inherited_scope_assignments (
                assignment_id TEXT PRIMARY KEY
                    REFERENCES artifact_scope_assignments(assignment_id),
                observation_id TEXT NOT NULL UNIQUE
                    REFERENCES artifact_observations(observation_id),
                run_id TEXT NOT NULL UNIQUE
                    REFERENCES scan_run_scope_contexts(run_id),
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                inherited_at TEXT NOT NULL
            );
CREATE TABLE scan_profiles (
                    profile_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    built_in INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    source_profile_id TEXT,
                    source_profile_version INTEGER,
                    settings_json TEXT NOT NULL,
                    PRIMARY KEY (profile_id, version)
                );
CREATE TABLE scan_run_audit (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    event TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    changed_at TEXT NOT NULL,
                    details TEXT NOT NULL DEFAULT ''
                );
CREATE TABLE scan_run_control (
                    run_id TEXT PRIMARY KEY,
                    cancellation_requested_at TEXT,
                    cancellation_requested_by TEXT,
                    cancellation_cause TEXT,
                    cancellation_detail TEXT,
                    cancellation_acknowledged_at TEXT,
                    CHECK (
                        cancellation_requested_at IS NULL
                        OR (
                            cancellation_requested_by IS NOT NULL
                            AND cancellation_cause IS NOT NULL
                        )
                    )
                );
CREATE TABLE scan_run_scope_contexts (
                run_id TEXT PRIMARY KEY REFERENCES scan_runs(run_id) ON DELETE CASCADE,
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                scope_label TEXT NOT NULL,
                scope_version INTEGER NOT NULL CHECK(scope_version >= 1),
                recorded_at TEXT NOT NULL
            );
CREATE TABLE scan_run_scope_sources (
                run_id TEXT NOT NULL REFERENCES scan_run_scope_contexts(run_id) ON DELETE CASCADE,
                saved_network_id TEXT NOT NULL REFERENCES saved_networks(saved_network_id),
                association_id TEXT NOT NULL REFERENCES saved_network_scope_associations(association_id),
                association_revision INTEGER NOT NULL CHECK(association_revision >= 1),
                PRIMARY KEY(run_id, saved_network_id)
            );
CREATE TABLE scan_runs (
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    operator_name TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    originating_host TEXT NOT NULL,
                    interface_name TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    manifest_json TEXT NOT NULL
                );
CREATE TABLE scan_schedule_chunks (
                occurrence_id TEXT NOT NULL,
                chunk_number INTEGER NOT NULL CHECK(chunk_number >= 1),
                targets_json TEXT NOT NULL,
                targets_digest TEXT NOT NULL CHECK(length(targets_digest) = 64),
                target_count INTEGER NOT NULL CHECK(target_count >= 1),
                state TEXT NOT NULL CHECK(state IN (
                    'waiting', 'preparing', 'active', 'complete', 'cancelled',
                    'needs_attention'
                )),
                contact_phase TEXT NOT NULL CHECK(contact_phase IN (
                    'not_started', 'preparing', 'contact_starting', 'contact_active',
                    'contact_stopped', 'complete', 'uncertain'
                )),
                scan_run_id TEXT UNIQUE,
                last_fencing_epoch INTEGER CHECK(last_fencing_epoch IS NULL OR last_fencing_epoch >= 1),
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                status_reason TEXT,
                PRIMARY KEY(occurrence_id, chunk_number),
                FOREIGN KEY(occurrence_id) REFERENCES scan_schedule_occurrences(occurrence_id)
                    ON DELETE CASCADE
            );
CREATE TABLE scan_schedule_definitions (
                schedule_id TEXT NOT NULL,
                definition_version INTEGER NOT NULL CHECK(definition_version >= 1),
                definition_digest TEXT NOT NULL CHECK(length(definition_digest) = 64),
                contract_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                PRIMARY KEY(schedule_id, definition_version),
                UNIQUE(schedule_id, definition_digest),
                FOREIGN KEY(schedule_id) REFERENCES scan_schedules(schedule_id)
                    ON DELETE CASCADE
            );
CREATE TABLE scan_schedule_occurrences (
                occurrence_id TEXT PRIMARY KEY CHECK(length(occurrence_id) = 32),
                schedule_id TEXT NOT NULL,
                definition_version INTEGER NOT NULL,
                definition_digest TEXT NOT NULL CHECK(length(definition_digest) = 64),
                due_at TEXT NOT NULL,
                trigger_kind TEXT NOT NULL CHECK(trigger_kind IN ('scheduled', 'manual')),
                trigger_key TEXT NOT NULL,
                actor TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'waiting', 'preparing', 'active', 'complete', 'cancelled',
                    'missed', 'needs_attention'
                )),
                frozen_json TEXT NOT NULL,
                frozen_digest TEXT NOT NULL CHECK(length(frozen_digest) = 64),
                first_missed_due_at TEXT,
                latest_missed_due_at TEXT,
                skipped_due_count INTEGER NOT NULL DEFAULT 0 CHECK(skipped_due_count >= 0),
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                status_reason TEXT,
                UNIQUE(schedule_id, definition_version, due_at, trigger_kind, trigger_key),
                FOREIGN KEY(schedule_id, definition_version)
                    REFERENCES scan_schedule_definitions(schedule_id, definition_version)
            );
CREATE TABLE scan_schedule_recovery_reviews (
                review_id TEXT PRIMARY KEY,
                occurrence_id TEXT NOT NULL UNIQUE,
                reviewed_by TEXT NOT NULL,
                reviewed_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                confirmed_former_contact_stopped INTEGER NOT NULL CHECK(
                    confirmed_former_contact_stopped = 1
                ),
                FOREIGN KEY(occurrence_id) REFERENCES scan_schedule_occurrences(occurrence_id)
            );
CREATE TABLE scan_schedule_scope_contexts (
                schedule_id TEXT PRIMARY KEY REFERENCES scan_schedules(schedule_id) ON DELETE CASCADE,
                scope_id TEXT NOT NULL REFERENCES network_scopes(scope_id),
                scope_label TEXT NOT NULL,
                scope_version INTEGER NOT NULL CHECK(scope_version >= 1),
                recorded_at TEXT NOT NULL
            );
CREATE TABLE scan_schedule_scope_sources (
                schedule_id TEXT NOT NULL REFERENCES scan_schedule_scope_contexts(schedule_id) ON DELETE CASCADE,
                saved_network_id TEXT NOT NULL REFERENCES saved_networks(saved_network_id),
                association_id TEXT NOT NULL REFERENCES saved_network_scope_associations(association_id),
                association_revision INTEGER NOT NULL CHECK(association_revision >= 1),
                PRIMARY KEY(schedule_id, saved_network_id)
            );
CREATE TABLE scan_schedules (
                    schedule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    profile_version INTEGER NOT NULL,
                    definition_json TEXT NOT NULL,
                    FOREIGN KEY (profile_id, profile_version)
                        REFERENCES scan_profiles(profile_id, version)
                );
CREATE TABLE searchsploit_query_cache (
                    provider_key TEXT NOT NULL,
                    query TEXT NOT NULL,
                    candidates_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (provider_key, query)
                );
CREATE TABLE service_entities (
                entity_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES endpoint_entities(entity_id),
                protocol TEXT NOT NULL,
                port INTEGER NOT NULL CHECK(port BETWEEN 0 AND 65535),
                UNIQUE(host_id, protocol, port)
            );
CREATE TABLE service_receipts (
                assessment_id TEXT NOT NULL REFERENCES entity_assessments(assessment_id),
                service_id TEXT NOT NULL REFERENCES service_entities(entity_id),
                facts_json TEXT NOT NULL,
                PRIMARY KEY(assessment_id, service_id)
            );
CREATE TABLE shared_analyst_themes (
                theme_id TEXT PRIMARY KEY,
                source_theme_id TEXT NOT NULL,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(owner, source_theme_id)
            );
CREATE TABLE work_lease_events (
                event_id TEXT PRIMARY KEY,
                lease_key TEXT NOT NULL,
                fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch >= 1),
                lease_id TEXT,
                owner_id TEXT,
                event_kind TEXT NOT NULL CHECK(event_kind IN (
                    'acquired', 'renewed', 'released', 'expired',
                    'recovery_required', 'recovery_cleared'
                )),
                recorded_at TEXT NOT NULL,
                detail TEXT
            );
CREATE TABLE work_leases (
                lease_key TEXT PRIMARY KEY,
                work_kind TEXT NOT NULL,
                work_id TEXT NOT NULL,
                fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch >= 1),
                lease_id TEXT,
                owner_id TEXT,
                state TEXT NOT NULL CHECK(state IN (
                    'active', 'released', 'recovery_required'
                )),
                acquired_at TEXT,
                renewed_at TEXT,
                expires_at TEXT,
                released_at TEXT,
                recovery_reason TEXT,
                CHECK(
                    (state = 'active' AND lease_id IS NOT NULL
                        AND owner_id IS NOT NULL AND acquired_at IS NOT NULL
                        AND renewed_at IS NOT NULL AND expires_at IS NOT NULL
                        AND released_at IS NULL AND recovery_reason IS NULL)
                    OR
                    (state = 'released' AND lease_id IS NULL AND owner_id IS NULL
                        AND expires_at IS NULL AND released_at IS NOT NULL
                        AND recovery_reason IS NULL)
                    OR
                    (state = 'recovery_required' AND lease_id IS NULL
                        AND owner_id IS NULL AND expires_at IS NULL
                        AND recovery_reason IS NOT NULL)
                )
            );
CREATE INDEX artifact_observations_sha ON artifact_observations(sha256, observed_at);
CREATE INDEX artifact_observations_source ON artifact_observations(source_kind, source_ref);
CREATE UNIQUE INDEX saved_networks_active_name_unique ON saved_networks(lower(name)) WHERE active = 1;
CREATE UNIQUE INDEX saved_networks_active_cidr_unique ON saved_networks(cidr) WHERE active = 1;
CREATE UNIQUE INDEX network_scopes_active_label
                ON network_scopes(label_key) WHERE active = 1;
CREATE INDEX network_scope_audit_scope
                ON network_scope_audit(scope_id, recorded_at, audit_id);
CREATE TRIGGER network_scopes_no_delete
                BEFORE DELETE ON network_scopes
                BEGIN SELECT RAISE(ABORT, 'network scopes cannot be deleted'); END;
CREATE TRIGGER network_scopes_id_immutable
                BEFORE UPDATE OF scope_id ON network_scopes
                BEGIN SELECT RAISE(ABORT, 'network scope identity is immutable'); END;
CREATE TRIGGER network_scope_audit_no_update
                BEFORE UPDATE ON network_scope_audit
                BEGIN SELECT RAISE(ABORT, 'network scope audit is immutable'); END;
CREATE TRIGGER network_scope_audit_no_delete
                BEFORE DELETE ON network_scope_audit
                BEGIN SELECT RAISE(ABORT, 'network scope audit is immutable'); END;
CREATE INDEX mission_environment_audit_record
                ON mission_environment_audit(record_kind, record_key, sequence);
CREATE TRIGGER mission_environment_tool_key_immutable
                BEFORE UPDATE OF tool_key ON mission_environment_tools
                BEGIN SELECT RAISE(ABORT, 'mission tool identity is immutable'); END;
CREATE TRIGGER mission_scope_id_immutable
                BEFORE UPDATE OF scope_id ON mission_scope_contexts
                BEGIN SELECT RAISE(ABORT, 'mission scope identity is immutable'); END;
CREATE TRIGGER mission_environment_audit_no_update
                BEFORE UPDATE ON mission_environment_audit
                BEGIN SELECT RAISE(ABORT, 'mission environment audit is immutable'); END;
CREATE TRIGGER mission_environment_audit_no_delete
                BEFORE DELETE ON mission_environment_audit
                BEGIN SELECT RAISE(ABORT, 'mission environment audit is immutable'); END;
CREATE INDEX scan_run_audit_run ON scan_run_audit(run_id, event_id);
CREATE TRIGGER global_no_strike_history_no_update
                BEFORE UPDATE ON global_no_strike_history
                BEGIN
                    SELECT RAISE(ABORT, 'Global No-Strike history is append-only');
                END;
CREATE TRIGGER global_no_strike_history_no_delete
                BEFORE DELETE ON global_no_strike_history
                BEGIN
                    SELECT RAISE(ABORT, 'Global No-Strike history is append-only');
                END;
CREATE TRIGGER global_no_strike_history_valid_insert
                BEFORE INSERT ON global_no_strike_history
                WHEN NEW.revision != COALESCE(
                        (SELECT MAX(revision) + 1 FROM global_no_strike_history), 1
                    )
                    OR NEW.entries_json IS NOT nct_normalize_ipv4_network_list(NEW.entries_json)
                    OR NEW.action NOT IN ('add', 'remove', 'legacy_snapshot')
                    OR nct_is_canonical_utc(NEW.changed_at) != 1
                    OR NEW.changed_by != trim(NEW.changed_by)
                    OR trim(NEW.changed_by) = ''
                    OR length(NEW.changed_by) > 100
                BEGIN
                    SELECT RAISE(ABORT, 'Invalid Global No-Strike history revision');
                END;
CREATE INDEX scan_runs_status_created ON scan_runs(status, created_at);
CREATE INDEX scan_runs_created ON scan_runs(created_at DESC);
CREATE INDEX scan_schedules_profile ON scan_schedules(profile_id, profile_version);
CREATE INDEX work_lease_event_history
                ON work_lease_events(lease_key, fencing_epoch, recorded_at, event_id);
CREATE UNIQUE INDEX one_open_schedule_occurrence
                ON scan_schedule_occurrences(schedule_id)
                WHERE state IN ('waiting', 'preparing', 'active', 'needs_attention');
CREATE INDEX schedule_occurrence_history
                ON scan_schedule_occurrences(schedule_id, created_at DESC, occurrence_id);
CREATE INDEX schedule_chunk_state
                ON scan_schedule_chunks(occurrence_id, state, chunk_number);
CREATE TRIGGER scan_schedule_definition_no_update
            BEFORE UPDATE ON scan_schedule_definitions
            BEGIN
                SELECT RAISE(ABORT, 'Schedule definitions are immutable');
            END;
CREATE TRIGGER scan_schedule_occurrence_frozen_fields
            BEFORE UPDATE OF schedule_id, definition_version, definition_digest,
                due_at, trigger_kind, trigger_key, actor, frozen_json, frozen_digest,
                first_missed_due_at, latest_missed_due_at, skipped_due_count, created_at
            ON scan_schedule_occurrences
            BEGIN
                SELECT RAISE(ABORT, 'Schedule occurrence plan is immutable');
            END;
CREATE TRIGGER scan_schedule_chunk_frozen_fields
            BEFORE UPDATE OF occurrence_id, chunk_number, targets_json, targets_digest,
                target_count, created_at
            ON scan_schedule_chunks
            BEGIN
                SELECT RAISE(ABORT, 'Schedule chunk plan is immutable');
            END;
CREATE TRIGGER scan_schedule_chunk_complete_irreversible
            BEFORE UPDATE OF state ON scan_schedule_chunks
            WHEN OLD.state = 'complete' AND NEW.state != 'complete'
            BEGIN
                SELECT RAISE(ABORT, 'Completed schedule chunks cannot reopen');
            END;
CREATE INDEX scan_history_memberships_group_page
                ON scan_history_memberships(group_id, created_at DESC, run_id DESC);
CREATE INDEX scan_history_memberships_run
                ON scan_history_memberships(run_id, group_id);
CREATE INDEX scan_history_groups_catalog
                ON scan_history_groups(kind, name COLLATE NOCASE, cidr, group_id);
CREATE TRIGGER scan_history_membership_group_insert
            AFTER INSERT ON scan_history_memberships
            BEGIN
                INSERT INTO scan_history_groups (
                    group_id, kind, name, cidr, description, category, tags_json,
                    scan_count, latest_created_at, latest_run_id, latest_scan_at,
                    latest_scan_name, latest_host_count
                ) VALUES (
                    NEW.group_id, NEW.kind, NEW.name, NEW.cidr, NEW.description,
                    NEW.category, NEW.tags_json, 1, NEW.created_at, NEW.run_id,
                    NEW.latest_scan_at, NEW.latest_scan_name, NEW.host_count
                )
                ON CONFLICT(group_id) DO UPDATE SET
                    scan_count = scan_history_groups.scan_count + 1,
                    kind = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.kind ELSE scan_history_groups.kind END,
                    name = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.name ELSE scan_history_groups.name END,
                    cidr = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.cidr ELSE scan_history_groups.cidr END,
                    description = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.description ELSE scan_history_groups.description END,
                    category = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.category ELSE scan_history_groups.category END,
                    tags_json = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.tags_json ELSE scan_history_groups.tags_json END,
                    latest_scan_at = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.latest_scan_at ELSE scan_history_groups.latest_scan_at END,
                    latest_scan_name = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.latest_scan_name ELSE scan_history_groups.latest_scan_name END,
                    latest_host_count = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.latest_host_count ELSE scan_history_groups.latest_host_count END,
                    latest_created_at = MAX(scan_history_groups.latest_created_at, excluded.latest_created_at),
                    latest_run_id = CASE WHEN excluded.latest_created_at > scan_history_groups.latest_created_at
                                   OR (excluded.latest_created_at = scan_history_groups.latest_created_at
                                       AND excluded.latest_run_id > scan_history_groups.latest_run_id)
                                THEN excluded.latest_run_id ELSE scan_history_groups.latest_run_id END;
            END;
CREATE TRIGGER scan_history_membership_group_delete
            AFTER DELETE ON scan_history_memberships
            BEGIN
                UPDATE scan_history_groups
                   SET scan_count = scan_count - 1
                 WHERE group_id = OLD.group_id;
                DELETE FROM scan_history_groups
                 WHERE group_id = OLD.group_id AND scan_count <= 0;
                UPDATE scan_history_groups
                   SET (kind, name, cidr, description, category, tags_json,
                        latest_created_at, latest_run_id, latest_scan_at,
                        latest_scan_name, latest_host_count) = (
                       SELECT kind, name, cidr, description, category, tags_json,
                              created_at, run_id, latest_scan_at,
                              latest_scan_name, host_count
                         FROM scan_history_memberships
                        WHERE group_id = OLD.group_id
                        ORDER BY created_at DESC, run_id DESC
                        LIMIT 1
                   )
                 WHERE group_id = OLD.group_id AND latest_run_id = OLD.run_id;
            END;
CREATE TRIGGER scan_history_run_dirty_insert
            AFTER INSERT ON scan_runs
            BEGIN
                INSERT INTO scan_history_index_dirty (run_id, changed_at)
                VALUES (NEW.run_id, CURRENT_TIMESTAMP)
                ON CONFLICT(run_id) DO UPDATE SET changed_at = excluded.changed_at;
            END;
CREATE TRIGGER scan_history_run_dirty_update
            AFTER UPDATE OF manifest_json ON scan_runs
            BEGIN
                INSERT INTO scan_history_index_dirty (run_id, changed_at)
                VALUES (NEW.run_id, CURRENT_TIMESTAMP)
                ON CONFLICT(run_id) DO UPDATE SET changed_at = excluded.changed_at;
            END;
CREATE TRIGGER scan_history_run_index_delete
            AFTER DELETE ON scan_runs
            BEGIN
                DELETE FROM scan_history_memberships WHERE run_id = OLD.run_id;
                DELETE FROM scan_history_index_dirty WHERE run_id = OLD.run_id;
            END;
CREATE UNIQUE INDEX saved_network_scope_one_root
                ON saved_network_scope_associations(saved_network_id)
                WHERE predecessor_id IS NULL;
CREATE UNIQUE INDEX saved_network_scope_one_successor
                ON saved_network_scope_associations(predecessor_id)
                WHERE predecessor_id IS NOT NULL;
CREATE INDEX saved_network_scope_current
                ON saved_network_scope_associations(saved_network_id, revision DESC);
CREATE TRIGGER saved_network_scope_validate_insert
            BEFORE INSERT ON saved_network_scope_associations
            BEGIN
                SELECT CASE WHEN NEW.actor != trim(NEW.actor)
                    OR length(NEW.actor) < 1 OR length(NEW.actor) > 100
                THEN RAISE(ABORT, 'association actor must be canonical text') END;
                SELECT CASE WHEN NEW.reason != trim(NEW.reason)
                    OR length(NEW.reason) < 1 OR length(NEW.reason) > 500
                THEN RAISE(ABORT, 'association reason must be canonical text') END;
                SELECT CASE WHEN datetime(NEW.recorded_at) IS NULL
                    OR NEW.recorded_at != strftime(
                        '%Y-%m-%dT%H:%M:%S+00:00', NEW.recorded_at
                    )
                THEN RAISE(ABORT, 'association time must be canonical UTC') END;
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1 FROM saved_networks
                    WHERE saved_network_id = NEW.saved_network_id AND active = 1
                ) THEN RAISE(ABORT, 'Saved Network must exist and be active') END;
                SELECT CASE WHEN NEW.scope_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM network_scopes
                    WHERE scope_id = NEW.scope_id AND active = 1
                ) THEN RAISE(ABORT, 'Network Scope must exist and be active') END;
                SELECT CASE WHEN NEW.predecessor_id IS NULL AND
                    (NEW.revision != 1 OR NEW.event != 'assigned')
                THEN RAISE(ABORT, 'association root must be an assignment at revision 1') END;
                SELECT CASE WHEN NEW.predecessor_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM saved_network_scope_associations previous
                    WHERE previous.association_id = NEW.predecessor_id
                      AND previous.saved_network_id = NEW.saved_network_id
                      AND NEW.revision = previous.revision + 1
                ) THEN RAISE(ABORT, 'association predecessor or revision is invalid') END;
                SELECT CASE WHEN NEW.predecessor_id IS NOT NULL AND EXISTS (
                    SELECT 1 FROM saved_network_scope_associations child
                    WHERE child.predecessor_id = NEW.predecessor_id
                ) THEN RAISE(ABORT, 'association predecessor is not the current revision') END;
                SELECT CASE WHEN NEW.predecessor_id IS NOT NULL AND NEW.event = 'assigned'
                    AND NOT EXISTS (
                        SELECT 1 FROM saved_network_scope_associations previous
                        WHERE previous.association_id = NEW.predecessor_id
                          AND previous.scope_id IS NULL
                    )
                THEN RAISE(ABORT, 'assigned event must follow a cleared association') END;
                SELECT CASE WHEN NEW.predecessor_id IS NOT NULL AND NEW.event = 'changed'
                    AND NOT EXISTS (
                        SELECT 1 FROM saved_network_scope_associations previous
                        WHERE previous.association_id = NEW.predecessor_id
                          AND previous.scope_id IS NOT NULL
                          AND previous.scope_id != NEW.scope_id
                    )
                THEN RAISE(ABORT, 'changed event must select a different scope') END;
                SELECT CASE WHEN NEW.predecessor_id IS NOT NULL AND NEW.event = 'cleared'
                    AND NOT EXISTS (
                        SELECT 1 FROM saved_network_scope_associations previous
                        WHERE previous.association_id = NEW.predecessor_id
                          AND previous.scope_id IS NOT NULL
                    )
                THEN RAISE(ABORT, 'cleared event must follow an assigned scope') END;
            END;
CREATE TRIGGER saved_network_scope_no_update
                BEFORE UPDATE ON saved_network_scope_associations
                BEGIN SELECT RAISE(ABORT, 'Saved Network scope history is immutable'); END;
CREATE TRIGGER saved_network_scope_no_delete
                BEFORE DELETE ON saved_network_scope_associations
                BEGIN SELECT RAISE(ABORT, 'Saved Network scope history is immutable'); END;
CREATE TRIGGER scan_run_scope_context_validate_insert
            BEFORE INSERT ON scan_run_scope_contexts
            BEGIN
                SELECT CASE WHEN NEW.scope_label != trim(NEW.scope_label)
                    OR length(NEW.scope_label) < 1
                THEN RAISE(ABORT, 'scan scope label must be canonical text') END;
                SELECT CASE WHEN datetime(NEW.recorded_at) IS NULL
                    OR NEW.recorded_at != strftime(
                        '%Y-%m-%dT%H:%M:%S+00:00', NEW.recorded_at
                    )
                THEN RAISE(ABORT, 'scan scope time must be canonical UTC') END;
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM network_scopes scope
                    JOIN scan_runs run ON run.run_id = NEW.run_id
                    WHERE scope.scope_id = NEW.scope_id
                      AND scope.active = 1
                      AND json_extract(
                        run.manifest_json, '$.network_scope_context.scope_id'
                      ) = NEW.scope_id
                      AND json_extract(
                        run.manifest_json, '$.network_scope_context.scope_label'
                      ) = NEW.scope_label
                      AND json_extract(
                        run.manifest_json, '$.network_scope_context.scope_version'
                      ) = NEW.scope_version
                      AND json_extract(
                        run.manifest_json, '$.network_scope_context.recorded_at'
                      ) = NEW.recorded_at
                      AND (
                        (scope.label = NEW.scope_label
                         AND scope.version = NEW.scope_version)
                        OR EXISTS (
                            SELECT 1
                            FROM scan_runs run
                            JOIN scan_schedule_scope_contexts scheduled
                              ON scheduled.schedule_id = json_extract(
                                run.manifest_json, '$.schedule_id'
                              )
                            WHERE run.run_id = NEW.run_id
                              AND scheduled.scope_id = NEW.scope_id
                              AND scheduled.scope_label = NEW.scope_label
                              AND scheduled.scope_version = NEW.scope_version
                              AND scheduled.recorded_at = NEW.recorded_at
                        )
                      )
                ) THEN RAISE(ABORT, 'scan scope snapshot is not authoritative') END;
            END;
CREATE TRIGGER scan_run_scope_source_validate_insert
            BEFORE INSERT ON scan_run_scope_sources
            BEGIN
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM saved_network_scope_associations association
                    JOIN scan_run_scope_contexts context
                      ON context.run_id = NEW.run_id
                    WHERE association.association_id = NEW.association_id
                      AND association.saved_network_id = NEW.saved_network_id
                      AND association.revision = NEW.association_revision
                      AND association.scope_id = context.scope_id
                      AND (
                        NOT EXISTS (
                            SELECT 1
                            FROM saved_network_scope_associations successor
                            WHERE successor.predecessor_id = association.association_id
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM scan_runs run
                            JOIN scan_schedule_scope_sources scheduled_source
                              ON scheduled_source.schedule_id = json_extract(
                                run.manifest_json, '$.schedule_id'
                              )
                            WHERE run.run_id = NEW.run_id
                              AND scheduled_source.saved_network_id = NEW.saved_network_id
                              AND scheduled_source.association_id = NEW.association_id
                              AND scheduled_source.association_revision = NEW.association_revision
                        )
                      )
                ) THEN RAISE(ABORT, 'scan scope source does not match its association') END;
            END;
CREATE TRIGGER scan_schedule_scope_context_validate_insert
            BEFORE INSERT ON scan_schedule_scope_contexts
            BEGIN
                SELECT CASE WHEN NEW.scope_label != trim(NEW.scope_label)
                    OR length(NEW.scope_label) < 1
                THEN RAISE(ABORT, 'schedule scope label must be canonical text') END;
                SELECT CASE WHEN datetime(NEW.recorded_at) IS NULL
                    OR NEW.recorded_at != strftime(
                        '%Y-%m-%dT%H:%M:%S+00:00', NEW.recorded_at
                    )
                THEN RAISE(ABORT, 'schedule scope time must be canonical UTC') END;
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM network_scopes scope
                    JOIN scan_schedules schedule
                      ON schedule.schedule_id = NEW.schedule_id
                    WHERE scope.scope_id = NEW.scope_id
                      AND scope.active = 1
                      AND scope.label = NEW.scope_label
                      AND scope.version = NEW.scope_version
                      AND json_extract(
                        schedule.definition_json,
                        '$.network_scope_context.scope_id'
                      ) = NEW.scope_id
                      AND json_extract(
                        schedule.definition_json,
                        '$.network_scope_context.scope_label'
                      ) = NEW.scope_label
                      AND json_extract(
                        schedule.definition_json,
                        '$.network_scope_context.scope_version'
                      ) = NEW.scope_version
                      AND json_extract(
                        schedule.definition_json,
                        '$.network_scope_context.recorded_at'
                      ) = NEW.recorded_at
                ) THEN RAISE(ABORT, 'schedule scope snapshot is not authoritative') END;
            END;
CREATE TRIGGER scan_schedule_scope_source_validate_insert
            BEFORE INSERT ON scan_schedule_scope_sources
            BEGIN
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM saved_network_scope_associations association
                    JOIN scan_schedule_scope_contexts context
                      ON context.schedule_id = NEW.schedule_id
                    WHERE association.association_id = NEW.association_id
                      AND association.saved_network_id = NEW.saved_network_id
                      AND association.revision = NEW.association_revision
                      AND association.scope_id = context.scope_id
                      AND NOT EXISTS (
                        SELECT 1
                        FROM saved_network_scope_associations successor
                        WHERE successor.predecessor_id = association.association_id
                      )
                ) THEN RAISE(ABORT, 'schedule scope source does not match its association') END;
            END;
CREATE TRIGGER artifact_scope_context_validate_insert
            BEFORE INSERT ON artifact_observation_scope_contexts
            BEGIN
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM scan_run_scope_contexts context
                    JOIN artifact_observations observation
                      ON observation.observation_id = NEW.observation_id
                    WHERE context.run_id = NEW.run_id
                      AND observation.source_ref = NEW.run_id
                      AND context.scope_id = NEW.scope_id
                      AND context.scope_label = NEW.scope_label
                      AND context.scope_version = NEW.scope_version
                      AND context.recorded_at = NEW.recorded_at
                ) THEN RAISE(ABORT, 'artifact scope snapshot does not match its scan run') END;
            END;
CREATE TRIGGER scan_run_scope_context_no_update
                BEFORE UPDATE ON scan_run_scope_contexts
                BEGIN SELECT RAISE(ABORT, 'scan scope context is immutable'); END;
CREATE TRIGGER scan_run_scope_context_no_delete
                BEFORE DELETE ON scan_run_scope_contexts
                WHEN EXISTS (SELECT 1 FROM scan_runs WHERE run_id = OLD.run_id)
                BEGIN SELECT RAISE(ABORT, 'scan scope context is immutable'); END;
CREATE TRIGGER scan_run_scope_source_no_update
                BEFORE UPDATE ON scan_run_scope_sources
                BEGIN SELECT RAISE(ABORT, 'scan scope sources are immutable'); END;
CREATE TRIGGER scan_run_scope_source_no_delete
                BEFORE DELETE ON scan_run_scope_sources
                WHEN EXISTS (SELECT 1 FROM scan_runs WHERE run_id = OLD.run_id)
                BEGIN SELECT RAISE(ABORT, 'scan scope sources are immutable'); END;
CREATE TRIGGER scan_schedule_scope_context_no_update
                BEFORE UPDATE ON scan_schedule_scope_contexts
                BEGIN SELECT RAISE(ABORT, 'schedule scope context is immutable'); END;
CREATE TRIGGER scan_schedule_scope_context_no_delete
                BEFORE DELETE ON scan_schedule_scope_contexts
                WHEN EXISTS (SELECT 1 FROM scan_schedules WHERE schedule_id = OLD.schedule_id)
                BEGIN SELECT RAISE(ABORT, 'schedule scope context is immutable'); END;
CREATE TRIGGER scan_schedule_scope_source_no_update
                BEFORE UPDATE ON scan_schedule_scope_sources
                BEGIN SELECT RAISE(ABORT, 'schedule scope sources are immutable'); END;
CREATE TRIGGER scan_schedule_scope_source_no_delete
                BEFORE DELETE ON scan_schedule_scope_sources
                WHEN EXISTS (SELECT 1 FROM scan_schedules WHERE schedule_id = OLD.schedule_id)
                BEGIN SELECT RAISE(ABORT, 'schedule scope sources are immutable'); END;
CREATE TRIGGER artifact_scope_context_no_update
                BEFORE UPDATE ON artifact_observation_scope_contexts
                BEGIN SELECT RAISE(ABORT, 'artifact scope context is immutable'); END;
CREATE TRIGGER artifact_scope_context_no_delete
                BEFORE DELETE ON artifact_observation_scope_contexts
                WHEN EXISTS (
                    SELECT 1 FROM artifact_observations
                    WHERE observation_id = OLD.observation_id
                )
                BEGIN SELECT RAISE(ABORT, 'artifact scope context is immutable'); END;
CREATE INDEX device_collections_address_created ON device_collections(device_address, created_at DESC);
CREATE INDEX device_commands_run_classification ON device_command_observations(run_id, classification, position);
CREATE INDEX device_collection_authority_state
                ON device_collection_authority(state, created_at DESC);
CREATE INDEX device_collection_authority_input_observation
                ON device_collection_authority_inputs(artifact_observation_id, run_id);
CREATE TRIGGER device_collection_authority_no_delete
                BEFORE DELETE ON device_collection_authority
                BEGIN SELECT RAISE(ABORT, 'device collection authority is permanent'); END;
CREATE TRIGGER device_collection_authority_no_reactivate
                BEFORE UPDATE ON device_collection_authority
                WHEN OLD.state = 'deleted'
                BEGIN SELECT RAISE(ABORT, 'deleted device collection cannot be reactivated'); END;
CREATE TRIGGER device_collection_authority_identity_immutable
                BEFORE UPDATE ON device_collection_authority
                WHEN OLD.state = 'active' AND (
                    NEW.artifact_observation_id IS NOT OLD.artifact_observation_id
                    OR NEW.artifact_sha256 IS NOT OLD.artifact_sha256
                    OR NEW.retained_filename IS NOT OLD.retained_filename
                    OR NEW.selection_contract IS NOT OLD.selection_contract
                    OR NEW.semantic_manifest_json IS NOT OLD.semantic_manifest_json
                    OR NEW.semantic_manifest_sha256 IS NOT OLD.semantic_manifest_sha256
                )
                BEGIN SELECT RAISE(ABORT, 'active device collection authority is immutable'); END;
CREATE TRIGGER device_collection_authority_legal_transition
                BEFORE UPDATE ON device_collection_authority
                WHEN NOT (
                    (OLD.state = 'preparing' AND NEW.state IN ('active', 'deleted'))
                    OR (OLD.state = 'active' AND NEW.state = 'deleted')
                )
                BEGIN SELECT RAISE(ABORT, 'illegal device collection authority transition'); END;
CREATE TRIGGER device_collection_authority_inputs_no_update
                BEFORE UPDATE ON device_collection_authority_inputs
                BEGIN SELECT RAISE(ABORT, 'device collection authority inputs are immutable'); END;
CREATE TRIGGER device_collection_authority_inputs_no_delete
                BEFORE DELETE ON device_collection_authority_inputs
                BEGIN SELECT RAISE(ABORT, 'device collection authority inputs are permanent'); END;
CREATE INDEX device_evidence_catalog_order
            ON device_evidence_catalog(completed_at DESC, created_at DESC, run_id DESC);
CREATE INDEX device_evidence_catalog_device
            ON device_evidence_catalog(device_key, completed_at DESC, created_at DESC);
CREATE TRIGGER device_evidence_catalog_authority_insert
            AFTER INSERT ON device_collection_authority
            WHEN NEW.state = 'active'
            BEGIN
                INSERT INTO device_evidence_catalog_dirty(run_id, reason)
                VALUES (NEW.run_id, 'authority_insert')
                ON CONFLICT(run_id) DO UPDATE SET
                    reason = excluded.reason,
                    marked_at = CURRENT_TIMESTAMP;
            END;
CREATE TRIGGER device_evidence_catalog_authority_update
            AFTER UPDATE ON device_collection_authority
            WHEN OLD.state = 'active' OR NEW.state = 'active'
            BEGIN
                INSERT INTO device_evidence_catalog_dirty(run_id, reason)
                VALUES (NEW.run_id, 'authority_update')
                ON CONFLICT(run_id) DO UPDATE SET
                    reason = excluded.reason,
                    marked_at = CURRENT_TIMESTAMP;
            END;
CREATE UNIQUE INDEX device_collection_profile_active_name
                ON device_collection_profile_roots(name_key)
                WHERE archived_at IS NULL;
CREATE TRIGGER device_collection_profile_versions_no_update
            BEFORE UPDATE ON device_collection_profile_versions
            BEGIN SELECT RAISE(ABORT, 'device collection profile versions are immutable'); END;
CREATE TRIGGER device_collection_profile_versions_no_delete
            BEFORE DELETE ON device_collection_profile_versions
            BEGIN SELECT RAISE(ABORT, 'device collection profile versions are immutable'); END;
CREATE TRIGGER device_collection_profile_roots_no_delete
            BEFORE DELETE ON device_collection_profile_roots
            BEGIN SELECT RAISE(ABORT, 'device collection profiles must be archived, not deleted'); END;
CREATE TRIGGER device_collection_profile_roots_no_reactivate
            BEFORE UPDATE OF archived_at ON device_collection_profile_roots
            WHEN OLD.archived_at IS NOT NULL AND NEW.archived_at IS NULL
            BEGIN SELECT RAISE(ABORT, 'archived device collection profiles cannot be reactivated'); END;
CREATE TRIGGER device_collection_profile_roots_identity_immutable
            BEFORE UPDATE OF profile_id, created_at, created_by ON device_collection_profile_roots
            BEGIN SELECT RAISE(ABORT, 'device collection profile identity is immutable'); END;
CREATE TRIGGER device_collection_profile_roots_version_forward_only
            BEFORE UPDATE OF active_version ON device_collection_profile_roots
            WHEN NEW.active_version != OLD.active_version + 1
              OR NOT EXISTS (
                  SELECT 1 FROM device_collection_profile_versions v
                  WHERE v.profile_id = OLD.profile_id
                    AND v.version = NEW.active_version
                    AND v.name = NEW.active_name
                    AND v.created_at = NEW.updated_at
                    AND v.created_by = NEW.updated_by
              )
            BEGIN SELECT RAISE(ABORT, 'device collection profile version pointer must advance to its matching immutable version'); END;
CREATE TRIGGER device_collection_profile_roots_metadata_requires_version
            BEFORE UPDATE OF active_name, name_key, updated_at, updated_by
            ON device_collection_profile_roots
            WHEN NEW.active_version = OLD.active_version
              AND NEW.archived_at IS OLD.archived_at
            BEGIN SELECT RAISE(ABORT, 'device collection profile metadata changes require a new version'); END;
CREATE TRIGGER device_collection_profile_roots_archive_once
            BEFORE UPDATE OF archived_at, archived_by ON device_collection_profile_roots
            WHEN OLD.archived_at IS NOT NULL
              OR NEW.archived_at IS NULL OR NEW.archived_by IS NULL
              OR NEW.active_version != OLD.active_version
              OR NEW.active_name != OLD.active_name OR NEW.name_key != OLD.name_key
            BEGIN SELECT RAISE(ABORT, 'device collection profile archive metadata is immutable'); END;
CREATE TRIGGER device_collection_profile_roots_archived_immutable
            BEFORE UPDATE ON device_collection_profile_roots
            WHEN OLD.archived_at IS NOT NULL
            BEGIN SELECT RAISE(ABORT, 'archived device collection profiles are immutable'); END;
CREATE INDEX derived_results_family_generated
                ON derived_results(family, generated_at DESC);
CREATE INDEX derived_result_input_reverse_lookup
                ON derived_result_inputs(
                    input_kind, input_identity, result_id, input_role
                );
CREATE INDEX derived_result_observation_lookup
                ON derived_result_observation_links(observation_id, result_id);
CREATE TRIGGER derived_results_no_update
                BEFORE UPDATE ON derived_results
                BEGIN SELECT RAISE(ABORT, 'derived results are immutable'); END;
CREATE TRIGGER derived_result_inputs_no_update
                BEFORE UPDATE ON derived_result_inputs
                BEGIN SELECT RAISE(ABORT, 'derived result inputs are immutable'); END;
CREATE TRIGGER derived_result_links_no_update
                BEFORE UPDATE ON derived_result_observation_links
                BEGIN SELECT RAISE(ABORT, 'derived result links are immutable'); END;
CREATE UNIQUE INDEX device_scope_assignment_root
                ON device_scope_assignments(run_id, authority_revision)
                WHERE supersedes_assignment_id IS NULL;
CREATE INDEX device_scope_assignment_run
                ON device_scope_assignments(run_id, authority_revision, revision);
CREATE INDEX device_interface_receipts_assessment
                ON device_interface_receipts(assessment_id, source_line_number, receipt_id);
CREATE TRIGGER device_scope_assignments_no_update
                BEFORE UPDATE ON device_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'device scope assignments are immutable'); END;
CREATE TRIGGER device_scope_assignments_no_delete
                BEFORE DELETE ON device_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'device scope assignments are immutable'); END;
CREATE TRIGGER device_scope_assignments_active_scope
                BEFORE INSERT ON device_scope_assignments
                WHEN NOT EXISTS (
                    SELECT 1 FROM network_scopes
                    WHERE scope_id = NEW.scope_id AND active = 1
                )
                BEGIN SELECT RAISE(ABORT, 'device assignment scope is missing or archived'); END;
CREATE TRIGGER device_scope_assignments_valid_root
                BEFORE INSERT ON device_scope_assignments
                WHEN NEW.supersedes_assignment_id IS NULL
                  AND (NEW.revision != 1 OR NEW.event_kind != 'assigned')
                BEGIN SELECT RAISE(ABORT, 'invalid device assignment root'); END;
CREATE TRIGGER device_scope_assignments_valid_successor
                BEFORE INSERT ON device_scope_assignments
                WHEN NEW.supersedes_assignment_id IS NOT NULL AND (
                    NEW.event_kind != 'corrected'
                    OR NOT EXISTS (
                        SELECT 1 FROM device_scope_assignments previous
                        WHERE previous.assignment_id = NEW.supersedes_assignment_id
                          AND previous.run_id = NEW.run_id
                          AND previous.authority_revision = NEW.authority_revision
                          AND previous.revision + 1 = NEW.revision
                          AND previous.scope_id != NEW.scope_id
                    )
                    OR EXISTS (
                        SELECT 1 FROM device_scope_assignments successor
                        WHERE successor.supersedes_assignment_id = NEW.supersedes_assignment_id
                    )
                )
                BEGIN SELECT RAISE(ABORT, 'invalid device assignment successor'); END;
CREATE TRIGGER device_interface_assessments_no_update
                BEFORE UPDATE ON device_interface_assessments
                BEGIN SELECT RAISE(ABORT, 'device interface assessments are immutable'); END;
CREATE TRIGGER device_interface_assessments_no_delete
                BEFORE DELETE ON device_interface_assessments
                BEGIN SELECT RAISE(ABORT, 'device interface assessments are immutable'); END;
CREATE TRIGGER device_interface_receipts_no_update
                BEFORE UPDATE ON device_interface_receipts
                BEGIN SELECT RAISE(ABORT, 'device interface receipts are immutable'); END;
CREATE TRIGGER device_interface_receipts_no_delete
                BEFORE DELETE ON device_interface_receipts
                BEGIN SELECT RAISE(ABORT, 'device interface receipts are immutable'); END;
CREATE TRIGGER pipeline_intake_sources_no_update
                BEFORE UPDATE ON pipeline_intake_sources
                BEGIN SELECT RAISE(ABORT, 'pipeline intake source markers are immutable'); END;
CREATE TRIGGER pipeline_intake_sources_no_delete
                BEFORE DELETE ON pipeline_intake_sources
                BEGIN SELECT RAISE(ABORT, 'pipeline intake source markers are immutable'); END;
CREATE INDEX pipeline_admission_intents_state
               ON pipeline_admission_intents(state, created_at, intent_id);
CREATE TRIGGER pipeline_admission_intents_identity_immutable
               BEFORE UPDATE ON pipeline_admission_intents
               WHEN OLD.intent_kind != NEW.intent_kind
                 OR OLD.source_kind != NEW.source_kind
                 OR OLD.source_id != NEW.source_id
                 OR OLD.policy_version != NEW.policy_version
                 OR IFNULL(OLD.observation_id, '') != IFNULL(NEW.observation_id, '')
                 OR IFNULL(OLD.assignment_id, '') != IFNULL(NEW.assignment_id, '')
                 OR IFNULL(OLD.scope_id, '') != IFNULL(NEW.scope_id, '')
                 OR OLD.actor != NEW.actor
                 OR OLD.request_token != NEW.request_token
                 OR OLD.contract_json != NEW.contract_json
                 OR OLD.created_at != NEW.created_at
               BEGIN SELECT RAISE(ABORT, 'pipeline admission intent identity is immutable'); END;
CREATE TRIGGER pipeline_admission_intents_state_guard
               BEFORE UPDATE ON pipeline_admission_intents
               WHEN OLD.state != NEW.state
                AND NOT (
                   OLD.state = 'pending'
                   AND NEW.state IN ('admitted', 'blocked')
                )
               BEGIN SELECT RAISE(ABORT, 'invalid pipeline admission transition'); END;
CREATE TRIGGER pipeline_admission_intents_no_delete
               BEFORE DELETE ON pipeline_admission_intents
               BEGIN SELECT RAISE(ABORT, 'pipeline admission intents are retained'); END;
CREATE INDEX device_vlan_assessments_scope
            ON device_vlan_assessments(scope_id, recorded_at, assessment_id);
CREATE INDEX device_vlan_assessments_version
            ON device_vlan_assessments(
                assignment_id, extractor_version, collection_contract,
                recorded_at DESC, assessment_id DESC
            );
CREATE INDEX device_vlan_receipts_assessment
            ON device_vlan_receipts(
                assessment_id, vlan_id, source_line_number, receipt_id
            );
CREATE TRIGGER device_vlan_assessments_no_update
            BEFORE UPDATE ON device_vlan_assessments
            BEGIN SELECT RAISE(ABORT, 'device VLAN assessments are immutable'); END;
CREATE TRIGGER device_vlan_assessments_no_delete
            BEFORE DELETE ON device_vlan_assessments
            BEGIN SELECT RAISE(ABORT, 'device VLAN assessments are immutable'); END;
CREATE TRIGGER device_vlan_receipts_no_update
            BEFORE UPDATE ON device_vlan_receipts
            BEGIN SELECT RAISE(ABORT, 'device VLAN receipts are immutable'); END;
CREATE TRIGGER device_vlan_receipts_no_delete
            BEFORE DELETE ON device_vlan_receipts
            BEGIN SELECT RAISE(ABORT, 'device VLAN receipts are immutable'); END;
CREATE INDEX device_vlan_admission_intents_state
            ON device_vlan_admission_intents(state, created_at, intent_id);
CREATE TRIGGER device_vlan_admission_intents_identity_immutable
            BEFORE UPDATE ON device_vlan_admission_intents
            WHEN OLD.assignment_id != NEW.assignment_id
              OR OLD.policy_version != NEW.policy_version
              OR OLD.source_observation_id != NEW.source_observation_id
              OR OLD.scope_id != NEW.scope_id
              OR OLD.actor != NEW.actor
              OR OLD.request_token != NEW.request_token
              OR OLD.contract_json != NEW.contract_json
              OR OLD.created_at != NEW.created_at
              OR (OLD.admitted_job_id IS NOT NULL
                  AND IFNULL(NEW.admitted_job_id, '') != OLD.admitted_job_id)
            BEGIN SELECT RAISE(ABORT, 'device VLAN admission identity is immutable'); END;
CREATE TRIGGER device_vlan_admission_intents_state_guard
            BEFORE UPDATE ON device_vlan_admission_intents
            WHEN OLD.state != NEW.state
             AND NOT (OLD.state = 'pending' AND NEW.state IN ('admitted', 'blocked'))
            BEGIN SELECT RAISE(ABORT, 'invalid device VLAN admission transition'); END;
CREATE TRIGGER device_vlan_admission_intents_no_delete
            BEFORE DELETE ON device_vlan_admission_intents
            BEGIN SELECT RAISE(ABORT, 'device VLAN admission intents are retained'); END;
CREATE INDEX device_contact_run_state
                ON device_contact_runs(state, created_at, run_id);
CREATE INDEX device_contact_control_history
                ON device_contact_controls(run_id, requested_at, control_id);
CREATE TRIGGER device_contact_run_plan_immutable
            BEFORE UPDATE OF operation_kind, subject_key, request_json,
                request_digest, created_at, created_by
            ON device_contact_runs
            BEGIN
                SELECT RAISE(ABORT, 'Device contact run plan is immutable');
            END;
CREATE TRIGGER device_contact_attempt_binding_immutable
            BEFORE UPDATE OF run_id, attempt_number, owner_id, run_lease_key,
                run_lease_id, run_lease_epoch, capacity_lease_key,
                capacity_lease_id, capacity_lease_epoch, started_at
            ON device_contact_attempts
            BEGIN
                SELECT RAISE(ABORT, 'Device contact attempt binding is immutable');
            END;
CREATE UNIQUE INDEX pipeline_job_one_active_attempt
                ON pipeline_job_attempts(job_id)
                WHERE state IN ('queued', 'running');
CREATE INDEX pipeline_job_attempt_queue
                ON pipeline_job_attempts(state, requested_at, attempt_id);
CREATE INDEX pipeline_job_run_lookup
                ON pipeline_jobs(source_run_id, requested_at DESC);
CREATE INDEX pipeline_job_type_run_lookup
                ON pipeline_jobs(
                    job_type, source_run_id, requested_at DESC, job_id DESC
                );
CREATE INDEX pipeline_job_source_lookup
                ON pipeline_jobs(source_kind, source_ref, requested_at DESC);
CREATE INDEX analyst_notes_owner_parent
               ON analyst_investigation_notes(owner, parent_id, position);
CREATE INDEX analyst_notes_parent
               ON analyst_investigation_notes(parent_id);
CREATE INDEX analyst_filter_presets_owner_page
               ON analyst_filter_presets(owner, page, lower(name));
CREATE TRIGGER network_semantics_wan_insert
               AFTER INSERT ON network_semantics
               BEGIN
                   DELETE FROM network_wan_interfaces WHERE role = NEW.role;
               END;
CREATE TRIGGER network_semantics_wan_update
               AFTER UPDATE OF node_id, interface_name ON network_semantics
               BEGIN
                   DELETE FROM network_wan_interfaces WHERE role = NEW.role;
               END;
CREATE TRIGGER network_semantics_wan_delete
               AFTER DELETE ON network_semantics
               BEGIN
                   DELETE FROM network_wan_interfaces WHERE role = OLD.role;
               END;
CREATE INDEX endpoint_receipts_host ON endpoint_receipts(host_id);
CREATE INDEX service_receipts_service ON service_receipts(service_id);
CREATE TRIGGER entity_assessments_active_scope
                BEFORE INSERT ON entity_assessments
                WHEN NOT EXISTS (
                    SELECT 1 FROM network_scopes
                    WHERE scope_id = NEW.scope_id AND active = 1
                )
                BEGIN SELECT RAISE(ABORT, 'network scope is missing or archived'); END;
CREATE TRIGGER entity_assessments_scope_immutable
                BEFORE UPDATE OF scope_id ON entity_assessments
                BEGIN SELECT RAISE(ABORT, 'assessment scope is immutable'); END;
CREATE TRIGGER endpoint_entities_scope_immutable
                BEFORE UPDATE OF scope_id ON endpoint_entities
                BEGIN SELECT RAISE(ABORT, 'endpoint scope is immutable'); END;
CREATE TRIGGER endpoint_entities_active_scope
                BEFORE INSERT ON endpoint_entities
                WHEN NOT EXISTS (
                    SELECT 1 FROM network_scopes
                    WHERE scope_id = NEW.scope_id AND active = 1
                )
                BEGIN SELECT RAISE(ABORT, 'network scope is missing or archived'); END;
CREATE TRIGGER endpoint_entities_no_update
                BEFORE UPDATE ON endpoint_entities
                BEGIN SELECT RAISE(ABORT, 'endpoint entities are immutable'); END;
CREATE TRIGGER endpoint_entities_no_delete
                BEFORE DELETE ON endpoint_entities
                BEGIN SELECT RAISE(ABORT, 'endpoint entities are immutable'); END;
CREATE TRIGGER service_entities_no_update
                BEFORE UPDATE ON service_entities
                BEGIN SELECT RAISE(ABORT, 'service entities are immutable'); END;
CREATE TRIGGER service_entities_no_delete
                BEFORE DELETE ON service_entities
                BEGIN SELECT RAISE(ABORT, 'service entities are immutable'); END;
CREATE TRIGGER entity_assessments_no_update
                BEFORE UPDATE ON entity_assessments
                BEGIN SELECT RAISE(ABORT, 'entity assessments are immutable'); END;
CREATE TRIGGER entity_assessments_no_delete
                BEFORE DELETE ON entity_assessments
                BEGIN SELECT RAISE(ABORT, 'entity assessments are immutable'); END;
CREATE TRIGGER endpoint_receipts_no_update
                BEFORE UPDATE ON endpoint_receipts
                BEGIN SELECT RAISE(ABORT, 'endpoint receipts are immutable'); END;
CREATE TRIGGER endpoint_receipts_no_delete
                BEFORE DELETE ON endpoint_receipts
                BEGIN SELECT RAISE(ABORT, 'endpoint receipts are immutable'); END;
CREATE TRIGGER service_receipts_no_update
                BEFORE UPDATE ON service_receipts
                BEGIN SELECT RAISE(ABORT, 'service receipts are immutable'); END;
CREATE TRIGGER service_receipts_no_delete
                BEFORE DELETE ON service_receipts
                BEGIN SELECT RAISE(ABORT, 'service receipts are immutable'); END;
CREATE UNIQUE INDEX artifact_scope_assignment_root
                ON artifact_scope_assignments(artifact_observation_id)
                WHERE supersedes_assignment_id IS NULL;
CREATE INDEX artifact_scope_assignment_observation
                ON artifact_scope_assignments(artifact_observation_id, revision);
CREATE TRIGGER artifact_scope_assignments_no_update
                BEFORE UPDATE ON artifact_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'artifact scope assignments are immutable'); END;
CREATE TRIGGER artifact_scope_assignments_no_delete
                BEFORE DELETE ON artifact_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'artifact scope assignments are immutable'); END;
CREATE TRIGGER artifact_scope_assignments_active_scope
                BEFORE INSERT ON artifact_scope_assignments
                WHEN NOT EXISTS (
                    SELECT 1 FROM network_scopes
                    WHERE scope_id = NEW.scope_id AND active = 1
                )
                BEGIN SELECT RAISE(ABORT, 'assignment scope is missing or archived'); END;
CREATE TRIGGER artifact_scope_assignments_valid_root
                BEFORE INSERT ON artifact_scope_assignments
                WHEN NEW.supersedes_assignment_id IS NULL
                     AND (NEW.revision != 1 OR NEW.event_kind != 'assigned')
                BEGIN SELECT RAISE(ABORT, 'invalid assignment root'); END;
CREATE TRIGGER artifact_scope_assignments_valid_successor
                BEFORE INSERT ON artifact_scope_assignments
                WHEN NEW.supersedes_assignment_id IS NOT NULL AND (
                    NEW.event_kind != 'corrected'
                    OR NOT EXISTS (
                        SELECT 1 FROM artifact_scope_assignments previous
                        WHERE previous.assignment_id = NEW.supersedes_assignment_id
                          AND previous.artifact_observation_id = NEW.artifact_observation_id
                          AND previous.revision + 1 = NEW.revision
                          AND previous.scope_id != NEW.scope_id
                    )
                    OR EXISTS (
                        SELECT 1 FROM artifact_scope_assignments successor
                        WHERE successor.supersedes_assignment_id = NEW.supersedes_assignment_id
                    )
                )
                BEGIN SELECT RAISE(ABORT, 'invalid assignment successor'); END;
CREATE TRIGGER artifact_scope_assignments_no_legacy_root
                BEFORE INSERT ON artifact_scope_assignments
                WHEN NEW.supersedes_assignment_id IS NULL AND EXISTS (
                    SELECT 1 FROM entity_assessments
                    WHERE artifact_observation_id = NEW.artifact_observation_id
                )
                BEGIN SELECT RAISE(ABORT, 'legacy assessment requires reconciliation'); END;
CREATE TRIGGER assessment_scope_assignment_links_match
                BEFORE INSERT ON assessment_scope_assignment_links
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM artifact_scope_assignments assignment
                    JOIN entity_assessments assessment
                      ON assessment.assessment_id = NEW.assessment_id
                    WHERE assignment.assignment_id = NEW.assignment_id
                      AND assignment.artifact_observation_id = assessment.artifact_observation_id
                      AND assignment.scope_id = assessment.scope_id
                )
                BEGIN SELECT RAISE(ABORT, 'assignment and assessment do not match'); END;
CREATE TRIGGER assessment_scope_assignment_links_current_active
                BEFORE INSERT ON assessment_scope_assignment_links
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM artifact_scope_assignments assignment
                    JOIN network_scopes scope ON scope.scope_id = assignment.scope_id
                    WHERE assignment.assignment_id = NEW.assignment_id
                      AND scope.active = 1
                      AND NOT EXISTS (
                          SELECT 1 FROM artifact_scope_assignments successor
                          WHERE successor.supersedes_assignment_id = assignment.assignment_id
                      )
                )
                BEGIN SELECT RAISE(ABORT, 'assignment is stale or scope is archived'); END;
CREATE TRIGGER assessment_scope_assignment_links_no_update
                BEFORE UPDATE ON assessment_scope_assignment_links
                BEGIN SELECT RAISE(ABORT, 'assessment assignment links are immutable'); END;
CREATE TRIGGER assessment_scope_assignment_links_no_delete
                BEFORE DELETE ON assessment_scope_assignment_links
                BEGIN SELECT RAISE(ABORT, 'assessment assignment links are immutable'); END;
CREATE INDEX scan_foundation_attempt_run
                ON scan_foundation_processing_attempts(run_id, started_at DESC);
CREATE TRIGGER scan_inherited_scope_assignment_validate
            BEFORE INSERT ON scan_inherited_scope_assignments
            WHEN NOT EXISTS (
                SELECT 1
                FROM artifact_scope_assignments assignment
                JOIN artifact_observations observation
                  ON observation.observation_id = NEW.observation_id
                JOIN artifact_observation_scope_contexts artifact_context
                  ON artifact_context.observation_id = NEW.observation_id
                JOIN scan_run_scope_contexts run_context
                  ON run_context.run_id = NEW.run_id
                JOIN scan_runs run ON run.run_id = NEW.run_id
                WHERE assignment.assignment_id = NEW.assignment_id
                  AND assignment.artifact_observation_id = NEW.observation_id
                  AND assignment.scope_id = NEW.scope_id
                  AND assignment.revision = 1
                  AND assignment.event_kind = 'assigned'
                  AND assignment.supersedes_assignment_id IS NULL
                  AND observation.source_kind = 'nmap_scan'
                  AND observation.source_ref = NEW.run_id
                  AND observation.original_filename = 'scan.xml'
                  AND artifact_context.run_id = NEW.run_id
                  AND artifact_context.scope_id = NEW.scope_id
                  AND run_context.scope_id = NEW.scope_id
                  AND run.status = 'completed'
            )
            BEGIN SELECT RAISE(ABORT, 'inherited scan assignment is not authoritative'); END;
CREATE TRIGGER scan_inherited_scope_assignment_no_update
                BEFORE UPDATE ON scan_inherited_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'inherited scan assignment is immutable'); END;
CREATE TRIGGER scan_inherited_scope_assignment_no_delete
                BEFORE DELETE ON scan_inherited_scope_assignments
                BEGIN SELECT RAISE(ABORT, 'inherited scan assignment is immutable'); END;
CREATE TRIGGER scan_foundation_attempt_no_insert
                BEFORE INSERT ON scan_foundation_processing_attempts
                BEGIN SELECT RAISE(ABORT, 'legacy scan processing history is read-only'); END;
CREATE TRIGGER scan_foundation_attempt_no_update
                BEFORE UPDATE ON scan_foundation_processing_attempts
                BEGIN SELECT RAISE(ABORT, 'legacy scan processing history is read-only'); END;
CREATE TRIGGER scan_foundation_attempt_no_delete
                BEFORE DELETE ON scan_foundation_processing_attempts
                BEGIN SELECT RAISE(ABORT, 'legacy scan processing history is read-only'); END;
CREATE TRIGGER automated_nmap_scope_correction_no_update
                BEFORE UPDATE ON automated_nmap_scope_corrections
                BEGIN SELECT RAISE(ABORT, 'automated Nmap scope corrections are append-only'); END;
CREATE TRIGGER automated_nmap_scope_correction_no_delete
                BEFORE DELETE ON automated_nmap_scope_corrections
                BEGIN SELECT RAISE(ABORT, 'automated Nmap scope corrections are append-only'); END;
CREATE INDEX searchsploit_query_cache_updated ON searchsploit_query_cache(updated_at);
DELETE FROM "sqlite_sequence";
COMMIT;
