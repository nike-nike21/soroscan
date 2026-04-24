"""
Migration for #280 GDPR data governance (AuditLog, DataDeletionRequest, PIIField)
and #284 contract deployment tracking (ContractDeployment).
"""
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("ingest", "0032_apikey_team_alter_contractmetadata_id_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # ------------------------------------------------------------------ #
        # AuditLog                                                             #
        # ------------------------------------------------------------------ #
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("action", models.CharField(choices=[("create", "Create"), ("update", "Update"), ("delete", "Delete")], db_index=True, max_length=16)),
                ("model_name", models.CharField(db_index=True, max_length=64)),
                ("object_id", models.CharField(db_index=True, max_length=255)),
                ("changes", models.JSONField(default=dict, help_text="Before/after snapshot of changed fields")),
                ("ip_address", models.GenericIPAddressField(default="0.0.0.0")),
                ("timestamp", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="audit_logs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ["-timestamp"]},
        ),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(fields=["model_name", "object_id"], name="ingest_audi_model_n_idx"),
        ),
        migrations.AddIndex(
            model_name="auditlog",
            index=models.Index(fields=["user", "timestamp"], name="ingest_audi_user_ts_idx"),
        ),
        # ------------------------------------------------------------------ #
        # DataDeletionRequest                                                  #
        # ------------------------------------------------------------------ #
        migrations.CreateModel(
            name="DataDeletionRequest",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("subject_email", models.EmailField(blank=True, help_text="Email of the data subject (used when subject_user is unknown)")),
                ("status", models.CharField(choices=[("pending", "Pending"), ("processing", "Processing"), ("completed", "Completed"), ("failed", "Failed")], db_index=True, default="pending", max_length=16)),
                ("reason", models.TextField(blank=True, help_text="Reason for the deletion request")),
                ("deleted_records", models.JSONField(default=dict, help_text="Summary of deleted records per model after processing")),
                ("error_detail", models.TextField(blank=True)),
                ("requested_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "requester",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="deletion_requests_made",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "subject_user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="deletion_requests_received",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ["-requested_at"]},
        ),
        # ------------------------------------------------------------------ #
        # PIIField                                                             #
        # ------------------------------------------------------------------ #
        migrations.CreateModel(
            name="PIIField",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("event_type", models.CharField(blank=True, help_text="Event type this field applies to (blank = all event types)", max_length=128)),
                ("field_path", models.CharField(help_text="Dot-notation path into the event payload, e.g. 'user.email'", max_length=256)),
                ("description", models.CharField(blank=True, max_length=256)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "contract",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="pii_fields",
                        to="ingest.trackedcontract",
                    ),
                ),
            ],
            options={"ordering": ["contract", "event_type", "field_path"]},
        ),
        migrations.AddConstraint(
            model_name="piifield",
            constraint=models.UniqueConstraint(fields=["contract", "event_type", "field_path"], name="unique_pii_contract_event_field"),
        ),
        # ------------------------------------------------------------------ #
        # ContractDeployment                                                   #
        # ------------------------------------------------------------------ #
        migrations.CreateModel(
            name="ContractDeployment",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("bytecode_hash", models.CharField(db_index=True, help_text="SHA-256 hash of the deployed WASM bytecode", max_length=64)),
                ("ledger_deployed", models.PositiveBigIntegerField(db_index=True, help_text="Ledger sequence at which this deployment was confirmed")),
                ("deployer_address", models.CharField(db_index=True, help_text="Stellar account address (G…) that deployed the contract", max_length=56)),
                ("is_upgrade", models.BooleanField(db_index=True, default=False, help_text="True when this deployment replaces a previous bytecode hash")),
                ("abi_version", models.CharField(blank=True, help_text="Optional semantic version tag for the ABI at this deployment", max_length=64)),
                ("abi_snapshot", models.JSONField(blank=True, help_text="ABI JSON captured at deployment time for historical reference", null=True)),
                ("abi_compatible", models.BooleanField(blank=True, help_text="True if ABI is backward-compatible with the previous deployment; null if unknown", null=True)),
                ("compatibility_warnings", models.JSONField(blank=True, default=list, help_text="List of ABI incompatibility warning strings")),
                ("tx_hash", models.CharField(blank=True, help_text="Transaction hash of the deployment transaction", max_length=64)),
                ("deployed_at", models.DateTimeField(db_index=True, help_text="Timestamp of the deployment")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "contract",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="deployments",
                        to="ingest.trackedcontract",
                    ),
                ),
            ],
            options={"ordering": ["-ledger_deployed"]},
        ),
        migrations.AddIndex(
            model_name="contractdeployment",
            index=models.Index(fields=["contract", "ledger_deployed"], name="ingest_cd_contract_ledger_idx"),
        ),
        migrations.AddIndex(
            model_name="contractdeployment",
            index=models.Index(fields=["bytecode_hash"], name="ingest_cd_bytecode_idx"),
        ),
        migrations.AddIndex(
            model_name="contractdeployment",
            index=models.Index(fields=["is_upgrade"], name="ingest_cd_is_upgrade_idx"),
        ),
        migrations.AddConstraint(
            model_name="contractdeployment",
            constraint=models.UniqueConstraint(
                fields=["contract", "ledger_deployed", "bytecode_hash"],
                name="unique_contract_ledger_bytecode",
            ),
        ),
    ]
