"""
Django signals for automatic audit logging of data mutations.

Connects post_save and post_delete signals for key models so that every
create/update/delete is recorded in AuditLog without modifying each model's
save() method.
"""
import logging
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)

# Models whose mutations should be audit-logged
_AUDITED_MODELS = [
    "TrackedContract",
    "ContractEvent",
    "WebhookSubscription",
    "APIKey",
    "DataDeletionRequest",
    "ContractDeployment",
]


def _write_audit_log(instance, action: str, changes: dict) -> None:
    """Write a single AuditLog entry, silently ignoring errors."""
    try:
        from .models import AuditLog
        AuditLog.objects.create(
            action=action,
            model_name=type(instance).__name__,
            object_id=str(instance.pk),
            changes=changes,
        )
    except Exception:
        logger.exception("Failed to write AuditLog for %s pk=%s", type(instance).__name__, instance.pk)


def _snapshot(instance) -> dict:
    """Return a lightweight field snapshot for the instance."""
    try:
        from django.forms.models import model_to_dict
        data = model_to_dict(instance)
        # Remove non-serialisable values
        return {k: str(v) if not isinstance(v, (str, int, float, bool, type(None), list, dict)) else v
                for k, v in data.items()}
    except Exception:
        return {}


def connect_audit_signals():
    """
    Dynamically connect post_save / post_delete signals for audited models.
    Called from IngestConfig.ready().
    """
    from django.apps import apps

    for model_name in _AUDITED_MODELS:
        try:
            model = apps.get_model("ingest", model_name)
        except LookupError:
            continue

        # post_save: distinguish create vs update via `created` flag
        def make_save_handler(m):
            def _on_save(sender, instance, created, **kwargs):
                action = "create" if created else "update"
                _write_audit_log(instance, action, _snapshot(instance))
            _on_save.__name__ = f"_audit_{m.__name__}_save"
            return _on_save

        # post_delete
        def make_delete_handler(m):
            def _on_delete(sender, instance, **kwargs):
                _write_audit_log(instance, "delete", {"pk": str(instance.pk)})
            _on_delete.__name__ = f"_audit_{m.__name__}_delete"
            return _on_delete

        post_save.connect(make_save_handler(model), sender=model, weak=False)
        post_delete.connect(make_delete_handler(model), sender=model, weak=False)
