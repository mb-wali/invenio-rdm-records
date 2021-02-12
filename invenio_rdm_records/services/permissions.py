# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
# Copyright (C) 2021 Graz University of Technology.
#
# Invenio-RDM-Records is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""Permissions for Invenio RDM Records."""

from invenio_drafts_resources.services.records.permissions import \
    RecordDraftPermissionPolicy
from invenio_records_permissions.generators import AnyUser, \
    AuthenticatedUser, Disable


class RDMRecordPermissionPolicy(RecordDraftPermissionPolicy):
    """Access control configuration for records.

    Note that even if the array is empty, the invenio_access Permission class
    always adds the ``superuser-access``, so admins will always be allowed.

    - Create action given to everyone for now.
    - Read access given to everyone if public record and given to owners
      always. (inherited)
    - Update access given to record owners. (inherited)
    - Delete access given to admins only. (inherited)
    """

    # State Publish
    can_search = [AnyUser()]
    can_create = [AuthenticatedUser()]
    can_update = [Disable()]
    can_delete = [Disable()]
    can_publish = [AnyUser()]
    can_read = [AnyUser()]
    can_read_update_files = [AnyUser()]
    can_manage = [AnyUser()]
    can_update_files = [AnyUser()]

    # State Draft
    can_update_draft = [AnyUser()]
    can_delete_draft = [AnyUser()]
    can_read_draft = [AnyUser()]
    can_read_draft_files = [AnyUser()]

    # ?
    can_read_files = [AnyUser()]
