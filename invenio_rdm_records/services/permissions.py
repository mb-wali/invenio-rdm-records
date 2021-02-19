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
    AuthenticatedUser, Disable, SystemProcess

from invenio_rdm_records.services.generators import IfRestricted, RecordOwners


class RDMRecordPermissionPolicy(RecordDraftPermissionPolicy):
    """Access control configuration for RDM records.

    Note that even if the array is empty, the invenio_access Permission class
    always adds the ``superuser-access``, so admins will always be allowed.

    - Search action given to everyone.
    - Create action given to Authenticated users/clients.
    - Update action disabled for now.
    - Delete action disabled for now.
    - Read action checks the user record protection.
    - Read files action checks the user files protection.
    - Update files action disabled for now.
    - Read draft action given to Owners.
    - Update draft action given to Owners.
    - Delete draft action given to Owners.
    - Read draft files action given to Owners.
    - Read update files action given to Owners.
    - Publish action given to Owners.
    - Manage action given to Owners.
    """

    can_search = [AnyUser(), SystemProcess()]
    can_create = [AuthenticatedUser(), SystemProcess()]
    can_update = [Disable()]
    can_delete = [Disable()]
    can_read = [
        IfRestricted('record',
                     then_=[RecordOwners()],
                     else_=[AnyUser(), SystemProcess()])
                     ]
    can_read_files = [
        IfRestricted('files',
                     then_=[RecordOwners()],
                     else_=[AnyUser(), SystemProcess()])
                     ]
    can_update_files = [Disable()]
    can_read_draft = [RecordOwners()]
    can_update_draft = [RecordOwners()]
    can_delete_draft = [RecordOwners()]
    can_read_draft_files = [RecordOwners()]
    can_read_update_files = [RecordOwners()]
    can_publish = [RecordOwners()]
    can_manage = [RecordOwners()]
