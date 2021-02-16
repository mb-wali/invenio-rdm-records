# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Graz University of Technology.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Permissions for Invenio RDM Records."""

from invenio_access.permissions import any_user, authenticated_user
from invenio_drafts_resources.services.records.permissions import \
    RecordDraftPermissionPolicy

# TODO: import some existing generators from invenio-rdm-records
from invenio_records_permissions.generators import AnyUser, \
    AuthenticatedUser, Disable, IfRestricted


class TestRDMPermissionPolicy(RecordDraftPermissionPolicy):
    """Define permission policies for RDM Records."""
    can_search = [AnyUser()]
    can_create = [AuthenticatedUser()]
    can_update = [Disable()]
    can_delete = [Disable()]
    can_read = [IfRestricted('files',
                             then_=[AuthenticatedUser()], else_=[AnyUser()])]


def test_permission_policy_generators(app, anyuser_identity,
                                      authenticated_identity,
                                      superuser_identity, minimal_record):
    """Test permission policies with given Identities."""
    policy = TestRDMPermissionPolicy

    # files = "restricted"
    minimal_record["access"]["files"] = "restricted"
    # record = "public"
    minimal_record["access"]["record"] = "public"

    assert policy(action='search').allows(anyuser_identity)
    assert policy(action='create').allows(authenticated_identity)
    assert policy(action='read').generators[0].needs(record=minimal_record
                                                     ) == [authenticated_user]


def test_permission_policy_needs_excludes(superuser_role_need):
    """Test permission policy excluding 'superuser_role_need'."""
    search_perm = TestRDMPermissionPolicy(action='search')
    create_perm = TestRDMPermissionPolicy(action='create')
    update_perm = TestRDMPermissionPolicy(action='update')
    delete_perm = TestRDMPermissionPolicy(action='delete')

    assert search_perm.needs == {superuser_role_need, any_user}
    assert search_perm.excludes == set()

    assert create_perm.needs == {superuser_role_need, authenticated_user}
    assert create_perm.excludes == set()

    assert update_perm.needs == {superuser_role_need}
    assert update_perm.excludes == {any_user}

    assert delete_perm.needs == {superuser_role_need}
    assert delete_perm.excludes == {any_user}
