# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Graz University of Technology.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Permissions for Invenio RDM Records."""

from elasticsearch_dsl import Q
from invenio_access.permissions import any_user, authenticated_user
from invenio_drafts_resources.services.records.permissions import \
    RecordDraftPermissionPolicy
from invenio_records_permissions.generators import AnyUser, \
    AuthenticatedUser, Disable


class TestRDMPermissionPolicy(RecordDraftPermissionPolicy):
    """Define permission policies for RDM Records."""
    can_search = [AnyUser()]
    can_create = [AuthenticatedUser()]
    can_update = [Disable()]
    can_delete = [Disable()]


def test_permission_policy_generators(app):
    """Test permission policies with given generators."""
    policy = TestRDMPermissionPolicy

    assert isinstance(policy(action='search').generators[0], AnyUser)
    assert isinstance(policy(action='create').generators[0], AuthenticatedUser)
    assert isinstance(policy(action='update').generators[0], Disable)
    assert isinstance(policy(action='delete').generators[0], Disable)


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
