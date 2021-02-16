# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Graz University of Technology.
#
# Invenio-RDM-Records is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""Invenio-RDM-Records Permissions Generators."""

from elasticsearch_dsl.query import Q
from invenio_access.permissions import any_user, authenticated_user
from invenio_records_permissions.generators import Generator


class IfRestricted(Generator):
    """IfRestricted.

    IfRestricted(
    ‘metadata’,
    RecordPermissionLevel(‘view’),
    ActionNeed(superuser-access),
    )

    A record permission level defines an aggregated set of
    low-level permissions,
    that grants increasing level of permissions to a record.

    """

    def __init__(self, field, then_, else_):
        """Constructor."""
        self.field = field
        self.then_ = then_
        self.else_ = else_

    def needs(self, record=None, **kwargs):
        """Enabling Needs."""
        if not record:
            return []

        is_field_restricted = (
            record and
            record.get('access', {}).get(self.field, "restricted")
        )

        if is_field_restricted == "restricted":
            return getattr(self.then_[0], 'needs')()
        else:
            return getattr(self.else_[0], 'needs')()

        return []

    def query_filter(self, **kwargs):
        """Filters for current identity as super user."""
        then_ = getattr(self.then_[0], 'query_filter')()
        else_ = getattr(self.else_[0], 'query_filter')()
        if is_field_restricted == "restricted":
            return then_
        else:
            return else_
        return []
