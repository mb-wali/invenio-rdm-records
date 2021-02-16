# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Graz University of Technology.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Pytest configuration.

See https://pytest-invenio.readthedocs.io/ for documentation on which test
fixtures are available.
"""

import pytest
from invenio_access.permissions import any_user, authenticated_user
from invenio_records_permissions.generators import AnyUser, AuthenticatedUser

from invenio_rdm_records.generators import IfRestricted


@pytest.mark.parametrize("field", ['files', 'record'])
def test_ifrestricted(field, minimal_record, mocker):
    # Restricted files, permission level = then_

    # files = "restricted"
    minimal_record["access"]["files"] = "restricted"
    # record = "public"
    minimal_record["access"]["record"] = "public"

    generator = IfRestricted(field=field,
                             then_=[AuthenticatedUser()], else_=[AnyUser()])
    if field in ['files']:
        assert generator.needs(record=minimal_record) == [authenticated_user]
    elif field in ['record']:
        assert generator.needs(record=minimal_record) == [any_user]
    else:
        assert generator.needs(record=record) == []

    # # assert generator.query_filter() == []
    # assert generator.query_filter().to_dict() == {
    #     'term': {"access.files": "restricted"}
    # }

    # Authenticated identity
    query_filter = generator.query_filter(
        identity=mocker.Mock(
            provides=[mocker.Mock(method='id', value=1)]
        )
    )

    assert query_filter.to_dict() == {'term': {'owned_by': 1}}