"""Tests for auth label Merkle commitment (Phase 2C-1)."""

from __future__ import annotations

import pytest

from auth_reference.auth_commitment import (
    AuthLabelLeaf,
    build_auth_merkle_tree,
    compute_auth_leaf,
    open_auth_label,
    verify_auth_opening_plaintext,
)


def _leaf(cid, tenant=1, project=10, level=3, state=1, epoch=7):
    return AuthLabelLeaf(cid, tenant, project, level, state, epoch)


def _tree_from_labels(*labels: AuthLabelLeaf):
    leaf_hashes = [compute_auth_leaf(*lbl.as_list()) for lbl in labels]
    return build_auth_merkle_tree(leaf_hashes)


@pytest.fixture
def four_leaf_tree():
    labels = (
        _leaf(101),
        _leaf(102, level=2),
        _leaf(103, project=11, level=1),
        _leaf(104, tenant=2, level=1),
    )
    root, tree = _tree_from_labels(*labels)
    return labels, root, tree


def test_valid_auth_opening_succeeds(four_leaf_tree):
    labels, root, tree = four_leaf_tree
    path = open_auth_label(0, tree)
    assert verify_auth_opening_plaintext(labels[0], path, root)


def test_forged_tenant_fails(four_leaf_tree):
    labels, root, tree = four_leaf_tree
    path = open_auth_label(0, tree)
    forged = AuthLabelLeaf(101, 99, 10, 3, 1, 7)
    assert labels[0] != forged
    assert not verify_auth_opening_plaintext(forged, path, root)


def test_forged_project_fails(four_leaf_tree):
    _, root, tree = four_leaf_tree
    path = open_auth_label(0, tree)
    forged = AuthLabelLeaf(101, 1, 99, 3, 1, 7)
    assert not verify_auth_opening_plaintext(forged, path, root)


def test_forged_level_state_epoch_fail(four_leaf_tree):
    _, root, tree = four_leaf_tree
    path = open_auth_label(0, tree)
    assert not verify_auth_opening_plaintext(_leaf(101, level=99), path, root)
    assert not verify_auth_opening_plaintext(_leaf(101, state=0), path, root)
    assert not verify_auth_opening_plaintext(_leaf(101, epoch=8), path, root)


def test_forged_cid_fails(four_leaf_tree):
    _, root, tree = four_leaf_tree
    path = open_auth_label(0, tree)
    assert not verify_auth_opening_plaintext(_leaf(999), path, root)


def test_wrong_merkle_path_fails(four_leaf_tree):
    labels, root, tree = four_leaf_tree
    path = open_auth_label(0, tree)
    bad_path = [row[:] for row in path]
    bad_path[0][1] ^= 1
    assert not verify_auth_opening_plaintext(labels[0], bad_path, root)


def test_leaf_field_order_matches_rust():
    """Cross-check one leaf against known Rust test vector field order."""
    h = compute_auth_leaf(101, 1, 10, 3, 1, 7)
    labels = [_leaf(101), _leaf(102, level=2), _leaf(103, project=11, level=1), _leaf(104, tenant=2, level=1)]
    leaf_hashes = [compute_auth_leaf(*lbl.as_list()) for lbl in labels]
    root, tree = build_auth_merkle_tree(leaf_hashes)
    assert leaf_hashes[0] == h
    assert verify_auth_opening_plaintext(labels[0], open_auth_label(0, tree), root)
