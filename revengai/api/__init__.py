# -*- coding: utf-8 -*-
from __future__ import annotations

from requests import get, post, Response

from reait.api import reveng_req, re_binary_id, re_bid_search, ReaitError


def RE_analyze_functions(fpath: str, binary_id: int = 0) -> Response:
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    end_point = f"v1/analyse/functions/{bid}"

    if bid == -1:
        raise ReaitError(f"No matches found for hash: {bin_id}", end_point)

    res: Response = reveng_req(get, end_point)

    res.raise_for_status()
    return res


def RE_models() -> Response:
    res: Response = reveng_req(get, "v1/models")

    res.raise_for_status()
    return res


def RE_functions_dump(function_ids: list[int]) -> Response:
    res: Response = reveng_req(post, "v1/functions/dump", json_data={"function_id_list": function_ids})

    res.raise_for_status()
    return res


def RE_explain(pseudo_code: str, language: str = None) -> Response:
    res: Response = reveng_req(post, "explain", data=pseudo_code,
                               json_data={"language": language} if language else None)

    res.raise_for_status()
    return res


def RE_search(fpath: str) -> Response:
    bin_id = re_binary_id(fpath)

    res: Response = reveng_req(get, "v1/search", json_data={"sha256_hash": bin_id})

    res.raise_for_status()
    return res


def RE_quick_search(model: str) -> Response:
    res: Response = reveng_req(get, f"v1/collections/quick/search", params={"model_name": model})

    res.raise_for_status()
    return res


def RE_recent_analysis(scope: str = "ALL", nb_analysis: int = 100) -> Response:
    res: Response = reveng_req(get, "v1/analyse/recent",
                               json_data={"status": "All",
                                          "scope": scope,
                                          "n": nb_analysis})

    res.raise_for_status()
    return res
