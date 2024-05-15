# -*- coding: utf-8 -*-

from __future__ import annotations

from os.path import basename
from requests import get, post, Response, HTTPError

from reait.api import reveng_req, re_binary_id, re_bid_search


def RE_collections_count(scope: str = "PUBLIC") -> Response:
    res: Response = reveng_req(post, "collections/count", json_data={"scope": scope})

    res.raise_for_status()
    return res


def RE_collections(scope: str = "PUBLIC", page_size: int = 100000, page_number: int = 1) -> Response:
    res: Response = reveng_req(post, "collections",
                               json_data={"scope": scope,
                                          "page_size": page_size,
                                          "page_number": page_number})

    res.raise_for_status()
    return res


def RE_analyze_functions(fpath: str, binary_id: int = 0) -> Response:
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    if bid == -1:
        raise HTTPError(f"No matches found for hash: {bin_id}")

    res: Response = reveng_req(get, f"v1/analyse/functions/{bid}")

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

    res: Response = reveng_req(get, "v1/search",
                               json_data={"sha_256_hash": bin_id,
                                          "binary_name": basename(fpath)})

    res.raise_for_status()
    return res


def RE_quick_search(model: str) -> Response:
    res: Response = reveng_req(get, f"collections/quick/search?model_name={model}")

    res.raise_for_status()
    return res


def RE_recent_analysis(scope: str = "ALL", nb_analysis: int = 100) -> Response:
    res: Response = reveng_req(get, "v1/analyse/recent",
                               json_data={"status": "All",
                                          "scope": scope,
                                          "n": nb_analysis})

    res.raise_for_status()
    return res
