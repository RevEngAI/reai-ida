# -*- coding: utf-8 -*-

from __future__ import annotations

from requests import post, Response, get

from reait.api import reveng_req, re_binary_id, re_bid_search


def RE_collections(scope: str = "PUBLIC", page_size: int = 100000, page_number: int = 1) -> Response:
    res: Response = reveng_req(post, "collections",
                               json_data={"scope": scope,
                                          "page_size": page_size,
                                          "page_number": page_number})

    res.raise_for_status()
    return res


def RE_analyze_functions(fpath: str, binary_id: int = 0) -> Response | None:
    bin_id = re_binary_id(fpath)
    bid = re_bid_search(bin_id) if binary_id == 0 else binary_id

    if bid == -1:
        return

    res: Response = reveng_req(get, f"analyse/functions/{bid}")

    res.raise_for_status()
    return res


def RE_models() -> Response:
    res: Response = reveng_req(get, "models")

    res.raise_for_status()
    return res


def RE_functions_dump(function_ids: list) -> Response:
    res = reveng_req(post, "functions/dump", json_data={"function_id_list": function_ids})

    res.raise_for_status()
    return res


def RE_explain(pseudo_code: str, language: str) -> Response:
    res: Response = reveng_req(post, "explain", data=pseudo_code, json_data={"language": language})

    res.raise_for_status()
    return res


def RE_search(fpath: str) -> Response:
    bin_id = re_binary_id(fpath)

    res = reveng_req(get, f"search?search=sha_256_hash:{bin_id}&state=All")

    res.raise_for_status()
    return res
