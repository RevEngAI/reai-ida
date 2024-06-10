# -*- coding: utf-8 -*-
from __future__ import annotations

from requests import get, post, Response

from reait.api import reveng_req, re_binary_id


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

    res: Response = reveng_req(get, "v1/search", json_data={"sha_256_hash": bin_id})

    res.raise_for_status()
    return res


def RE_collection_search(search: str) -> Response:
    res: Response = reveng_req(get, f"v1/collections/quick/search",
                               params={"search_term": search if search else ""})

    res.raise_for_status()
    return res


def RE_recent_analysis(status: str = "All", scope: str = "ALL", nb_analysis: int = 50) -> Response:
    res: Response = reveng_req(get, "v1/analyse/recent",
                               json_data={"status": status,
                                          "scope": scope,
                                          "n": nb_analysis})

    res.raise_for_status()
    return res


def RE_functions_dump(function_ids: list[int]) -> Response:
    res: Response = reveng_req(get, "v1/functions/dump", json_data={"function_id_list": function_ids})

    res.raise_for_status()
    return res
