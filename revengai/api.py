import json
import ida_kernwin
from collections.abc import Callable, Iterable, Mapping
import requests
from typing import Dict, Any, Union, List
from revengai.configuration import Configuration
from revengai.logger import plugin_logger
from threading import Thread


class Threader(Thread):
    def __init__(self, target, kwargs=None, args=()) -> None:
        super(Threader, self).__init__(target=target, args=args, kwargs=kwargs)
        self._result = None

    def run(self):
        self._result = self._target(**self._kwargs)

    def get_result(self):
        return self._result


class Endpoint:
    ep = {
        "echo": (lambda: "/echo", requests.get),
        "get_models": (lambda: "/models", requests.get),
        "explain": (lambda: "/explain", requests.post),
        "analyse": (lambda: "/upload", requests.post),
        "status": (lambda sha256hash: f"/analyse/status/{sha256hash}", requests.get),
        "delete": (lambda bin_id: f"/analyse/{bin_id}", requests.delete),
        "collections": (lambda: f"/collections", requests.get),
        "embeddings": (lambda bin_id: f"/embeddings/{bin_id}", requests.get),
        "nearest": (lambda: f"/ ann/symbol", requests.post),
        "getid": (
            lambda sha256hash: f"/search?search=sha_256_hash:{sha256hash}",
            requests.get,
        ),
    }

    cache = {}

    def __init__(self, configuration: Configuration) -> None:
        self._conf = configuration
        self._runner: Threader = None

    def _request(
        self,
        req: requests.request,
        endpoint: str,
        additional_headers: Dict = None,  # HTTP headers
        data: bytes = None,  # POST form-encoded data
        param: Dict = None,  # URL Parameters
    ) -> None:
        """Make a request on another thread to ensure that this call is non-blocking

        Args:
            req (requests.request): _description_
            additional_headers (Dict, optional): _description_. Defaults to None.
            param (_type_, optional): _description_. Defaults to None.
        """
        conf = self._conf.config
        header = {"Authorization": f"{conf['key']}"}
        if additional_headers:
            header.update(additional_headers)
        self._runner = Threader(
            target=req,
            kwargs={
                "url": f"{conf['host']}{endpoint}",
                "headers": header,
                "data": data,
                "params": param,
            },
        )
        self._runner.start()

    def _result(self, timeout: int = 2) -> Any:
        """Gets result from threaded request. By default blocks for 2 seconds, if you want non-blocking pass 0 as timeout.

        Args:
            timeout (int, optional): Timeout to wait for in seconds. Defaults to 2.

        Returns:
            Any: Returns the result or an error if the request timed out.
        """
        if not self._runner.is_alive():
            plugin_logger.info("thread finished")
            return self._runner.get_result()
        else:
            plugin_logger.info("thread still running, waiting...")
            self._runner.join(timeout)
            if self._runner.is_alive():
                plugin_logger.warn("thread timed out")
                return None
            else:
                plugin_logger.info("thread work finished")
                return self._runner.get_result()

    def _error_handle_request(
        self,
        r: requests.request,
        ep: str,
        timeout: int,
        data: Dict = None,
        param: Dict = None,
    ) -> any:
        self._request(r, ep, data=data, param=param)
        res: requests.Response = self._result(timeout)
        if res is not None:
            try:
                plugin_logger.info(f"response {res.content} code {res.status_code}")
                return res.json(), res
            except requests.JSONDecodeError as jde:
                plugin_logger.error(str(jde))
        return None, 0

    def ping(self) -> Union[None, Dict]:
        # TODO - The echo endpoint does not seem to work right now so just ignore it
        # right now this just uses the collections endpoint and checks the status of
        # the request
        return self.collections()

    def upload(
        self, data: bytes, file_name: str
    ) -> Union[None, Dict[str, Union[str, int]]]:
        param = {"file_name": file_name, "model": self._conf.config["current_model"]}
        return self._error_handle_request(
            self.ep["analyse"][1], self.ep["analyse"][0](), data=data, param=param
        )

    def collections(self) -> Union[None, Dict[str, Union[str, int]]]:
        return self._error_handle_request(
            self.ep["collections"][1], self.ep["collections"][0]()
        )

    def delete(self, bin_id) -> Union[None, Dict[str, Union[str, int]]]:
        return self._error_handle_request(
            self.ep["delete"][1],
            self.ep["delete"][0](bin_id),
        )

    def get_symbol_embeddings(
        self,
        bin_id,
    ) -> Union[None, Dict[str, Union[str, int]]]:
        # Returns a list of function embeddings for the binary or 400 ret code
        return self._error_handle_request(
            self.ep["embeddings"][1],
            self.ep["embeddings"][0](bin_id),
        )

    def get_symbol_nearest(
        self,
        hash,
        embeddings,
        nns: int = 5,
        collections: list = None,
        ignore_hashes: list = None,
    ) -> Union[None, Dict[str, Union[str, int]]]:
        params = {
            "nns": nns,
            "model_name": self._conf.config["current_model"],
            "ignore_hashes": [hash],
        }
        if collections:
            params["collections"] = collections
        if ignore_hashes:  # by default we block finding functions in our own binary
            params[ignore_hashes].append(ignore_hashes)

        return self._error_handle_request(
            self.ep["nearest"][1],
            self.ep["nearest"][0](),
            data=json.dumps(embeddings),
            param=params,
        )

    def get_models(self) -> Union[None, Dict[str, Union[str, int]]]:
        """Gets the available models from the endpoint

        Returns:
            Union[None, List[str]]: If successful a list of models or None if any errors.
        """
        return self._error_handle_request(
            self.ep["get_models"][1],
            self.ep["get_models"][0](),
        )

    def explain(self, decomp_data) -> Union[None, Dict[str, Union[str, int]]]:
        """Requests explanation of function from endpoint."""
        return self._error_handle_request(
            self.ep["explain"][1],
            self.ep["explain"][0](),
            30,
            data=decomp_data,
        )

    def get_id(self, hash) -> Union[None, int]:
        """
        Gets the ID for the binary from the endpoint.
        """
        if hash in Endpoint.cache.keys():
            plugin_logger.info(
                f"found cached id for hash{hash} of {Endpoint.cache[hash]}"
            )
            return Endpoint.cache[hash]

        # get id matching to hash
        js, resp = self._error_handle_request(
            self.ep["getid"][1], self.ep["getid"][0](hash)
        )

        if resp.status_code == 200:
            for bin in js["binaries"]:
                if hash == bin["sha_256_hash"]:
                    # found the right one
                    bin_id = bin["binary_details"][0]["binary_id"]
                    Endpoint.cache[hash] = bin_id
                    plugin_logger.info(f"caching id {bin_id} for hash {hash}")
                    return bin_id
            ida_kernwin.warning(f"Did not find matching hash from endpoint")
        else:
            ida_kernwin.warning(f"error response from endpoint")
        return None
