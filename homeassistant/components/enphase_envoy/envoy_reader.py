"""Module to read production and consumption values from an Enphase Envoy on the local network."""
import contextlib
import datetime
from json.decoder import JSONDecodeError
import logging
import re
import time

from envoy_utils.envoy_utils import EnvoyUtils
import httpx
import jwt
import xmltodict

from homeassistant.util.network import is_ipv6_address

#
# Legacy parser is only used on ancient firmwares
#
PRODUCTION_REGEX = r"<td>Current[l].*</td>\s+<td>\s*(\d+|\d+\.\d+)\s*(W|kW|MW)</td>"
DAY_PRODUCTION_REGEX = r"<td>Today</td>\s+<td>\s*(\d+|\d+\.\d+)\s*(Wh|kWh|MWh)</td>"
WEEK_PRODUCTION_REGEX = (
    r"<td>Past Week</td>\s+<td>\s*(\d+|\d+\.\d+)\s*(Wh|kWh|MWh)</td>"
)
LIFE_PRODUCTION_REGEX = (
    r"<td>Since Installation</td>\s+<td>\s*(\d+|\d+\.\d+)\s*(Wh|kWh|MWh)</td>"
)
SERIAL_REGEX = re.compile(r"Envoy\s*Serial\s*Number:\s*([0-9]+)")

ENDPOINT_URL_PRODUCTION_JSON = "http{}://{}/production.json?details=1"
ENDPOINT_URL_PRODUCTION_V1 = "http{}://{}/api/v1/production"
ENDPOINT_URL_PRODUCTION_INVERTERS = "http{}://{}/api/v1/production/inverters"
ENDPOINT_URL_PRODUCTION = "http{}://{}/production"
ENDPOINT_URL_CHECK_JWT = "https://{}/auth/check_jwt"
ENDPOINT_URL_ENSEMBLE_INVENTORY = "http{}://{}/ivp/ensemble/inventory"
ENDPOINT_URL_HOME_JSON = "http{}://{}/home.json"
ENDPOINT_URL_INFO_XML = "http{}://{}/info.xml"

# pylint: disable=pointless-string-statement

ENVOY_MODEL_S = "PC"
ENVOY_MODEL_C = "P"
ENVOY_MODEL_LEGACY = "P0"

LOGIN_URL = "https://entrez.enphaseenergy.com/login_main_page"
TOKEN_URL = "https://entrez.enphaseenergy.com/entrez_tokens"

# paths for the enlighten 1 year owner token
ENLIGHTEN_AUTH_URL = "https://enlighten.enphaseenergy.com/login/login.json"
ENLIGHTEN_TOKEN_URL = "https://entrez.enphaseenergy.com/tokens"

_LOGGER = logging.getLogger(__name__)


def has_production_and_consumption(json):
    """Check if json has keys for both production and consumption."""
    return "production" in json and "consumption" in json


def has_metering_setup(json):
    """Check if Active Count of Production CTs (eim) installed is greater than one."""
    return json["production"][1]["activeCount"] > 0


class SwitchToHTTPS(Exception):
    """Switch to https."""


class EnvoyReader:  # pylint: disable=too-many-instance-attributes
    """Instance of EnvoyReader."""

    # P0 for older Envoy model C, s/w < R3.9 no json pages
    # P for production data only (ie. Envoy model C, s/w >= R3.9)
    # or ENVOY-S standard (not metered)
    # PC for production and consumption data (ie. Envoy model S metered)

    message_battery_not_available = (
        "Battery storage data not available for your Envoy device."
    )

    message_consumption_not_available = (
        "Consumption data not available for your Envoy device."
    )

    message_grid_status_not_available = (
        "Grid status not available for your Envoy device."
    )

    def __init__(  # pylint: disable=too-many-arguments
        self,
        host,
        username="envoy",
        password="",
        inverters=False,
        async_client=None,
        enlighten_user=None,
        enlighten_pass=None,
        commissioned=False,
        enlighten_site_id=None,
        enlighten_serial_num=None,
        https_flag="",
        use_enlighten_owner_token=False,
        token_refresh_buffer_seconds=0,
        store=None,
        info_refresh_buffer_seconds=3600,
    ) -> None:
        """Init the EnvoyReader."""
        self.host = host.lower()
        # IPv6 addresses need to be enclosed in brackets
        if is_ipv6_address(self.host):
            self.host = f"[{self.host}]"
        self.username = username
        self.password = password
        self.get_inverters = inverters
        self.endpoint_type = None
        self.has_grid_status = True
        self.serial_number_last_six = None
        self.endpoint_production_json_results = None
        self.endpoint_production_v1_results = None
        self.endpoint_production_inverters = None
        self.endpoint_production_results = None
        self.endpoint_ensemble_json_results = None
        self.endpoint_home_json_results = None
        self.endpoint_info_results = None
        self.isMeteringEnabled = False  # pylint: disable=invalid-name
        self._async_client = async_client
        self._authorization_header = None
        self._cookies = None
        self.enlighten_user = enlighten_user
        self.enlighten_pass = enlighten_pass
        self.commissioned = commissioned
        self.enlighten_site_id = enlighten_site_id
        self.enlighten_serial_num = enlighten_serial_num
        self.https_flag = https_flag
        self.use_enlighten_owner_token = use_enlighten_owner_token
        self.token_refresh_buffer_seconds = token_refresh_buffer_seconds
        self.info_refresh_buffer_seconds = info_refresh_buffer_seconds
        self.info_next_refresh_time = datetime.datetime.now()

        self._store = store
        self._store_data: dict[str, str] = {}
        self._store_update_pending = False

    @property
    def _token(self):
        return self._store_data.get("token", "")

    @_token.setter
    def _token(self, token_value):
        self._store_data["token"] = token_value
        self._store_update_pending = True

    async def sync_store(self):
        """Synchronize the store data."""
        if self._store and not self._store_data:
            self._store_data = await self._store.async_load() or {}

        if self._store and self._store_update_pending:
            self._store_update_pending = False
            await self._store.async_save(self._store_data)

    @property
    def async_client(self):
        """Return the httpx client."""
        return self._async_client or httpx.AsyncClient(
            verify=False, headers=self._authorization_header, cookies=self._cookies
        )

    async def _update(self):
        """Update the data."""
        if self.endpoint_type == ENVOY_MODEL_S:
            await self._update_from_pc_endpoint()
        if self.endpoint_type == ENVOY_MODEL_C or (
            self.endpoint_type == ENVOY_MODEL_S and not self.isMeteringEnabled
        ):
            await self._update_from_p_endpoint()
        if self.endpoint_type == ENVOY_MODEL_LEGACY:
            await self._update_from_p0_endpoint()

    async def _update_from_pc_endpoint(self):
        """Update from PC endpoint."""
        await self._update_endpoint(
            "endpoint_production_json_results", ENDPOINT_URL_PRODUCTION_JSON
        )
        await self._update_endpoint(
            "endpoint_ensemble_json_results", ENDPOINT_URL_ENSEMBLE_INVENTORY
        )
        if self.has_grid_status:
            await self._update_endpoint(
                "endpoint_home_json_results", ENDPOINT_URL_HOME_JSON
            )
        await self._update_info_endpoint()

    async def _update_from_p_endpoint(self):
        """Update from P endpoint."""
        await self._update_endpoint(
            "endpoint_production_v1_results", ENDPOINT_URL_PRODUCTION_V1
        )
        await self._update_info_endpoint()

    async def _update_from_p0_endpoint(self):
        """Update from P0 endpoint."""
        await self._update_endpoint(
            "endpoint_production_results", ENDPOINT_URL_PRODUCTION
        )

    async def _update_info_endpoint(self):
        """Update from info.xml endpoint if next time expried."""
        if self.info_next_refresh_time <= datetime.datetime.now():
            await self._update_endpoint("endpoint_info_results", ENDPOINT_URL_INFO_XML)
            self.info_next_refresh_time = datetime.datetime.now() + datetime.timedelta(
                seconds=self.info_refresh_buffer_seconds
            )
            _LOGGER.debug(
                "Info endpoint updated, set next update time: %s using interval: %s",
                self.info_next_refresh_time,
                self.info_refresh_buffer_seconds,
            )
        else:
            _LOGGER.debug(
                "Info endpoint next update time is: %s using interval: %s",
                self.info_next_refresh_time,
                self.info_refresh_buffer_seconds,
            )

    async def _update_endpoint(self, attr, url):
        """Update a property from an endpoint."""
        formatted_url = url.format(self.https_flag, self.host)
        response = await self._async_fetch_with_retry(
            formatted_url, follow_redirects=False
        )
        setattr(self, attr, response)

    async def _async_fetch_with_retry(self, url, **kwargs):
        """Retry 3 times to fetch the url if there is a transport error."""
        for attempt in range(3):
            header = " <Blank Authorization Header> "
            if self._authorization_header:
                header = " <Authorization header with Token hidden> "

            _LOGGER.debug(
                "HTTP GET Attempt #%s: %s: Header:%s ",
                attempt + 1,
                url,
                header,
            )
            try:
                async with self.async_client as client:
                    resp = await client.get(
                        url, headers=self._authorization_header, timeout=30, **kwargs
                    )
                    if resp.status_code == 401 and attempt < 2:
                        if self.use_enlighten_owner_token:
                            _LOGGER.debug(
                                "Received 401 from Envoy; refreshing token cookies, attempt %s of 2",
                                attempt + 1,
                            )
                            could_refresh_cookies = await self._refresh_token_cookies()
                            if not could_refresh_cookies:
                                _LOGGER.debug(
                                    "Authorize with envoy failed; refreshing token, attempt %s of 2",
                                    attempt + 1,
                                )
                                await self._getEnphaseToken()
                            continue

                        # don't try cookie and token refresh for legacy envoy
                        _LOGGER.debug(
                            "Received 401 from Envoy; retrying, attempt %s of 2",
                            attempt + 1,
                        )
                        continue
                    _LOGGER.debug(
                        "Fetched (%s) from %s: %s: %s",
                        attempt + 1,
                        url,
                        resp,
                        resp.text,
                    )
                    if resp.status_code == 404:
                        return None
                    return resp
            except httpx.TransportError:
                if attempt == 2:
                    raise

    async def _async_post(self, url, data=None, cookies=None, **kwargs):
        """Post data to url."""

        _LOGGER.debug("HTTP POST Attempt: %s", url)
        # _LOGGER.debug("HTTP POST Data: %s", data)
        # try:  #ruff TRY302 rule states not to use try in this case.
        async with self.async_client as client:
            resp = await client.post(
                url, cookies=cookies, data=data, timeout=30, **kwargs
            )
            _LOGGER.debug("HTTP POST %s: %s: %s", url, resp, resp.text)
            _LOGGER.debug("HTTP POST Cookie: %s", resp.cookies)
            return resp
        # except httpx.TransportError:  # pylint: disable=try-except-raise
        #    raise

    async def _fetch_owner_token_json(self):
        """Try to fetch the owner token json from Enlighten API."""
        async with self.async_client as client:
            # login to enlighten website

            payload_login = {
                "user[email]": self.enlighten_user,
                "user[password]": self.enlighten_pass,
            }
            resp = await client.post(ENLIGHTEN_AUTH_URL, data=payload_login, timeout=30)
            if resp.status_code >= 400:
                _LOGGER.warning("Login to Enphase site failed %s", resp)
                resp.raise_for_status()

            # now that we're in a logged in session, we can request the 1 year owner token to access envoy
            login_data = resp.json()
            payload_token = {
                "session_id": login_data["session_id"],
                "serial_num": self.enlighten_serial_num,
                "username": self.enlighten_user,
            }
            resp = await client.post(
                ENLIGHTEN_TOKEN_URL, json=payload_token, timeout=30
            )
            if resp.status_code != 200:
                _LOGGER.warning("Getting token from to Enphase site failed %s", resp)
                resp.raise_for_status()
            return resp.text

    async def _getEnphaseToken(self):
        self._token = await self._fetch_owner_token_json()
        _LOGGER.debug("Obtained Token from Enphase site")

        if self._is_enphase_token_expired(self._token):
            raise RuntimeError("Just received token already expired")

        await self._refresh_token_cookies()

    async def _refresh_token_cookies(self):
        """Refresh the client's cookie with the token (if valid)."""
        """:returns True if cookie refreshed, False if it couldn't be."""

        # Create HTTP Header
        self._authorization_header = {"Authorization": "Bearer " + self._token}

        # Fetch the Enphase Token status from the local Envoy
        token_validation = await self._async_post(
            ENDPOINT_URL_CHECK_JWT.format(self.host)
        )

        if token_validation.status_code == 200:
            # set the cookies for future clients
            self._cookies = token_validation.cookies
            return True

        # token not valid if we get here
        return False

    def _is_enphase_token_valid(self, response):
        if response == "Valid token.":
            _LOGGER.debug("Token is valid")
            return True
        _LOGGER.debug("Invalid token!")
        return False

    def _is_enphase_token_expired(self, token):
        decode = jwt.decode(
            token, options={"verify_signature": False}, algorithms="ES256"
        )
        exp_epoch = decode["exp"]
        # allow a buffer so we can try and grab it sooner
        exp_epoch -= self.token_refresh_buffer_seconds
        exp_time = datetime.datetime.fromtimestamp(exp_epoch)
        if datetime.datetime.now() < exp_time:
            _LOGGER.debug("Token expires at: %s", exp_time)
            return False
        _LOGGER.debug("Token expired on: %s", exp_time)
        return True

    async def check_connection(self):
        """Check if the Envoy is reachable. Also check if HTTP or."""
        """HTTPS is needed."""
        _LOGGER.debug("Checking Host: %s", self.host)
        resp = await self._async_fetch_with_retry(
            ENDPOINT_URL_PRODUCTION_V1.format(self.https_flag, self.host)
        )
        _LOGGER.debug("Check connection HTTP Code: %s", resp.status_code)
        if resp.status_code == 301:
            raise SwitchToHTTPS

    async def getData(self, getInverters=True):  # pylint: disable=invalid-name
        """Fetch data from the endpoint and if inverters selected default."""
        """to fetching inverter data."""

        # Check if the Secure flag is set
        if self.https_flag == "s":
            _LOGGER.debug(
                "Checking Token value: %s (Only first 10 characters shown)",
                self._token[1:10],
            )
            # Check if a token has already been retrieved
            if self._token == "":
                _LOGGER.debug("Found empty token: %s", self._token)
                await self._getEnphaseToken()
            else:
                _LOGGER.debug(
                    "Token is populated: %s (Only first 10 characters shown)",
                    self._token[1:10],
                )
                if self._is_enphase_token_expired(self._token):
                    _LOGGER.debug("Found Expired token - Retrieving new token")
                    await self._getEnphaseToken()

        if not self.endpoint_type:
            await self.detect_model()
        else:
            await self._update()

        _LOGGER.debug(
            "Using Model: %s (HTTP%s, Metering enabled: %s, Get Inverters: %s, Use Enligthen %s)",
            self.endpoint_type,
            self.https_flag,
            self.isMeteringEnabled,
            self.get_inverters,
            self.use_enlighten_owner_token,
        )

        if not self.get_inverters or not getInverters:
            return

        inverters_url = ENDPOINT_URL_PRODUCTION_INVERTERS.format(
            self.https_flag, self.host
        )
        response = await self._async_fetch_with_retry(inverters_url)

        if response.status_code == 401:
            # Legacy model R with fw <3.9 has no json, >=3.9 no inverters json
            if self.endpoint_type in [ENVOY_MODEL_C, ENVOY_MODEL_LEGACY]:
                self.get_inverters = False
                _LOGGER.debug(
                    "Error 401 when getting inverters, disabling inverter collection"
                )
            response.raise_for_status()
        self.endpoint_production_inverters = response
        return

    async def detect_model(self):
        """Determine if the Envoy supports consumption values or only production."""
        # If a password was not given as an argument when instantiating
        # the EnvoyReader object than use the last six numbers of the serial
        # number as the password.  Otherwise use the password argument value.
        if self.password == "" and not self.serial_number_last_six:
            await self.get_serial_number()

        with contextlib.suppress(httpx.HTTPError):
            await self._update_from_pc_endpoint()

        # If self.endpoint_production_json_results.status_code is set with
        # 401 then we will give an error
        if (
            self.endpoint_production_json_results
            and self.endpoint_production_json_results.status_code == 401
        ):
            raise RuntimeError(
                "Could not connect to Envoy model. "
                + "It appears your Envoy is running firmware that requires secure communication. "
                + "Please enter in the needed Enlighten credentials during setup."
            )

        if (
            self.endpoint_production_json_results
            and self.endpoint_production_json_results.status_code == 200
            and has_production_and_consumption(
                self.endpoint_production_json_results.json()
            )
        ):
            self.isMeteringEnabled = has_metering_setup(
                self.endpoint_production_json_results.json()
            )
            if not self.isMeteringEnabled:
                await self._update_from_p_endpoint()
            self.endpoint_type = ENVOY_MODEL_S
            return

        with contextlib.suppress(httpx.HTTPError):
            await self._update_from_p_endpoint()

        if (
            self.endpoint_production_v1_results
            and self.endpoint_production_v1_results.status_code == 200
        ):
            self.endpoint_type = ENVOY_MODEL_C  # Envoy-C, production only
            return

        with contextlib.suppress(httpx.HTTPError):
            await self._update_from_p0_endpoint()

        if (
            self.endpoint_production_results
            and self.endpoint_production_results.status_code == 200
        ):
            self.endpoint_type = ENVOY_MODEL_LEGACY  # older Envoy-C
            self.get_inverters = False  # don't get inverters for this model
            return

        raise RuntimeError(
            "Could not connect or determine Envoy model. "
            + "Check that the device is up at 'http://"
            + self.host
            + "'."
        )

    async def get_serial_number(self):
        """Get last six digits of Envoy serial number for auth."""
        full_serial = await self.get_full_serial_number()
        if full_serial:
            gen_passwd = EnvoyUtils.get_password(full_serial, self.username)
            if self.username == "envoy" or self.username != "installer":
                self.password = self.serial_number_last_six = full_serial[-6:]
            else:
                self.password = gen_passwd

    async def get_full_serial_number(self):
        """Get the  Envoy serial number."""
        response = await self._async_fetch_with_retry(
            f"http{self.https_flag}://{self.host}/info.xml",
            follow_redirects=True,
        )
        if not response.text:
            return None
        if "<sn>" in response.text:
            return response.text.split("<sn>")[1].split("</sn>")[0]
        match = SERIAL_REGEX.search(response.text)
        if match:
            # if info.xml is in html format we're dealing with ENVOY R
            _LOGGER.debug(
                "Legacy model identified by info.xml being html. Disabling inverters"
            )
            self.get_inverters = False
            return match.group(1)

    def create_connect_errormessage(self):
        """Create error message if unable to connect to Envoy."""
        return (
            "Unable to connect to Envoy. "
            + "Check that the device is up at 'http://"
            + self.host
            + "'."
        )

    def create_json_errormessage(self):
        """Create error message if unable to parse JSON response."""
        return (
            "Got a response from '"
            + self.host
            + "', but metric could not be found. "
            + "Maybe your model of Envoy doesn't "
            + "support the requested metric."
        )

    async def production(self):
        """Return production data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        if self.endpoint_type == ENVOY_MODEL_S:
            raw_json = self.endpoint_production_json_results.json()
            idx = 1 if self.isMeteringEnabled else 0
            production = raw_json["production"][idx]["wNow"]
        elif self.endpoint_type == ENVOY_MODEL_C:
            raw_json = self.endpoint_production_v1_results.json()
            production = raw_json["wattsNow"]
        elif self.endpoint_type == ENVOY_MODEL_LEGACY:
            text = self.endpoint_production_results.text
            match = re.search(PRODUCTION_REGEX, text, re.MULTILINE)
            if match:
                if match.group(2) == "kW":
                    production = float(match.group(1)) * 1000
                elif match.group(2) == "mW":
                    production = float(match.group(1)) * 1000000
                else:
                    production = float(match.group(1))
            else:
                raise RuntimeError("No match for production, check REGEX  " + text)
        return int(production)

    async def production_phase(self, phase):
        """Return production phase data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        phase_map = {"production_l1": 0, "production_l2": 1, "production_l3": 2}

        if self.endpoint_type == ENVOY_MODEL_S:
            raw_json = self.endpoint_production_json_results.json()
            idx = 1 if self.isMeteringEnabled else 0
            try:
                return int(
                    raw_json["production"][idx]["lines"][phase_map[phase]]["wNow"]
                )
            except (KeyError, IndexError):
                return None

        return None

    async def consumption(self):
        """Return consumptiom data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        """Only return data if Envoy supports Consumption"""
        if self.endpoint_type in [ENVOY_MODEL_C, ENVOY_MODEL_LEGACY]:
            return self.message_consumption_not_available

        raw_json = self.endpoint_production_json_results.json()
        consumption = raw_json["consumption"][0]["wNow"]
        return int(consumption)

    async def consumption_phase(self, phase):
        """Return consumption phase data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        phase_map = {"consumption_l1": 0, "consumption_l2": 1, "consumption_l3": 2}

        """Only return data if Envoy supports Consumption"""
        if self.endpoint_type in [ENVOY_MODEL_C, ENVOY_MODEL_LEGACY]:
            return None

        raw_json = self.endpoint_production_json_results.json()
        try:
            return int(raw_json["consumption"][0]["lines"][phase_map[phase]]["wNow"])
        except (KeyError, IndexError):
            return None

    async def daily_production(self):
        """Return daily production data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        if self.endpoint_type == ENVOY_MODEL_S and self.isMeteringEnabled:
            raw_json = self.endpoint_production_json_results.json()
            daily_production = raw_json["production"][1]["whToday"]
        elif self.endpoint_type == ENVOY_MODEL_C or (
            self.endpoint_type == ENVOY_MODEL_S and not self.isMeteringEnabled
        ):
            raw_json = self.endpoint_production_v1_results.json()
            daily_production = raw_json["wattHoursToday"]
        elif self.endpoint_type == ENVOY_MODEL_LEGACY:
            text = self.endpoint_production_results.text
            match = re.search(DAY_PRODUCTION_REGEX, text, re.MULTILINE)
            if match:
                if match.group(2) == "kWh":
                    daily_production = float(match.group(1)) * 1000
                elif match.group(2) == "MWh":
                    daily_production = float(match.group(1)) * 1000000
                else:
                    daily_production = float(match.group(1))
            else:
                raise RuntimeError("No match for Day production, check REGEX  " + text)
        return int(daily_production)

    async def daily_production_phase(self, phase):
        """Return daily production phase data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        phase_map = {
            "daily_production_l1": 0,
            "daily_production_l2": 1,
            "daily_production_l3": 2,
        }

        if self.endpoint_type == ENVOY_MODEL_S and self.isMeteringEnabled:
            raw_json = self.endpoint_production_json_results.json()
            try:
                return int(
                    raw_json["production"][1]["lines"][phase_map[phase]]["whToday"]
                )
            except (KeyError, IndexError):
                return None

        return None

    async def daily_consumption(self):
        """Return daily consumption data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        """Only return data if Envoy supports Consumption"""
        if self.endpoint_type in [ENVOY_MODEL_C, ENVOY_MODEL_LEGACY]:
            return self.message_consumption_not_available

        raw_json = self.endpoint_production_json_results.json()
        daily_consumption = raw_json["consumption"][0]["whToday"]
        return int(daily_consumption)

    async def daily_consumption_phase(self, phase):
        """Return daily consumption data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        phase_map = {
            "daily_consumption_l1": 0,
            "daily_consumption_l2": 1,
            "daily_consumption_l3": 2,
        }

        """Only return data if Envoy supports Consumption"""
        if self.endpoint_type in [ENVOY_MODEL_C, ENVOY_MODEL_LEGACY]:
            return None

        raw_json = self.endpoint_production_json_results.json()
        try:
            return int(raw_json["consumption"][0]["lines"][phase_map[phase]]["whToday"])
        except (KeyError, IndexError):
            return None

    async def seven_days_production(self):
        """Return last 7 days production data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        if self.endpoint_type == ENVOY_MODEL_S and self.isMeteringEnabled:
            raw_json = self.endpoint_production_json_results.json()
            seven_days_production = raw_json["production"][1]["whLastSevenDays"]
        elif self.endpoint_type == ENVOY_MODEL_C or (
            self.endpoint_type == ENVOY_MODEL_S and not self.isMeteringEnabled
        ):
            raw_json = self.endpoint_production_v1_results.json()
            seven_days_production = raw_json["wattHoursSevenDays"]
        elif self.endpoint_type == ENVOY_MODEL_LEGACY:
            text = self.endpoint_production_results.text
            match = re.search(WEEK_PRODUCTION_REGEX, text, re.MULTILINE)
            if match:
                if match.group(2) == "kWh":
                    seven_days_production = float(match.group(1)) * 1000
                elif match.group(2) == "MWh":
                    seven_days_production = float(match.group(1)) * 1000000
                else:
                    seven_days_production = float(match.group(1))
            else:
                raise RuntimeError("No match for 7 Day production, check REGEX " + text)
        return int(seven_days_production)

    async def seven_days_consumption(self):
        """Return last 7 days consumption data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        """Only return data if Envoy supports Consumption"""
        if self.endpoint_type in [ENVOY_MODEL_C, ENVOY_MODEL_LEGACY]:
            return self.message_consumption_not_available

        raw_json = self.endpoint_production_json_results.json()
        seven_days_consumption = raw_json["consumption"][0]["whLastSevenDays"]
        return int(seven_days_consumption)

    async def lifetime_production(self):
        """Return lifetime production data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        if self.endpoint_type == ENVOY_MODEL_S:
            raw_json = self.endpoint_production_json_results.json()
            idx = 1 if self.isMeteringEnabled else 0
            lifetime_production = raw_json["production"][idx]["whLifetime"]
        elif self.endpoint_type == ENVOY_MODEL_C:
            raw_json = self.endpoint_production_v1_results.json()
            lifetime_production = raw_json["wattHoursLifetime"]
        elif self.endpoint_type == ENVOY_MODEL_LEGACY:
            text = self.endpoint_production_results.text
            match = re.search(LIFE_PRODUCTION_REGEX, text, re.MULTILINE)
            if match:
                if match.group(2) == "kWh":
                    lifetime_production = float(match.group(1)) * 1000
                elif match.group(2) == "MWh":
                    lifetime_production = float(match.group(1)) * 1000000
                else:
                    lifetime_production = float(match.group(1))
            else:
                raise RuntimeError(
                    "No match for Lifetime production, check REGEX " + text
                )
        return int(lifetime_production)

    async def lifetime_production_phase(self, phase):
        """Return lifetime production phase data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        phase_map = {
            "lifetime_production_l1": 0,
            "lifetime_production_l2": 1,
            "lifetime_production_l3": 2,
        }

        if self.endpoint_type == ENVOY_MODEL_S and self.isMeteringEnabled:
            raw_json = self.endpoint_production_json_results.json()

            try:
                return int(
                    raw_json["production"][1]["lines"][phase_map[phase]]["whLifetime"]
                )
            except (KeyError, IndexError):
                return None

        return None

    async def lifetime_consumption(self):
        """Return llifetime consumption data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        """Only return data if Envoy supports Consumption"""
        if self.endpoint_type in [ENVOY_MODEL_C, ENVOY_MODEL_LEGACY]:
            return self.message_consumption_not_available

        raw_json = self.endpoint_production_json_results.json()
        lifetime_consumption = raw_json["consumption"][0]["whLifetime"]
        return int(lifetime_consumption)

    async def lifetime_consumption_phase(self, phase):
        """Return lifetime consumption phase data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        phase_map = {
            "lifetime_consumption_l1": 0,
            "lifetime_consumption_l2": 1,
            "lifetime_consumption_l3": 2,
        }

        """Only return data if Envoy supports Consumption"""
        if self.endpoint_type in [ENVOY_MODEL_C, ENVOY_MODEL_LEGACY]:
            return None

        raw_json = self.endpoint_production_json_results.json()
        try:
            return int(
                raw_json["consumption"][0]["lines"][phase_map[phase]]["whLifetime"]
            )
        except (KeyError, IndexError):
            return None

    async def inverters_production(self):
        """Return inverters production data from stored data."""
        """Running getData() beforehand will set self.endpoint_type and self.isDataRetrieved."""

        """Only return data if Envoy supports retrieving Inverter data"""
        if not self.get_inverters:
            return None

        response_dict: dict[str, str] = {}
        try:
            for item in self.endpoint_production_inverters.json():
                response_dict[item["serialNumber"]] = [
                    item["lastReportWatts"],
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(item["lastReportDate"])
                    ),
                ]
        except (JSONDecodeError, KeyError, IndexError, TypeError, AttributeError):
            return None

        return response_dict

    async def battery_storage(self):
        """Return battery data from Envoys that support and have batteries installed."""
        if self.endpoint_type in [ENVOY_MODEL_C, ENVOY_MODEL_LEGACY]:
            return self.message_battery_not_available

        try:
            raw_json = self.endpoint_production_json_results.json()
        except JSONDecodeError:
            return None

        """For Envoys that support batteries but do not have them installed the"""
        """percentFull will not be available in the JSON results. The API will"""
        """only return battery data if batteries are installed."""
        if "percentFull" not in raw_json["storage"][0].keys():
            # "ENCHARGE" batteries are part of the "ENSEMBLE" api instead
            # Check to see if it's there. Enphase has too much fun with these names
            if self.endpoint_ensemble_json_results is not None:
                ensemble_json = self.endpoint_ensemble_json_results.json()
                if len(ensemble_json) > 0 and "devices" in ensemble_json[0]:
                    return ensemble_json[0]["devices"]
            return self.message_battery_not_available

        return raw_json["storage"][0]

    async def grid_status(self):
        """Return grid status reported by Envoy."""
        if self.has_grid_status and self.endpoint_home_json_results is not None:
            if self.endpoint_production_json_results.status_code == 200:
                home_json = self.endpoint_home_json_results.json()
                if "enpower" in home_json and "grid_status" in home_json["enpower"]:
                    return home_json["enpower"]["grid_status"]
        self.has_grid_status = False
        return None

    async def envoy_info(self):
        """Return information reported by Envoy info.xml."""
        device_data = {}

        if self.endpoint_info_results:
            try:
                data = xmltodict.parse(self.endpoint_info_results.text)
                device_data["software"] = data["envoy_info"]["device"]["software"]
                device_data["pn"] = data["envoy_info"]["device"]["pn"]
                device_data["metered"] = data["envoy_info"]["device"]["imeter"]
            except (KeyError, IndexError, TypeError, AttributeError):
                pass

        return device_data
