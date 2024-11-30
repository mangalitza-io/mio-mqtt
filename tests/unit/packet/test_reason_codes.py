import pytest

from mio_mqtt.packet.reason_codes import (
    DISCONNECT_WITH_WILL_MESSAGE,
    GRANTED_QOS_2,
    NO_MATCHING_SUBSCRIBERS,
    NO_SUBSCRIPTION_EXISTED,
    SUCCESS,
    ReasonCode,
    ReasonCodeError,
    ReasonCodeKeyError,
    ReasonCodes,
    ReasonCodeTypeError,
    ReasonCodeValueError,
)


class TestReasonCodeError:
    def test_reason_code_error_inherits_from_exception(self) -> None:
        assert issubclass(ReasonCodeError, Exception)

    def test_codec_error_can_be_initialized(self) -> None:
        err: ReasonCodeError = ReasonCodeError()
        assert isinstance(err, ReasonCodeError)

    def test_codec_error_can_be_raised(self) -> None:
        with pytest.raises(ReasonCodeError) as exc_info:
            raise ReasonCodeError()
        assert exc_info.type is ReasonCodeError


class TestReasonCodeTypeError:
    def test_reason_code_type_error_inherits_from_reason_code_error(
        self,
    ) -> None:
        assert issubclass(ReasonCodeTypeError, ReasonCodeError)

    def test_reason_code_type_error_inherits_from_type_error(self) -> None:
        assert issubclass(ReasonCodeTypeError, TypeError)

    def test_reason_code_type_error_can_be_initialized(self) -> None:
        err: ReasonCodeTypeError = ReasonCodeTypeError()
        assert isinstance(err, ReasonCodeError)

    def test_reason_code_type_error_can_be_raised(self) -> None:
        with pytest.raises(ReasonCodeTypeError) as exc_info:
            raise ReasonCodeTypeError()
        assert exc_info.type is ReasonCodeTypeError


class TestReasonCodeValueError:
    def test_reason_code_value_error_inherits_from_reason_code_error(
        self,
    ) -> None:
        assert issubclass(ReasonCodeValueError, ReasonCodeError)

    def test_reason_code_value_error_inherits_from_value_error(self) -> None:
        assert issubclass(ReasonCodeValueError, ValueError)

    def test_reason_code_value_error_can_be_initialized(self) -> None:
        err: ReasonCodeValueError = ReasonCodeValueError()
        assert isinstance(err, ReasonCodeError)

    def test_reason_code_value_error_can_be_raised(self) -> None:
        with pytest.raises(ReasonCodeValueError) as exc_info:
            raise ReasonCodeValueError()
        assert exc_info.type is ReasonCodeValueError


class TestReasonCodeKeyError:
    def test_reason_code_key_error_inherits_from_reason_code_error(
        self,
    ) -> None:
        assert issubclass(ReasonCodeKeyError, ReasonCodeError)

    def test_reason_code_key_error_inherits_from_key_error(self) -> None:
        assert issubclass(ReasonCodeKeyError, KeyError)

    def test_reason_code_key_error_can_be_initialized(self) -> None:
        err: ReasonCodeKeyError = ReasonCodeKeyError()
        assert isinstance(err, ReasonCodeError)

    def test_reason_code_key_error_can_be_raised(self) -> None:
        with pytest.raises(ReasonCodeKeyError) as exc_info:
            raise ReasonCodeKeyError()
        assert exc_info.type is ReasonCodeKeyError


class TestReasonCode:
    def setup_method(self) -> None:
        self.reason_code_ok: ReasonCode = ReasonCode(code=0x00, name="Test")
        self._reason_code_err: ReasonCode = ReasonCode(code=0xFF, name="Test")

    def test_reason_code_ok_initialization(self) -> None:
        assert self.reason_code_ok.code == 0x00
        assert self.reason_code_ok.name == "Test"

    def test_reason_code_ok_is_success(self) -> None:
        assert self.reason_code_ok.is_success

    def test_reason_code_err_is_failure(self) -> None:
        assert self._reason_code_err.is_failure

    def test_reason_code_ok_not_is_failure(self) -> None:
        assert not self.reason_code_ok.is_failure

    def test_reason_code_err_not_is_success(self) -> None:
        assert not self._reason_code_err.is_success


class TestReasonCodes:
    def setup_method(self) -> None:
        self.reason_codes: ReasonCodes = ReasonCodes(
            [
                SUCCESS,
                GRANTED_QOS_2,
                DISCONNECT_WITH_WILL_MESSAGE,
                NO_MATCHING_SUBSCRIBERS,
                NO_SUBSCRIPTION_EXISTED,
            ]
        )

    def test_reason_codes_length(self) -> None:
        assert 5 == len(self.reason_codes)

    def test_reason_codes_iter(self) -> None:
        keys = set(iter(self.reason_codes))
        assert 5 == len(keys)
        assert SUCCESS.code in keys

    def test_reason_codes_getitem(self) -> None:
        reason_code = self.reason_codes[SUCCESS.code]
        assert SUCCESS == reason_code

    def test_reason_codes_get_reason_code(self) -> None:
        reason_code = self.reason_codes.get_reason_code(SUCCESS.code)
        assert SUCCESS == reason_code

    def test_reason_code_invalid_key(self) -> None:
        with pytest.raises(ReasonCodeKeyError) as exc_info:
            _ = self.reason_codes[0xFF]
        assert exc_info.type is ReasonCodeKeyError

    def test_reason_code_invalid_init_val(self) -> None:
        class NotReasonCode:
            @property
            def code(self) -> int:
                return 0

        with pytest.raises(ReasonCodeTypeError) as exc_info:
            ReasonCodes([NotReasonCode])  # type: ignore[list-item]
        assert exc_info.type is ReasonCodeTypeError

    def test_reason_code_invalid_init_val2(self) -> None:
        with pytest.raises(ReasonCodeTypeError) as exc_info:
            ReasonCodes([None])  # type: ignore[list-item]
        assert exc_info.type is ReasonCodeTypeError

    def test_reason_code_key_multiplication(self) -> None:
        with pytest.raises(ReasonCodeValueError) as exc_info:
            ReasonCodes([SUCCESS, SUCCESS])
        assert exc_info.type is ReasonCodeValueError
