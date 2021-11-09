from j1939.j1939 import J1939Message


class ECU:
    def __init__(self, address: int):
        self._address = address
        self._address_claimed_response = None
        self._prop_messages = []

    @property
    def address(self):
        return self._address

    @property
    def name(self):
        if self._address_claimed_response is None:
            return None
        return self._address_claimed_response.data

    @property
    def address_claimed_response(self) -> J1939Message:
        return self._address_claimed_response

    @address_claimed_response.setter
    def address_claimed_response(self, msg: J1939Message):
        if msg.pdu_format != 0xEE:
            raise ValueError("Address claimed should have PDU Format 0xEE")
        if msg.src_addr != self.address:
            raise ValueError("Address of ECU does not match this ECU")
        if len(msg.data) != 16:
            raise ValueError("NAME should be 8 bytes long")
        self._address_claimed_response = msg

    @property
    def prop_messages(self) -> list:
        return self._prop_messages

    def add_prop_message(self, msg: J1939Message):
        """
        Adds the msg to the list of proprietary messages, only if it's unique.
        """
        for p in self._prop_messages:
            if msg.can_id == p.can_id:
                if msg.data == p.data:
                    return  # not unique
        self._prop_messages.append(msg)

    def __str__(self):
        name = "unknown"
        if self.name is not None:
            name = self.name
        return "address: {:<3}   NAME: {}".format(self.address, name)
