import logging

from ServerConst import PORT_FILE_NAME,DEFAULT_PORT

# logger format - print to console
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("debug.log"),
        logging.StreamHandler()
    ]
)


class PortID:
    def __init__(self):
        self.logger = logging.getLogger("PortId")
        self.port = 0

    @staticmethod
    def get_port_id(self):
        """
        parse port.info file , if file didn't contains a valid port Id number
        return default port IF
        :param self:
        :return: port ID number
        """

        try:
            f = open(PORT_FILE_NAME, "r")
            # read port number
            self.port = f.readline()
            f.close()
            if not (self.port.isdecimal()) or not (0 < len(self.port) < 5):
                raise Exception(f'Invalid port format {self.port}')
            self.logger.info(f'Found a valid server port ID : {self.port}')
        except FileNotFoundError:
            self.logger.warning(f'using default port {DEFAULT_PORT}, {PORT_FILE_NAME} file not exit')
            port = DEFAULT_PORT
        except Exception as exp:
            self.logger.error(
                f'Error {exp} in port ID from {PORT_FILE_NAME} ,running using default port {DEFAULT_PORT}')
            port = DEFAULT_PORT
        return int(self.port)