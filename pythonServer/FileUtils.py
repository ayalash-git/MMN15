import logging
import os

from ServerConst import RECEIVE_FILES_FOLDER

# logger format - print to console
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("debug.log"),
        logging.StreamHandler()
    ]
)


class FileUtils:
    def __init__(self):
        self.logger = logging.getLogger("fileUtils")

    @staticmethod
    def create_directory(self):
        """
        This function creates a folder
        to save the received files
        """
        current_directory = os.getcwd()
        # represents raw string, will cause backslashes in the string to be interpreted as actual backslashes rather
        # than special characters
        final_directory = os.path.abspath(f'{current_directory}/{RECEIVE_FILES_FOLDER}')
        if not os.path.exists(final_directory):
            os.makedirs(final_directory)
            self.logger.debug(f'create receive file directory {final_directory}')
        self.logger.info(f'The received file folder in the path:: {final_directory}')

    @classmethod
    def delete_file(cls, self, full_file_name):
        """
        Delete file from RECEIVE_FILES_FOLDER
        :param self:
        :param full_file_name:
        :return:
        """
        file_name = cls.extract_file_name(full_file_name)
        path_name = os.path.abspath(f'./{RECEIVE_FILES_FOLDER}/{file_name}')
        try:
            os.remove(path_name)
            self.logger.debug(f"Remove file {path_name} done")
        except OSError:
            self.logger.error(f"The file {file_name} does not exist")
        except Exception as exp:
            self.logger.error(f"An error {exp} during delete file {file_name}")

    @classmethod
    def extract_file_name(cls, file_name):
        """
        Extract file name only from full string (255 chars)
        :param file_name:
        :return:
        """
        index = file_name.find(b'\x00')
        return file_name[:index].decode()

    @classmethod
    def save_file(cls, self, file_name, dec_file):
        """
        Save file in server RECEIVE_FILES_FOLDER
        :param self:
        :param file_name:
        :param dec_file:
        :return: Full file path
        """
        file_path = os.path.abspath(f'./{RECEIVE_FILES_FOLDER}/{file_name}')
        self.logger.debug(f'File should be saved on server files : {file_path}')
        try:
            with open(file_path, 'w') as f:
                f.write(str(dec_file))
        except OSError:
            self.logger.error(f"The file {file_name} does not exist")
        except Exception as exp:
            self.logger.error(f"An error {exp} during delete file {file_name}")
        return file_path
