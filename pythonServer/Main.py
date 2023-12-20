from Server import *

"""
 create server, main function
"""


def main():
    server = Server('')
    try:
        server.run()
        server.close()
    except Exception as exp:
        logging.error(f'Got an unexpected error during server running {exp}')
        server.close()


if __name__ == '__main__':
    main()
