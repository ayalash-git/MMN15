#include "Client.h"

int main(int argc, char* argv[])
{
    try
    {
        boost::asio::io_context io_context;
        Client c(io_context);

        c.process_requests();

        c.close_connection();
    }
    catch (exception& e)
    {
        cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}