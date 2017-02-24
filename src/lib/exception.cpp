#include "badaes/exception.hpp"

using namespace BadAES;

Exception::Exception
(const char *what)
   : std::exception()
{
   this->whatVal = what;
}

const char *
Exception::what
(void)
{
   return this->whatVal;
}
