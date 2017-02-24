#pragma once

#include <exception>

namespace BadAES
{
   class Exception : public std::exception
   {
   protected:
      const char *whatVal;

   public:
      Exception(const char *what);

      virtual const char *what(void);
   };
}
