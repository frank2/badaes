#pragma once

#include <stdint.h>
#include <utility>

#include <badaes/exception.hpp>

namespace BadAES
{
   class Field
   {
   protected:
      uint32_t exponents;

   public:
      Field(uint32_t exponents);
      Field();
      Field(const Field &field);

      static Field AESMul(Field l, Field r);
      static Field AESPow(Field x, size_t exponent);

      void setExponents(uint32_t exponents);
      uint32_t getExponents(void) const;

      void setExponent(size_t index, uint8_t value);
      uint8_t getExponent(size_t index) const;

      uint8_t width(void) const;

      Field pow(uint32_t exponent) const;

      bool operator<(const Field &other) const;
      bool operator>(const Field &other) const;
      bool operator==(const Field &other) const;
      bool operator!=(const Field &other) const;
      bool operator<=(const Field &other) const;
      bool operator>=(const Field &other) const;
      
      uint8_t operator[](size_t index) const;
      
      Field operator^(const Field &other) const;
      void operator^=(const Field &other);
      Field operator+(const Field &other) const;
      void operator+=(const Field &other);
      Field operator-(const Field &other) const;
      void operator-=(const Field &other);

      Field operator*(const Field &other) const;
      void operator*=(const Field &other);
      
      Field operator/(const Field &other) const;
      void operator/=(const Field &other);
      Field operator%(const Field &other) const;
      void operator%=(const Field &other);

   protected:
      std::pair<Field, Field> divide(const Field &other) const;
   };
}
