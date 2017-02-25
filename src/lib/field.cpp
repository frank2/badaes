#include "badaes/field.hpp"

using namespace BadAES;

Field::Field
(uint32_t exponents)
{
   this->exponents = exponents;
}

Field::Field
(void)
{
   this->exponents = 0;
}

Field::Field
(const Field &field)
{
   this->exponents = field.getExponents();
}

Field
Field::AESMul
(Field l, Field r)
{
   return (l * r) % Field(0x11B);
}

void
Field::setExponents
(uint32_t exponents)
{
   this->exponents = exponents;
}

uint32_t
Field::getExponents
(void) const
{
   return this->exponents;
}

void
Field::setExponent
(size_t index, uint8_t value)
{
   if (index >= 32)
      throw Exception("index out of range");

   if (value == 0)
      this->exponents &= ~(1 << index);
   else
      this->exponents |= 1 << index;
}

uint8_t
Field::getExponent
(size_t index) const
{
   if (index >= 32)
      throw Exception("index out of range");

   return (this->exponents >> index) & 1;
}

uint8_t
Field::width
(void) const
{
   uint8_t width;
   uint32_t calc;
   
   if (this->exponents == 0)
      return 0;

   width = 1;
   calc = this->exponents >> 1;

   while (calc > 0)
   {
      width += 1;
      calc >>= 1;
   }

   return width;
}

Field
Field::pow
(uint32_t exponent) const
{
   Field result(1);

   for (uint32_t i=0; i<exponent; ++i)
      result *= *this;

   return result;
}

bool
Field::operator<
(const Field &other) const
{
   return this->exponents < other.getExponents();
}

bool
Field::operator>
(const Field &other) const
{
   return other < *this;
}

bool
Field::operator==
(const Field &other) const
{
   return !(*this < other) && !(*this > other);
}

bool
Field::operator!=
(const Field &other) const
{
   return !(*this == other);
}

bool
Field::operator<=
(const Field &other) const
{
   return *this < other || *this == other;
}

bool
Field::operator>=
(const Field &other) const
{
   return *this > other || *this == other;
}

uint8_t
Field::operator[]
(size_t index) const
{
   return this->getExponent(index);
}

Field
Field::operator^
(const Field &other) const
{
   return Field(this->exponents ^ other.getExponents());
}

void
Field::operator^=
(const Field &other)
{
   this->exponents = (*this ^ other).getExponents();
}

Field
Field::operator+
(const Field &other) const
{
   return *this ^ other;
}

void
Field::operator+=
(const Field &other)
{
   *this ^= other;
}
      
Field
Field::operator-
(const Field &other) const
{
   return *this ^ other;
}

void
Field::operator-=
(const Field &other)
{
   *this ^= other;
}

Field
Field::operator*
(const Field &other) const
{
   Field result;

   for (int i=0; i<other.width(); ++i)
   {
      Field newPoly;
      
      if (other[i] == 0)
         continue;

      for (int j=0; j<this->width(); ++j)
      {
         if ((*this)[j] == 0)
            continue;

         newPoly.setExponent(i+j, 1);
      }

      result += newPoly;
   }

   return result;
}

void
Field::operator*=
(const Field &other)
{
   this->exponents = (*this * other).getExponents();
}

Field
Field::operator/
(const Field &other) const
{
   return this->divide(other).first;
}

void
Field::operator/=
(const Field &other)
{
   this->exponents = (*this / other).getExponents();
}

Field
Field::operator%
(const Field &other) const
{
   return this->divide(other).second;
}

void
Field::operator%=
(const Field &other)
{
   this->exponents = (*this % other).getExponents();
}

std::pair<Field, Field>
Field::divide
(const Field &other) const
{
   Field result;
   Field remainder(this->exponents);

   while (remainder.width() - other.width() >= 0)
   {
      uint8_t delta = remainder.width() - other.width();
      Field polyDelta(1 << delta);
      
      result.setExponent(delta, 1);
      remainder -= other * polyDelta;
   }

   return std::pair<Field, Field>(result, remainder);
}
