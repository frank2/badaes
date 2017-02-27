#pragma once

#include <stdint.h>
#include <vector>

#include <badaes/exception.hpp>
#include <badaes/field.hpp>

namespace BadAES
{
   class Word
   {
   protected:
      std::vector<Field> fields;

   public:
      const static size_t Size = 4;
      
      Word(std::vector<Field> fields);
      Word(uint32_t fields[Word::Size]);
      Word(const Word &word);
      Word();

      void setFields(std::vector<Field> fields);
      void setFields(uint32_t fields[Word::Size]);
      std::vector<Field> getFields(void) const;

      void setField(int index, Field field);
      Field getField(int index) const;

      Word rol(void) const;
      void irol(void);

      Word ror(void) const;
      void iror(void);

      Field &operator[](int index);

      bool operator<(const Word &other) const;
      bool operator>(const Word &other) const;
      bool operator==(const Word &other) const;
      bool operator!=(const Word &other) const;
      bool operator<=(const Word &other) const;
      bool operator>=(const Word &other) const;

      Word operator^(const Word &other) const;
      void operator^=(const Word &other); 
      Word operator+(const Word &other) const;
      void operator+=(const Word &other);
      Word operator-(const Word &other) const;
      void operator-=(const Word &other);
      Word operator*(const Word &other) const;
      void operator*=(const Word &other);
   };
}
