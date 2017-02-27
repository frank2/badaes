#include "badaes/word.hpp"

using namespace BadAES;

Word::Word
(std::vector<Field> fields)
{
   this->fields.resize(Word::Size);
   this->setFields(fields);
}

Word::Word
(uint32_t fields[Word::Size])
{
   /* so like this is kinda bad but works because
      sizeof(uint32_t) == sizeof(Field)
      soooo... sorry, lol */
   
   this->fields.resize(Word::Size);
   this->setFields(std::vector<Field>(fields, fields+Word::Size));
}

Word::Word
(const Word &word)
{
   this->fields.resize(Word::Size);
   this->setFields(word.getFields());
}

Word::Word
(void)
{
   this->fields.resize(Word::Size);
}

void
Word::setFields
(std::vector<Field> fields)
{
   if (fields.size() != Word::Size)
      throw Exception("vector is not the length of a word");

   this->fields = std::vector<Field>(fields.begin(), fields.end());
}

void
Word::setFields
(uint32_t fields[Word::Size])
{
   this->setFields(std::vector<Field>(fields, fields+Word::Size));
}

std::vector<Field>
Word::getFields
(void) const
{
   return this->fields;
}

void
Word::setField
(int index, Field field)
{
   if (index < 0)
      this->fields[index+Word::Size] = field;
   else
      this->fields[index] = field;
}

Field
Word::getField
(int index) const
{
   if (index < 0)
      return this->fields[index+Word::Size];
   else
      return this->fields[index];
}

Word
Word::rol
(void) const
{
   std::vector<Field> result(this->fields.begin(), this->fields.end());
   Field movement;

   movement = result[0];
   result.erase(result.begin());
   result.push_back(movement);

   return Word(result);
}

void
Word::irol
(void)
{
   this->setFields(this->rol().getFields());
}

Word
Word::ror
(void) const
{
   std::vector<Field> result(this->fields.begin(), this->fields.end());
   Field movement;

   movement = result[Word::Size-1];
   result.erase(result.begin()+(Word::Size-1));
   result.insert(result.begin(), movement);

   return Word(result);
}

void
Word::iror
(void)
{
   this->setFields(this->ror().getFields());
}

Field &
Word::operator[]
(int index)
{
   if (index < 0)
      return this->fields[index+Word::Size];
   else
      return this->fields[index];
}

bool
Word::operator<
(const Word &other) const
{
   for (int i=Word::Size-1; i>=0; --i)
   {
      if (this->getField(i) == other.getField(i))
         continue;

      return this->getField(i) < other.getField(i);
   }

   return false;
}

bool
Word::operator>
(const Word &other) const
{
   return other < *this;
}

bool
Word::operator==
(const Word &other) const
{
   return !(*this < other) && !(other < *this);
}

bool
Word::operator!=
(const Word &other) const
{
   return !(*this == other);
}

bool
Word::operator<=
(const Word &other) const
{
   return *this < other || *this == other;
}

bool
Word::operator>=
(const Word &other) const
{
   return *this > other || *this == other;
}
   
Word
Word::operator^
(const Word &other) const
{
   Word result(this->fields);

   for (int i=0; i<Word::Size; ++i)
      result[i] = result[i] ^ other.getField(i);

   return result;
}

void
Word::operator^=
(const Word &other)
{
   this->setFields((*this ^ other).getFields());
}

Word
Word::operator+
(const Word &other) const
{
   return *this ^ other;
}

void
Word::operator+=
(const Word &other)
{
   *this ^= other;
}

Word
Word::operator-
(const Word &other) const
{
   return *this ^ other;
}

void
Word::operator-=
(const Word &other)
{
   *this ^= other;
}

Word
Word::operator*
(const Word &other) const
{
   Word result;

   for (int i=0; i<Word::Size; ++i)
      for (int j=0; j<Word::Size; ++j)
         result[i] += Field::AESMul(this->getField(i-j), other.getField(j));

   return result;
}

void
Word::operator*=
(const Word &other)
{
   this->setFields((*this * other).getFields());
}
