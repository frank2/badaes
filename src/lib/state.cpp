#include "badaes/state.hpp"

using namespace BadAES;

State::State
(std::vector<Word> words)
{
   if (this->blockSize == 0)
      this->setBlockSize(words.size());
   
   this->setWords(words);
}

State::State
(uint8_t *stateData, size_t stateSize)
{
   if (this->blockSize == 0)
   {
      if (stateSize % Word::Size != 0)
         throw Exception("key size must be a multiple of Word size");

      this->setBlockSize(stateSize / Word::Size);
   }

   this->setWords(stateData, stateSize);
}

State::State
(size_t blockSize)
{
   this->setBlockSize(blockSize);
}

State::State
(const State &state)
{
   this->setBlockSize(state.getBlockSize());
   this->setWords(state.getWords());
}

State::State
(void)
{
   if (this->blockSize != 0)
      this->words.resize(this->blockSize);
}

Word &
State::operator[]
(int index)
{
   if (index < 0)
      return this->words[index+this->blockSize];
   else
      return this->words[index];
}

void
State::setBlockSize
(size_t blockSize)
{
   this->blockSize = blockSize;
   this->words.resize(blockSize);
}

size_t
State::getBlockSize
(void) const
{
   return this->blockSize;
}

void
State::setWords
(std::vector<Word> words)
{
   if (words.size() != this->blockSize)
      throw Exception("input vector not equal to block size");
   
   this->words = std::vector<Word>(words.begin(), words.end());
}

void
State::setWords
(uint8_t *stateData, size_t stateSize)
{
   std::vector<Word> newWords;
   
   if (stateSize % Word::Size != 0)
      throw Exception("state size must be a multiple of Word size");

   if (stateSize / Word::Size != this->blockSize)
      throw Exception("state size not equal to  block state size");
   
   for (size_t i=0; i<this->blockSize; ++i)
   {
      std::vector<Field> fields;

      for (size_t j=0; j<Word::Size; ++j)
         fields.push_back(Field(stateData[i*Word::Size+j]));

      newWords.push_back(Word(fields));
   }

   this->setWords(newWords);
}

std::vector<Word>
State::getWords
(void) const
{
   return this->words;
}

void
State::addState
(State *state)
{
   if (this->blockSize != state->getBlockSize())
      throw Exception("states not equal in size");

   for (size_t i=0; i<this->blockSize; ++i)
      this->words[i] = this->words[i] ^ (*state)[i];
}

void
State::addRoundKey
(Key *key, size_t round)
{
   for (size_t i=0; i<this->blockSize; ++i)
      this->words[i] = this->words[i] ^ (*key)[round*this->blockSize+i];
}

void
State::subBytes
(const SBox *sBox)
{
   for (size_t i=0; i<this->blockSize; ++i)
      this->words[i] = sBox->subWord(this->words[i]);
}

void
State::invSubBytes
(const SBox *sBox)
{
   for (size_t i=0; i<this->blockSize; ++i)
      this->words[i] = sBox->invSubWord(this->words[i]);
}

void
State::shiftRows
(void)
{
   for (size_t i=1; i<Word::Size; ++i)
   {
      std::vector<Field> newRow(this->blockSize);

      for (size_t j=0; j<this->blockSize; ++j)
      {
         int index = (i+j) % this->blockSize;
         newRow[j] = (*this)[index][i];
      }

      for (size_t j=0; j<this->blockSize; ++j)
         (*this)[j][i] = newRow[j];
   }
}

void
State::invShiftRows
(void)
{
   for (size_t i=1; i<Word::Size; ++i)
   {
      std::vector<Field> newRow(this->blockSize);

      for (size_t j=0; j<this->blockSize; ++j)
      {
         int index = (-((long)i)+j) % this->blockSize;
         newRow[j] = (*this)[index][i];
      }

      for (size_t j=0; j<this->blockSize; ++j)
         (*this)[j][i] = newRow[j];
   }
}

void
State::mixColumns
(void)
{
   for (size_t i=0; i<this->blockSize; ++i)
      this->words[i] = Word({0x2, 0x1, 0x1, 0x3}) * this->words[i];
}

void
State::invMixColumns
(void)
{
   for (size_t i=0; i<this->blockSize; ++i)
      this->words[i] = Word({0xe, 0x9, 0xd, 0xb}) * this->words[i];
}
