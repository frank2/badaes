#include "badaes/state.hpp"

using namespace BadAES;

State::State
(std::vector<Word> words, const SBox *sBox)
{
   if (this->blockSize == 0)
      this->blockSize = words.size();
   
   this->setWords(words);
   this->setSBox(sBox);
}

State::State
(uint8_t *stateData, size_t stateSize, const SBox *sBox)
{
   if (this->blockSize == 0)
   {
      if (stateSize % Word::Size != 0)
         throw Exception("key size must be a multiple of Word size");

      this->setBlockSize(stateSize / Word::Size);
   }

   this->setWords(stateData, stateSize);
   this->setSBox(sBox);
}

State::State
(size_t blockSize, const SBox *sBox)
{
   this->setBlockSize(blockSize);
   this->setSBox(sBox);
}

State::State
(const State &state)
{
   this->setBlockSize(state.getBlockSize());
   this->setWords(state.getWords());
   this->setSBox(state.getSBox());
}

State::State
(void)
{
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
   
   for (int i=0; i<this->blockSize; ++i)
   {
      std::vector<Field> fields;

      for (int j=0; j<Word::Size; ++j)
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
State::setSBox
(const SBox *sBox)
{
   this->sBox = sBox;
}

const SBox *
State::getSBox
(void) const
{
   return this->sBox;
}

void
State::addState
(State *state)
{
   if (state->getBlockSize() != this->blockSize)
      throw Exception("states are not equal in size");

   for (int i=0; i<this->blockSize; ++i)
      this->words[i] = this->words[i] ^ (*state)[i];
}

void
State::addRoundKey
(Key *key, size_t round)
{
   for (int i=0; i<this->blockSize; ++i)
      this->words[i] = this->words[i] ^ (*key)[round*this->blockSize+i];
}

void
State::subBytes
(void)
{
   for (int i=0; i<this->blockSize; ++i)
      this->words[i] = this->sBox->subWord(this->words[i]);
}

void
State::invSubBytes
(void)
{
   for (int i=0; i<this->blockSize; ++i)
      this->words[i] = this->sBox->invSubWord(this->words[i]);
}

void
State::shiftRows
(void)
{
   for (int i=1; i<Word::Size; ++i)
   {
      std::vector<Field> newRow(this->blockSize);

      for (int j=0; j<this->blockSize; ++j)
      {
         int index = (i+j) % this->blockSize;
         newRow[j] = (*this)[index][i];
      }

      for (int j=0; j<this->blockSize; ++j)
         (*this)[j][i] = newRow[j];
   }
}

void
State::invShiftRows
(void)
{
   for (int i=1; i<Word::Size; ++i)
   {
      std::vector<Field> newRow(this->blockSize);

      for (int j=0; j<this->blockSize; ++j)
      {
         int index = (-i+j) % this->blockSize;
         newRow[j] = (*this)[index][i];
      }

      for (int j=0; j<this->blockSize; ++j)
         (*this)[j][i] = newRow[j];
   }
}

void
State::mixColumns
(void)
{
   for (int i=0; i<this->blockSize; ++i)
      this->words[i] = Word({0x2, 0x1, 0x1, 0x3}) * this->words[i];
}

void
State::invMixColumns
(void)
{
   for (int i=0; i<this->blockSize; ++i)
      this->words[i] = Word({0xe, 0x9, 0xd, 0xb}) * this->words[i];
}

AESState::AESState
(std::vector<Word> words)
   : State(words, SBox::AESSBox())
{
}

AESState::AESState
(uint8_t *stateData, size_t stateSize)
   : State(stateData, stateSize, SBox::AESSBox())
{
}

AESState::AESState
(const AESState &state)
   : State(state)
{
   this->setBlockSize(AESState::BlockSize);
}

AESState::AESState
(const State &state)
   : State(state)
{
   this->setBlockSize(AESState::BlockSize);
}

AESState::AESState
(void)
   : State()
{
   this->setBlockSize(AESState::BlockSize);
}



