#include "badaes/cipher.hpp"

using namespace BadAES;

Cipher::Cipher
(Key *key, SBox *sBox, size_t blockSize)
{
   this->setKey(key);
   this->setBlockSize(blockSize);
}

Cipher::Cipher
(const Cipher &cipher)
{
   this->setKey(cipher.getKey());
   this->setBlockSize(cipher.getBlockSize());
}

Cipher::Cipher
(void)
{
   this->key = NULL;
}

void
Cipher::setKey
(Key *key)
{
   this->key = key;
}

Key *
Cipher::getKey
(void) const
{
   return this->key;
}

void
Cipher::setSBox
(SBox *sBox)
{
   this->sBox = sBox;
}

SBox *
Cipher::getSBox
(void) const
{
   return this->sBox;
}

void
Cipher::setBlockSize
(size_t blockSize)
{
   this->blockSize = blockSize;
}

size_t
Cipher::getBlockSize
(void) const
{
   return this->blockSize;
}

size_t
Cipher::numberOfRounds
(void)
{
   if (this->key == NULL)
      return 0;

   return this->key->getSize()+6;
}

void
Cipher::encryptionRound
(State *state, size_t round)
{
   if (round == this->numberOfRounds())
   {
      state->subBytes(this->sBox);
      state->shiftRows();
   }
   else if (round != 0)
   {
      state->subBytes(this->sBox);
      state->shiftRows();
      state->mixColumns();
   }
   
   state->addRoundKey(this->key, round);
}

void
Cipher::decryptionRound
(State *state, size_t round)
{
   if (round != 0)
   {
      state->invShiftRows();
      state->invSubBytes(this->sBox);
   }

   state->addRoundKey(this->key, round);

   if (round != 0 && round != this->numberOfRounds())
      state->invMixColumns();
}

uint8_t *
Cipher::encrypt
(uint8_t *dataBuffer, size_t dataSize, size_t *outSize)
{
   std::vector<State> states = this->getStatesFromBuffer(dataBuffer, dataSize);

   for (size_t i=0; i<states.size(); ++i)
      for (size_t j=0; j<=this->numberOfRounds(); ++j)
         this->encryptionRound(&states[i], j);

   return this->dumpStatesToBuffer(states, outSize);
}

uint8_t *
Cipher::decrypt
(uint8_t *dataBuffer, size_t dataSize, size_t *outSize)
{
   std::vector<State> states = this->getStatesFromBuffer(dataBuffer, dataSize);

   for (size_t i=0; i<states.size(); ++i)
      for (int j=this->numberOfRounds(); j>=0; --j)
         this->decryptionRound(&states[i], j);

   return this->dumpStatesToBuffer(states, outSize);
}

std::vector<State>
Cipher::getStatesFromBuffer
(uint8_t *dataBuffer, size_t dataSize)
{
   std::vector<State> result;
   size_t dataChunks;

   for (dataChunks=0; dataChunks<dataSize; dataChunks+=this->blockSize*Word::Size)
   {
      std::vector<Word> newWords;
      State state;

      state.setBlockSize(this->blockSize);
      
      for (size_t i=0; i<this->blockSize; ++i)
      {
         std::vector<Field> wordFields;

         for (size_t j=0; j<Word::Size; ++j)
         {
            if (dataChunks+i*this->blockSize+j >= dataSize)
               wordFields.push_back(Field(0));
            else
               wordFields.push_back(Field(dataBuffer[dataChunks+i*this->blockSize+j]));
         }

         newWords.push_back(Word(wordFields));
      }

      state.setWords(newWords);
      result.push_back(state);
   }

   return result;
}

uint8_t *
Cipher::dumpStatesToBuffer
(std::vector<State> states, size_t *outSize)
{
   uint8_t *result;
   size_t blockByteSize = this->blockSize * Word::Size;

   *outSize = blockByteSize * states.size();
   result = new uint8_t[*outSize];

   for (size_t i=0; i<states.size(); ++i)
      for (size_t j=0; j<this->blockSize; ++j)
         for (size_t k=0; k<Word::Size; ++k)
            result[i*blockByteSize+j*Word::Size+k] = (uint8_t)states[i][j][k].getExponents();

   return result;
}

AESCipher::AESCipher
(Key *key, size_t blockSize)
   : Cipher(key, SBox::AESSBox(), blockSize)
{
}

AESCipher::AESCipher
(const AESCipher &cipher)
   : Cipher(cipher)
{
}

AESCipher::AESCipher
(void)
   : Cipher()
{
}
