#include "badaes/cipher.hpp"

using namespace BadAES;

Cipher::Cipher
(Key *key, SBox *sBox, size_t blockSize)
{
   this->setKey(key);
   this->setBlockSize(blockSize);
   this->setSBox(sBox);
}

Cipher::Cipher
(const Cipher &cipher)
{
   this->setKey(cipher.getKey());
   this->setBlockSize(cipher.getBlockSize());
   this->setSBox(cipher.getSBox());
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
   this->initVector.resize(blockSize);
}

size_t
Cipher::getBlockSize
(void) const
{
   return this->blockSize;
}

void
Cipher::setInitVector
(std::vector<Word> initVector)
{
   if (initVector.size() != this->initVector.size())
      throw Exception("vector sizes are not equal");

   this->initVector = std::vector<Word>(initVector.begin(), initVector.end());
}

std::vector<Word>
Cipher::getInitVector
(void) const
{
   return this->initVector;
}

void
Cipher::generateVector
(void)
{
   std::vector<Word> newWords;

   /* EVE GO AWAY U R NOT WELCOME IN MY SHITTY RNG */
   srand(time(NULL));
   
   for (int i=0; i<this->blockSize; ++i)
   {
      std::vector<Field> newFields;

      for (int j=0; j<Word::Size; ++j)
         newFields.push_back(Field(rand() % 256));

      newWords.push_back(Word(newFields));
   }

   this->initVector = std::vector<Word>(newWords.begin(), newWords.end());
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
   if (round != this->numberOfRounds())
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
   std::vector<State> states;

   if (dataSize % (this->blockSize * Word::Size) != 0)
      throw Exception("buffer size must be a multiple of blocksize * word size");

   states = this->getStatesFromBuffer(dataBuffer, dataSize);

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

AESCipherECB::AESCipherECB
(Key *key)
   : Cipher(key, SBox::AESSBox(), AESCipherECB::BlockSize)
{
}

AESCipherECB::AESCipherECB
(const AESCipherECB &cipher)
   : Cipher(cipher)
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherECB::BlockSize);
}

AESCipherECB::AESCipherECB
(void)
   : Cipher()
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherECB::BlockSize);
}

AESCipherCBC::AESCipherCBC
(Key *key)
   : AESCipherECB(key)
{
}

AESCipherCBC::AESCipherCBC
(const AESCipherCBC &cipher)
   : AESCipherECB(cipher)
{
}

AESCipherCBC::AESCipherCBC
(void)
   : AESCipherECB()
{
}

uint8_t *
AESCipherCBC::encrypt
(uint8_t *dataBuffer, size_t dataSize, size_t *outSize)
{
   std::vector<State> states = this->getStatesFromBuffer(dataBuffer, dataSize);
   std::vector<Word> rotatingVector(this->blockSize);

   this->generateVector();

   rotatingVector = std::vector<Word>(this->initVector.begin(), this->initVector.end());

   for (size_t i=0; i<states.size(); ++i)
   {
      states[i].addVector(rotatingVector);
      
      for (size_t j=0; j<=this->numberOfRounds(); ++j)
         this->encryptionRound(&states[i], j);

      rotatingVector = states[i].getWords();
   }

   return this->dumpStatesToBuffer(states, outSize);
}

uint8_t *
AESCipherCBC::decrypt
(uint8_t *dataBuffer, size_t dataSize, size_t *outSize)
{
   std::vector<State> states;
   std::vector<Word> previousVector(this->blockSize), nextVector(this->blockSize);

   if (dataSize % (this->blockSize * Word::Size) != 0)
      throw Exception("buffer size must be a multiple of blocksize * word size");

   states = this->getStatesFromBuffer(dataBuffer, dataSize);
   previousVector = std::vector<Word>(this->initVector.begin(), this->initVector.end());

   for (size_t i=0; i<states.size(); ++i)
   {
      nextVector = states[i].getWords();
      
      for (int j=this->numberOfRounds(); j>=0; --j)
         this->decryptionRound(&states[i], j);

      states[i].addVector(previousVector);
      previousVector = nextVector;
   }

   return this->dumpStatesToBuffer(states, outSize);
}

AESCipherPCBC::AESCipherPCBC
(Key *key)
   : AESCipherECB(key)
{
}

AESCipherPCBC::AESCipherPCBC
(const AESCipherPCBC &cipher)
   : AESCipherECB(cipher)
{
}

AESCipherPCBC::AESCipherPCBC
(void)
   : AESCipherECB()
{
}

uint8_t *
AESCipherPCBC::encrypt
(uint8_t *dataBuffer, size_t dataSize, size_t *outSize)
{
   std::vector<State> states = this->getStatesFromBuffer(dataBuffer, dataSize);
   std::vector<Word> rotatingVector(this->blockSize);

   this->generateVector();

   rotatingVector = std::vector<Word>(this->initVector.begin(), this->initVector.end());

   for (size_t i=0; i<states.size(); ++i)
   {
      std::vector<Word> plaintext, ciphertext;

      plaintext = states[i].getWords();
      
      states[i].addVector(rotatingVector);
      
      for (size_t j=0; j<=this->numberOfRounds(); ++j)
         this->encryptionRound(&states[i], j);

      ciphertext = states[i].getWords();

      for (size_t j=0; j<this->blockSize; ++j)
         rotatingVector[j] = plaintext[j] ^ ciphertext[j];
   }

   return this->dumpStatesToBuffer(states, outSize);
}

uint8_t *
AESCipherPCBC::decrypt
(uint8_t *dataBuffer, size_t dataSize, size_t *outSize)
{
   std::vector<State> states;
   std::vector<Word> rotatingVector(this->blockSize);

   if (dataSize % (this->blockSize * Word::Size) != 0)
      throw Exception("buffer size must be a multiple of blocksize * word size");

   states = this->getStatesFromBuffer(dataBuffer, dataSize);
   rotatingVector = std::vector<Word>(this->initVector.begin(), this->initVector.end());

   for (size_t i=0; i<states.size(); ++i)
   {
      std::vector<Word> plaintext, ciphertext;

      ciphertext = states[i].getWords();
      
      for (int j=this->numberOfRounds(); j>=0; --j)
         this->decryptionRound(&states[i], j);

      states[i].addVector(rotatingVector);

      plaintext = states[i].getWords();

      for (size_t j=0; j<this->blockSize; ++j)
         rotatingVector[j] = ciphertext[j] ^ plaintext[j];
   }

   return this->dumpStatesToBuffer(states, outSize);
}

AESCipherCFB::AESCipherCFB
(Key *key)
   : AESCipherECB(key)
{
}

AESCipherCFB::AESCipherCFB
(const AESCipherCFB &cipher)
   : AESCipherECB(cipher)
{
}

AESCipherCFB::AESCipherCFB
(void)
   : AESCipherECB()
{
}

/* rivest: how many layers of blockchaining r u on
   rijindael: like, maybe cipherblock chaining propogation my dude
   rivest: u are like little baby, watch this */
uint8_t *
AESCipherCFB::encrypt
(uint8_t *dataBuffer, size_t dataSize, size_t *outSize)
{
   std::vector<State> states = this->getStatesFromBuffer(dataBuffer, dataSize);
   std::vector<Word> rotatingVector(this->blockSize);

   this->generateVector();

   rotatingVector = std::vector<Word>(this->initVector.begin(), this->initVector.end());

   for (size_t i=0; i<states.size(); ++i)
   {
      State vectorState(rotatingVector);
      std::vector<Word> stateWords;
      
      for (size_t j=0; j<=this->numberOfRounds(); ++j)
         this->encryptionRound(&vectorState, j);

      for (size_t j=0; j<this->blockSize; ++j)
         states[i][j] = states[i][j] ^ vectorState[j];
      
      rotatingVector = states[i].getWords();
   }

   return this->dumpStatesToBuffer(states, outSize);
}

uint8_t *
AESCipherCFB::decrypt
(uint8_t *dataBuffer, size_t dataSize, size_t *outSize)
{
   std::vector<State> states;
   std::vector<Word> rotatingVector(this->blockSize);

   if (dataSize % (this->blockSize * Word::Size) != 0)
      throw Exception("buffer size must be a multiple of blocksize * word size");

   states = this->getStatesFromBuffer(dataBuffer, dataSize);
   rotatingVector = std::vector<Word>(this->initVector.begin(), this->initVector.end());

   for (size_t i=0; i<states.size(); ++i)
   {
      State vectorState(rotatingVector);
      std::vector<Word> stateWords;
      
      for (size_t j=0; j<=this->numberOfRounds(); ++j)
         this->encryptionRound(&vectorState, j);

      rotatingVector = states[i].getWords();

      for (size_t j=0; j<this->blockSize; ++j)
         states[i][j] = states[i][j] ^ vectorState[j];
   }

   return this->dumpStatesToBuffer(states, outSize);
}

AESCipherOFB::AESCipherOFB
(Key *key)
   : AESCipherECB(key)
{
}

AESCipherOFB::AESCipherOFB
(const AESCipherOFB &cipher)
   : AESCipherECB(cipher)
{
}

AESCipherOFB::AESCipherOFB
(void)
   : AESCipherECB()
{
}

/* rivest: how many layers of blockchaining r u on
   rijindael: like, maybe cipherblock chaining propogation my dude
   rivest: u are like little baby, watch this */
uint8_t *
AESCipherOFB::encrypt
(uint8_t *dataBuffer, size_t dataSize, size_t *outSize)
{
   std::vector<State> states = this->getStatesFromBuffer(dataBuffer, dataSize);
   std::vector<Word> rotatingVector(this->blockSize);

   this->generateVector();

   rotatingVector = std::vector<Word>(this->initVector.begin(), this->initVector.end());

   for (size_t i=0; i<states.size(); ++i)
   {
      State vectorState(rotatingVector);
      std::vector<Word> stateWords;
      
      for (size_t j=0; j<=this->numberOfRounds(); ++j)
         this->encryptionRound(&vectorState, j);
      
      rotatingVector = vectorState.getWords();

      for (size_t j=0; j<this->blockSize; ++j)
         states[i][j] = states[i][j] ^ vectorState[j];
   }

   return this->dumpStatesToBuffer(states, outSize);
}

uint8_t *
AESCipherOFB::decrypt
(uint8_t *dataBuffer, size_t dataSize, size_t *outSize)
{
   std::vector<State> states;
   std::vector<Word> rotatingVector(this->blockSize);

   if (dataSize % (this->blockSize * Word::Size) != 0)
      throw Exception("buffer size must be a multiple of blocksize * word size");

   states = this->getStatesFromBuffer(dataBuffer, dataSize);
   rotatingVector = std::vector<Word>(this->initVector.begin(), this->initVector.end());

   for (size_t i=0; i<states.size(); ++i)
   {
      State vectorState(rotatingVector);
      std::vector<Word> stateWords;
      
      for (size_t j=0; j<=this->numberOfRounds(); ++j)
         this->encryptionRound(&vectorState, j);

      rotatingVector = vectorState.getWords();

      for (size_t j=0; j<this->blockSize; ++j)
         states[i][j] = states[i][j] ^ vectorState[j];
   }

   return this->dumpStatesToBuffer(states, outSize);
}
