#include "badaes/cipher.hpp"

using namespace BadAES;

CipherECB::CipherECB
(Key *key, SBox *sBox, size_t blockSize)
{
   this->setKey(key);
   this->setBlockSize(blockSize);
   this->setSBox(sBox);
}

CipherECB::CipherECB
(const CipherECB &cipher)
{
   this->setKey(cipher.getKey());
   this->setBlockSize(cipher.getBlockSize());
   this->setSBox(cipher.getSBox());
}

CipherECB::CipherECB
(void)
{
   this->key = NULL;
}

void
CipherECB::setKey
(Key *key)
{
   this->key = key;
}

Key *
CipherECB::getKey
(void) const
{
   return this->key;
}

void
CipherECB::setSBox
(SBox *sBox)
{
   this->sBox = sBox;
}

SBox *
CipherECB::getSBox
(void) const
{
   return this->sBox;
}

void
CipherECB::setBlockSize
(size_t blockSize)
{
   this->blockSize = blockSize;
   this->initVector.resize(blockSize);
}

size_t
CipherECB::getBlockSize
(void) const
{
   return this->blockSize;
}

void
CipherECB::setInitVector
(std::vector<Word> initVector)
{
   if (initVector.size() != this->initVector.size())
      throw Exception("vector sizes are not equal");

   this->initVector = std::vector<Word>(initVector.begin(), initVector.end());
}

std::vector<Word>
CipherECB::getInitVector
(void) const
{
   return this->initVector;
}

void
CipherECB::generateVector
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
CipherECB::numberOfRounds
(void)
{
   if (this->key == NULL)
      return 0;

   return this->key->getSize()+6;
}

void
CipherECB::encryptionRound
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
CipherECB::decryptionRound
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
CipherECB::encrypt
(uint8_t *dataBuffer, size_t dataSize, size_t *outSize)
{
   std::vector<State> states = this->getStatesFromBuffer(dataBuffer, dataSize);

   for (size_t i=0; i<states.size(); ++i)
      for (size_t j=0; j<=this->numberOfRounds(); ++j)
         this->encryptionRound(&states[i], j);

   return this->dumpStatesToBuffer(states, outSize);
}

uint8_t *
CipherECB::decrypt
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
CipherECB::getStatesFromBuffer
(uint8_t *dataBuffer, size_t dataSize)
{
   std::vector<State> result;
   size_t dataChunks;

   /* GO AWAY EVE */
   srand(time(NULL));

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
               wordFields.push_back(Field(rand() % 256));
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
CipherECB::dumpStatesToBuffer
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

CipherCBC::CipherCBC
(Key *key, SBox *sBox, size_t blockSize)
   : CipherECB(key, sBox, blockSize)
{
}

CipherCBC::CipherCBC
(const CipherCBC &cipher)
   : CipherECB(cipher)
{
}

CipherCBC::CipherCBC
(void)
   : CipherECB()
{
}

uint8_t *
CipherCBC::encrypt
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
CipherCBC::decrypt
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

CipherPCBC::CipherPCBC
(Key *key, SBox *sBox, size_t blockSize)
   : CipherECB(key, sBox, blockSize)
{
}

CipherPCBC::CipherPCBC
(const CipherPCBC &cipher)
   : CipherECB(cipher)
{
}

CipherPCBC::CipherPCBC
(void)
   : CipherECB()
{
}

uint8_t *
CipherPCBC::encrypt
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
CipherPCBC::decrypt
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

CipherCFB::CipherCFB
(Key *key, SBox *sBox, size_t blockSize)
   : CipherECB(key, sBox, blockSize)
{
}

CipherCFB::CipherCFB
(const CipherCFB &cipher)
   : CipherECB(cipher)
{
}

CipherCFB::CipherCFB
(void)
   : CipherECB()
{
}

/* rivest: how many layers of blockchaining r u on
   rijindael: like, maybe cipherblock chaining propogation my dude
   rivest: u are like little baby, watch this */
uint8_t *
CipherCFB::encrypt
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
CipherCFB::decrypt
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

CipherOFB::CipherOFB
(Key *key, SBox *sBox, size_t blockSize)
   : CipherECB(key, sBox, blockSize)
{
}

CipherOFB::CipherOFB
(const CipherOFB &cipher)
   : CipherECB(cipher)
{
}

CipherOFB::CipherOFB
(void)
   : CipherECB()
{
}

/* rivest: how many layers of blockchaining r u on
   rijindael: like, maybe cipherblock chaining propogation my dude
   rivest: u are like little baby, watch this */
uint8_t *
CipherOFB::encrypt
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
CipherOFB::decrypt
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

AESCipherECB::AESCipherECB
(Key *key)
   : CipherECB(key, SBox::AESSBox(), AESCipherECB::BlockSize)
{
}

AESCipherECB::AESCipherECB
(const AESCipherECB &cipher)
   : CipherECB(cipher)
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherECB::BlockSize);
}

AESCipherECB::AESCipherECB
(void)
   : CipherECB()
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherECB::BlockSize);
}

AESCipherCBC::AESCipherCBC
(Key *key)
   : CipherCBC(key, SBox::AESSBox(), AESCipherCBC::BlockSize)
{
}

AESCipherCBC::AESCipherCBC
(const AESCipherCBC &cipher)
   : CipherCBC(cipher)
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherCBC::BlockSize);
}

AESCipherCBC::AESCipherCBC
(void)
   : CipherCBC()
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherCBC::BlockSize);
}

AESCipherPCBC::AESCipherPCBC
(Key *key)
   : CipherPCBC(key, SBox::AESSBox(), AESCipherPCBC::BlockSize)
{
}

AESCipherPCBC::AESCipherPCBC
(const AESCipherPCBC &cipher)
   : CipherPCBC(cipher)
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherPCBC::BlockSize);
}

AESCipherPCBC::AESCipherPCBC
(void)
   : CipherPCBC()
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherPCBC::BlockSize);
}

AESCipherCFB::AESCipherCFB
(Key *key)
   : CipherCFB(key, SBox::AESSBox(), AESCipherCFB::BlockSize)
{
}

AESCipherCFB::AESCipherCFB
(const AESCipherCFB &cipher)
   : CipherCFB(cipher)
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherCFB::BlockSize);
}

AESCipherCFB::AESCipherCFB
(void)
   : CipherCFB()
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherCFB::BlockSize);
}

AESCipherOFB::AESCipherOFB
(Key *key)
   : CipherOFB(key, SBox::AESSBox(), AESCipherOFB::BlockSize)
{
}

AESCipherOFB::AESCipherOFB
(const AESCipherOFB &cipher)
   : CipherOFB(cipher)
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherOFB::BlockSize);
}

AESCipherOFB::AESCipherOFB
(void)
   : CipherOFB()
{
   this->setSBox(SBox::AESSBox());
   this->setBlockSize(AESCipherOFB::BlockSize);
}
