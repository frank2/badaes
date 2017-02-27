#include "badaes/key.hpp"

using namespace BadAES;

Key::Key
(std::vector<Word> words, const SBox *sBox)
{
   if (this->size == 0)
      this->setSize(words.size());
   
   this->setWords(words);
   this->setSBox(sBox);
   this->setRoundConstant(Field(1));
}

Key::Key
(uint8_t *keyData, size_t bufferSize, const SBox *sBox)
{
   std::vector<Word> newWords;
   
   if (bufferSize % Word::Size != 0)
      throw Exception("buffer must be a multiple of the size of a Word object");

   if (this->size == 0)
      this->setSize(bufferSize / Word::Size);
   
   this->setWords(keyData, bufferSize);
   this->setSBox(sBox);
   this->setRoundConstant(Field(1));
}

Key::Key
(size_t size, const SBox *sBox)
{
   this->setSize(size);
   this->setSBox(sBox);
   this->setRoundConstant(Field(1));
}

Key::Key
(const Key &key)
{
   if (this->size == 0)
      this->setSize(key.getSize());
   
   this->setWords(key.getWords());
   this->setSBox(key.getSBox());
   this->setExpansion(key.getExpansion());
   this->setRoundConstant(key.getRoundConstant());
}

Key::Key
(void)
{
   this->setRoundConstant(Field(1));
}

Key
Key::Generate
(size_t size, const SBox *sBox)
{
   std::vector<Word> newKeyVector;
   Key newKey(size, sBox);

   /* lol this is so bad plz don't tell Eve what time you generated this key */
   srand(time(NULL));

   for (size_t i=0; i<size; ++i)
   {
      std::vector<Field> fields(4);

      for (int j=0; j<Word::Size; ++j)
         fields[j] = Field(rand() % 256);

      newKeyVector.push_back(Word(fields));
   }

   newKey.setWords(newKeyVector);

   return newKey;
}

Word
Key::operator[]
(size_t index)
{
   return this->getRound(index);
}

void
Key::setSize
(size_t size)
{
   this->size = size;
   this->words.resize(size);
}

size_t
Key::getSize
(void) const
{
   return this->size;
}

void
Key::setWords
(std::vector<Word> words)
{
   if (words.size() != this->size)
      throw Exception("word vector not equal to key size");

   this->words = std::vector<Word>(words.begin(), words.end());
   this->expansion = std::vector<Word>(this->words.begin(), this->words.end());
}

void
Key::setWords
(uint8_t *keyData, size_t bufferSize)
{
   std::vector<Word> newWords;

   if (bufferSize % Word::Size != 0)
      throw Exception("buffer size must be a multiple of Word size");
   
   for (size_t i=0; i<this->size; ++i)
   {
      std::vector<Field> fields(4);
      
      for (int j=0; j<Word::Size; ++j)
         fields[j] = Field(keyData[i*Word::Size+j]);

      newWords.push_back(Word(fields));
   }

   this->setWords(newWords);
}

std::vector<Word>
Key::getWords
(void) const
{
   return this->words;
}

void
Key::setSBox
(const SBox *sBox)
{
   this->sBox = sBox;
}

const SBox *
Key::getSBox
(void) const
{
   return this->sBox;
}

void
Key::setExpansion
(std::vector<Word> expansion)
{
   this->expansion = std::vector<Word>(expansion.begin(), expansion.end());
}

std::vector<Word>
Key::getExpansion
(void) const
{
   return this->expansion;
}

void
Key::setRoundConstant
(Field constant)
{
   this->roundConstant = constant;
}

Field
Key::getRoundConstant
(void) const
{
   return this->roundConstant;
}

Word
Key::getRound
(size_t index)
{
   size_t expansionSize = this->expansion.size();
   
   if (index >= expansionSize)
   {
      for (size_t i=0; i<=index-expansionSize; ++i)
      {
         size_t baseIndex = i+expansionSize;
         Word word = this->expansion[baseIndex-1];

         if (baseIndex % this->size == 0)
         {
            if (baseIndex/this->size != 1 || this->roundConstant.getExponents() != 1)
               this->roundConstant = Field::AESMul(this->roundConstant, Field(2));
            
            word = this->sBox->subWord(word.rol());
            word[0] = word[0] ^ this->roundConstant;
         }
         else if (this->size > 6 && baseIndex % this->size == 4)
         {
            word = this->sBox->subWord(word);
         }

         this->expansion.push_back(word ^ this->expansion[baseIndex-this->size]);
      }
   }

   return this->expansion[index];
}

Key
Key::fork
(void) const
{
   Key result;
   size_t slice = this->expansion.size() - this->size;

   result.setSize(this->size);
   result.setWords(std::vector<Word>(this->expansion.begin()+slice
                                     ,this->expansion.end()));
   result.setRoundConstant(this->roundConstant);
   result.setSBox(this->sBox);

   return result;
}

AESKey::AESKey
(std::vector<Word> words)
   : Key(words, SBox::AESSBox())
{
}

AESKey::AESKey
(uint8_t *keyData, size_t bufferSize)
   : Key(keyData, bufferSize, SBox::AESSBox())
{
}

AESKey::AESKey
(const AESKey &key)
   : Key(key)
{
}

AESKey::AESKey
(const Key &key)
   : Key(key)
{
}

AESKey::AESKey
(size_t size)
   : Key(size, SBox::AESSBox())
{
}

AESKey::AESKey
()
   : Key()
{
   this->setSBox(SBox::AESSBox());
}

AESKey
AESKey::Generate
(size_t size)
{
   return AESKey(Key::Generate(size, SBox::AESSBox()));
}

AESKey128::AESKey128
(std::vector<Word> words)
   : AESKey(words)
{
}

AESKey128::AESKey128
(uint8_t *keyData, size_t bufferSize)
   : AESKey(keyData, bufferSize)
{
}

AESKey128::AESKey128
(const AESKey128 &key)
   : AESKey(key)
{
}

AESKey128::AESKey128
(const AESKey &key)
   : AESKey(key)
{
}

AESKey128::AESKey128
(const Key &key)
   : AESKey(key)
{
}

AESKey128::AESKey128
(void)
   : AESKey()
{
   this->setSize(AESKey128::Size);
}

AESKey128
AESKey128::Generate
(void)
{
   return AESKey128(AESKey::Generate(AESKey128::Size));
}

AESKey192::AESKey192
(std::vector<Word> words)
   : AESKey(words)
{
}

AESKey192::AESKey192
(uint8_t *keyData, size_t bufferSize)
   : AESKey(keyData, bufferSize)
{
}

AESKey192::AESKey192
(const AESKey192 &key)
   : AESKey(key)
{
}

AESKey192::AESKey192
(const AESKey &key)
   : AESKey(key)
{
}

AESKey192::AESKey192
(const Key &key)
   : AESKey(key)
{
}

AESKey192::AESKey192
(void)
   : AESKey()
{
   this->setSize(AESKey192::Size);
}

AESKey192
AESKey192::Generate
(void)
{
   return AESKey192(AESKey::Generate(AESKey192::Size));
}

AESKey256::AESKey256
(std::vector<Word> words)
   : AESKey(words)
{
}

AESKey256::AESKey256
(uint8_t *keyData, size_t bufferSize)
   : AESKey(keyData, bufferSize)
{
}

AESKey256::AESKey256
(const AESKey256 &key)
   : AESKey(key)
{
}

AESKey256::AESKey256
(const AESKey &key)
   : AESKey(key)
{
}

AESKey256::AESKey256
(const Key &key)
   : AESKey(key)
{
}

AESKey256::AESKey256
(void)
   : AESKey()
{
   this->setSize(AESKey256::Size);
}

AESKey256
AESKey256::Generate
(void)
{
   return AESKey256(AESKey::Generate(AESKey256::Size));
}
