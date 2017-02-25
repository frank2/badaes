#include "main.hpp"

using namespace BadAES;

int
main
(int argc, char *argv[])
{
   Field fx, fy;
   Word wx, wy, wz;

   fx = Field(0x57);
   fy = Field(0x83);

   assert((fx ^ fy) == Field(0xd4));
   assert(Field::AESMul(fx, fy) == Field(0xc1));
   assert(Field::AESMul(fx, Field(0x13)) == Field(0xFE));

   wx = Word({0x2, 0x1, 0x1, 0x3});
   wy = Word({0xd4, 0xbf, 0x5d, 0x30});
   wz = Word({0x04, 0x66, 0x81, 0xe5});

   assert(wx * wy == wz);

   wx = Word({0x09, 0xcf, 0x4f, 0x3c});
   wy = Word({0xcf, 0x4f, 0x3c, 0x09});

   assert(wx.rol() == wy);
   assert(wy.ror() == wx);

   return 0;
}
