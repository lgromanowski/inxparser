#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <sstream>

struct Header {
    uint32_t signature;
    uint16_t f4;
    uint8_t copyrights[98];
    uint32_t headerSize;
    uint32_t f6c; //
    uint32_t types; // Types
    uint32_t f74; //
    uint32_t f48; //
} __attribute__((packed));

struct Type {
    uint8_t fieldsCount;
    uint16_t unknown;
    uint8_t nameLength;

    std::string name;
};

struct Field {
    uint8_t type;
    uint8_t width;
    uint8_t nameLength;

    std::string name;
};

unsigned char* base = nullptr;

void dumpHeader(const Header& h) {
  printf("Signature: 0x%02X\n"
         "size: %u\n"
         "f4: 0x%02X (%u)\n"
         "f6c: 0x%02X (%u)\n"
         "f70: 0x%02X (%u)\n"
         "f74: 0x%02X (%u)\n"
         "f48: 0x%02X (%u)\n",
         h.signature,
         h.headerSize,
         h.f4, h.f4,
         h.f6c, h.f6c,
         h.types, h.types,
         h.f74, h.f74,
         h.f48, h.f48
         );
}

enum InxTypes {
  INX_STRING = 0,
  INX_CHAR,
  INX_SHORT,
  INX_INT,
  INX_NUMBER,
  INX_POINTER,
  INX_BOOL,
  INX_HWND,
  INX_UNKNOWN = 8,
  INX_STRUCT,
  INX_OBJECT,
  INX_ANSISTRING,

  INX_LAST
};


#define PTR(line, x) do { printf("### (%u) ptr: %p (offset: %p)\n", line, x, (void*)(x - base)); } while(0)

template <class T>
T get(unsigned char*& ptr) {
  T result = *(reinterpret_cast<T*>(ptr));
  ptr += sizeof(T);
  return result;
}

const char* getType(unsigned int i) {
  if (i < INX_LAST) {
    static const char * const types[INX_LAST] = {
      "STRING", "CHAR", "SHORT", "INT",
      "NUMBER", "POINTER", "BOOL", "HWND",
      "unknown8", "STRUC", "OBJECT", "ANSISTRING"
    };

    return types[i];
  }

  return "INVALID";
}

std::string getString(unsigned char*& ptr) {
  std::string result;
  unsigned int end = get<uint16_t>(ptr);
  for (unsigned int i = 0; i < end; ++i) {
    result += static_cast<char>(get<uint8_t>(ptr));
  }

  return result;
}

std::string getType2(unsigned char*& ptr) {
  static std::stringstream str;
  str.str("");

  uint8_t type = get<uint8_t>(ptr);
  uint16_t width = get<uint16_t>(ptr);
  str << getType(type);
  if (type == 9) {
    str << "_" << width << " " << getString(ptr);
  }
  else if (width != 1) {
    str << " " << getString(ptr) << "[" << width << "]";
  }

  return str.str();
}


void dumpStruc(unsigned char*& ptr) {
  PTR(__LINE__, ptr);
  unsigned int end = get<uint16_t>(ptr);
  unsigned int unk32 = get<uint16_t>(ptr);
  printf("string unk32: %u (0x%02x)\n", unk32, unk32);
  unk32 = get<uint16_t>(ptr);
  printf("string unk32: %u (0x%02x)\n", unk32, unk32);

  PTR(__LINE__, ptr);
  for (unsigned int i = 0; i < end; ++i) {
    printf("  %s %s\n", getType2(ptr).c_str(), getString(ptr).c_str());
  }
}

void dumpStrucs(unsigned char*& ptr) {
  unsigned char* p = ptr;
  PTR(__LINE__, p);
  unsigned int end = get<uint16_t>(p);
  PTR(__LINE__, p);
  printf("STRUCTS count: %u (0x%02x)\n", end, end);
  for (unsigned int i = 0; i < end; ++i) {
    printf("struc_%u\n", i);
    dumpStruc(p);
    printf("end\n");
  }
}

void dumpArgs(unsigned char*& ptr) {
  unsigned int n = get<uint16_t>(ptr);
  printf("  Args(%u): ", n);

  for (unsigned int i = 0; i < n; ++i) {
    unsigned int b = get<uint8_t>(ptr);
    unsigned int b2 = get<uint8_t>(ptr);
    bool byRef = false;
    bool skip = false;
    if (b == 0 || b == 11) {
      byRef = (b2 == 2);
    }
    else if (b >= 1 && b <= 7) {
      byRef = (b2 == 3);
    }
    else if (b == 10) {
      byRef = (b2 == 4);
    }
    else {
      printf("*** BAD ARG: %u\n", b);
      skip = true;
    }
    if (!skip) {
      if ((b >= 1 && b <= 7) || (b == 10) || (b == 11)) {
        printf("%s %s", byRef ? "BYREF" : "BYVAL", getType(b));
      }
      else {
        printf("(%u,%u)", b, b2);
      }
      if (i < n - 1) {
        printf(", ");
      }
    }
  }
  printf("\n");
}

void dumpFunc1(unsigned char*& ptr) {
  unsigned char b = get<uint8_t>(ptr);
  printf("  Flags: %c (0x%02X)\n", b, static_cast<unsigned int>(b));
  b = get<uint8_t>(ptr);
  printf("  Returns: %s\n", getType(b));
  printf("  Name: %s.%s\n", getString(ptr).c_str(), getString(ptr).c_str());
  ptr += 2;
  dumpArgs(ptr);
}

void dumpFunc2(unsigned char*& ptr) {
  unsigned char b = get<uint8_t>(ptr);
  printf("  Flags: %c (0x%02X)\n", b, static_cast<unsigned int>(b));
  b = get<uint8_t>(ptr);
  printf("  Returns: %s\n", getType(b));
  printf("  Name: %s\n", getString(ptr).c_str());
  printf("  Number: %u\n", get<uint16_t>(ptr));
  dumpArgs(ptr);
}

void dumpFuncs(unsigned char*& ptr) {
  unsigned char* p = ptr;
  unsigned int end = get<uint16_t>(p) - 1;
  for (unsigned int i = 0; i < end; ++i) {
    printf("func_%u\n", i);
    unsigned int b = get<uint8_t>(p);
    p--;
    if ((b & 1) != 0) {
      dumpFunc1(p);
    }
    else if ((b & 2) != 0) {
      dumpFunc2(p);
    }
    else {
      printf("Func error!\n");
      exit(1);
    }
    printf("end\n");
  }
}

void dumpTypes(unsigned char*& ptr) {

  unsigned char* p = ptr;
  unsigned int end = get<uint16_t>(p);
  for (unsigned int i = 0; i < end; ++i) {
    printf("typedef type_%03u\nbegin\n", i);

    unsigned int fieldsCount = get<uint16_t>(p);
    for (unsigned j = 0; j < fieldsCount; ++j) {
      unsigned int type = get<uint8_t>(p);
      unsigned int width = get<uint16_t>(p);

      if (type == 9) {
          printf("  type_%03u %s;\n", width, getString(p).c_str());
      }
      else if (width != 1) {
        printf("  %s %s[%u];\n", getType(type), getString(p).c_str(), width);
      }
      else {
        printf("  %s %s;\n", getType(type), getString(p).c_str());
      }
    }

    printf("end\n\n");
  }
}

int main(int argc, char** argv)
{
  if (argc == 2) {
    FILE* f = fopen(argv[1], "rb");
    if (f != nullptr){
      fseek(f, 0, SEEK_END);
      long size = ftell(f);

      if (size > 0) {
        fseek(f, 0, SEEK_SET);
        unsigned char* buf = new (std::nothrow) unsigned char[size + 1];
        if (buf != nullptr) {
          base = buf;
          memset(buf, 0, size+1);
          fread(buf, size, 1, f);
          fclose(f);

          Header h;
          memcpy(&h, buf, sizeof(h));

          dumpHeader(h);

          //unsigned char* strucs = buf + h.f70;
          //unsigned char* funcs = buf + h.f6c;
          unsigned char* types = buf + h.types;

          //dumpStrucs(strucs);
          //dumpFuncs(funcs);
          dumpTypes(types);

          delete[] buf;
        }
      }
      else {
        printf("Wrong file size: %ld", size);
        fclose(f);
      }
    }
  }
  else {
    printf("Usage: inxdumper setup.inx\n");
  }
  return 0;
}

