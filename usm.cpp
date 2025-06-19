#include <bitset>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iosfwd>
#include <iostream>
#include <map>
#include <numeric>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

enum class ENDIAN { BIG, LITTLE };

template <typename uint_type>
uint_type char_to_uint(const std::vector<char> &chr, size_t offset,
                       ENDIAN endian = ENDIAN::BIG) {
  static_assert(std::is_unsigned<uint_type>::value, "只允許 unsigned 數字類別");
  constexpr size_t byteCount = sizeof(uint_type);

  if (chr.size() < offset + byteCount) {
    throw std::out_of_range("vector長度不夠:" + std::to_string(chr.size()) +
                            " 取值:" + std::to_string(offset) +
                            " 以及後續需要的長度:" + std::to_string(byteCount));
  }
  uint_type result = 0;
  if (endian == ENDIAN::BIG) {
    for (size_t i = 0; i < byteCount; ++i) {
      result <<= 8;
      result |= static_cast<uint8_t>(chr[offset + i]);
    }
  } else if (endian == ENDIAN::LITTLE) {
    for (size_t i = 0; i < byteCount; ++i) {
      result |= static_cast<uint64_t>(static_cast<uint8_t>(chr[offset + i]))
                << (8 * i);
    }

  } else
    throw std::logic_error("未知的endian類別");

  return result;
}

const size_t CHUNK_HEADER_SIZE = 8;

// Chunk 資訊結構體 (與之前相同)
struct ChunkInfo {
  char magic[4];                  // 0~3 magic
  uint32_t payload_size;          // 4~7 payload 大小
  std::vector<char> payload_data; // 8+ payload 的資料
};

// 照著payload前24 byte填寫
struct PayloadInfo {
  uint8_t unknown_1;   // 0 未知1
  uint8_t data_offset; // 1 實際資料開始位置 chunk頭到 data 頭
  uint16_t padding;    // 2~3 payload尾 到chunk尾 的padding
  uint8_t channel;     // 4 通道
  uint16_t unknown_2;  // 5~6 未知2
  uint8_t type_raw;    // 7 種類
  uint32_t frame_time; // 8~11 幀時間
  uint32_t frame_rate; // 12~15幀率
  uint64_t unknown_3;  // 16~23未知3

  std::vector<char> data; // 24+ data

  PayloadInfo(std::vector<char> &chrs) {
    if (chrs.size() < 25)
      throw std::out_of_range("解析Payload時 傳入的vector過小。");
    unknown_1 = (uint8_t)chrs[0];
    data_offset = (uint8_t)chrs[1];
    padding = char_to_uint<uint16_t>(chrs, 2);
    channel = (uint8_t)chrs[4];
    unknown_2 = char_to_uint<uint16_t>(chrs, 5);
    type_raw = (uint8_t)chrs[7];
    frame_time = char_to_uint<uint32_t>(chrs, 8);
    frame_rate = char_to_uint<uint32_t>(chrs, 12);
    unknown_3 = char_to_uint<uint64_t>(chrs, 16);
    data = std::vector<char>(chrs.begin() + 24, chrs.end() - padding);
  }
};

struct IVF_Info {
  /*bytes 0-3  signature: 'DKIF'
    bytes 4-5    version (should be 0)
    bytes 6-7    length of header in bytes
    bytes 8-11   codec FourCC (e.g., 'VP80')
    bytes 12-13  width in pixels
    bytes 14-15  height in pixels
    bytes 16-19  frame rate
    bytes 20-23  time scale
    bytes 24-27  number of frames in file
    bytes 28-31  unused
    */
  char magic[4];
  uint16_t version;
  uint16_t header_length;
  char codec[4];
  uint16_t width;
  uint16_t height;
  uint32_t frame_rate;
  uint32_t time;
  uint32_t frames_number;
  uint32_t unused;
  IVF_Info(const std::vector<char> &data, size_t offset) {
    if (data.size() < offset + 32) {
      throw std::out_of_range("IVF header資料長度不足");
    }
    std::memcpy(magic, &data[offset], 4);
    version = char_to_uint<uint16_t>(data, offset + 4, ENDIAN::LITTLE);
    header_length = char_to_uint<uint16_t>(data, offset + 6, ENDIAN::LITTLE);
    std::memcpy(codec, &data[offset + 8], 4);
    width = char_to_uint<uint16_t>(data, offset + 12, ENDIAN::LITTLE);
    height = char_to_uint<uint16_t>(data, offset + 14, ENDIAN::LITTLE);
    frame_rate = char_to_uint<uint32_t>(data, offset + 16, ENDIAN::LITTLE);
    time = char_to_uint<uint32_t>(data, offset + 20, ENDIAN::LITTLE);
    frames_number = char_to_uint<uint32_t>(data, offset + 24, ENDIAN::LITTLE);
    unused = char_to_uint<uint32_t>(data, offset + 28, ENDIAN::LITTLE);
  }
};

struct IVF_frame_data {
  uint32_t size;      // 0~3 header之後的data大小
  uint64_t timestamp; // 4~11 時間
  std::vector<char> data;
  IVF_frame_data(const std::vector<char> &data, size_t offset) {
    if (data.size() < offset + 8) {
      throw std::out_of_range("IVF_frame_data header資料長度不足");
    }
    size = char_to_uint<uint32_t>(data, offset, ENDIAN::LITTLE);
    if (data.size() < offset + 8 + size) {
      std::ostringstream oss;
      oss << "IVF_frame_data 聲明data長度不足(輸入data.size:" << data.size()
          << ", 聲明size:" << size << ")";
      throw std::out_of_range(oss.str());
    }
    timestamp = char_to_uint<uint64_t>(data, offset + 4, ENDIAN::LITTLE);
    this->data.assign(data.begin() + offset + 12, data.begin() + offset + size);
  }
};

const std::map<uint8_t, std::string> KNOWN_PAYLOAD_TYPES = {
    {0x00, "stream(影/音訊)"},
    {0x01, "header(開頭/CRID)"},
    {0x02, "section_end(標記某個段落結束)"},
    {0x03, "seek(標記查找位置)"}};

enum class DATA_TYPE {
  CHAR,   // 10000
  UCHAR,  // 10001
  SHORT,  // 10010
  USHORT, // 10011
  INT,    // 10100
  UINT,   // 10101
  LONG,   // 10110
  ULONG,  // 10111
  FLOAT,  // 11000
  DOUBLE, // 11001
  STRING, // 11010 头指针为4B，指向字符串数据
  BYTE    // 11011 头指针与尾指针各4B，指向byte流数据
};

// 已知的 USM/CRI chunk Magic (與之前相同)
const std::map<std::string, std::string> KNOWN_CHUNK_TYPES = {
    {"CRID", "CRI USM Header (Outer wrapper)"},
    {"@UTF", "UTF Table (Metadata, often contains track info, etc.)"},
    {"@SFV", "Sofdec Video Stream"},
    {"@SFA", "Sofdec Audio Stream"},
    {"@ADX", "ADX Audio Stream"},
    {"@AHX", "AHX Audio Stream"},
    {"@HCA", "HCA Audio Stream"},
    {"@VP9", "VP9 Video Stream"},
    {"H264", "H.264 Video Stream"},
    {"AV01", "AV1 Video Stream"},
    {"OPUS", "Opus Audio Stream"},
    {"@ALP", "Alpha Channel Stream"},
    {"@SUB", "Subtitle Stream"},
    {"INFO", "Information Chunk"},
    {"SEEK", "Seek Table Chunk"}};

std::string dataTypeToString(DATA_TYPE type) {
  switch (type) {
  case DATA_TYPE::CHAR:
    return "CHAR";
  case DATA_TYPE::UCHAR:
    return "UCHAR";
  case DATA_TYPE::SHORT:
    return "SHORT";
  case DATA_TYPE::USHORT:
    return "USHORT";
  case DATA_TYPE::INT:
    return "INT";
  case DATA_TYPE::UINT:
    return "UINT";
  case DATA_TYPE::LONG:
    return "LONG";
  case DATA_TYPE::ULONG:
    return "ULONG";
  case DATA_TYPE::FLOAT:
    return "FLOAT";
  case DATA_TYPE::DOUBLE:
    return "DOUBLE";
  case DATA_TYPE::STRING:
    return "STRING";
  case DATA_TYPE::BYTE:
    return "BYTE";
  default:
    return "UNKNOWN";
  }
}

std::string char_to_string(std::vector<char> &vec, size_t pos) {
  if (pos >= vec.size())
    return "";
  // 可能會有未定義行為 如果輸入的檔案是壞掉的 但沒差 不重要
  return std::string(&vec[pos]); // 要保證從 pos 開始有 \0 結尾
}

// 從 ifstream 讀取一個大端序的 32 位元無符號整數
bool read_u32_be(char bytes[4], uint32_t &value) {
  value = (static_cast<uint32_t>(bytes[0]) << 24) |
          (static_cast<uint32_t>(bytes[1]) << 16) |
          (static_cast<uint32_t>(bytes[2]) << 8) |
          (static_cast<uint32_t>(bytes[3]));
  return true;
}

// 嘗試在指定的位移解析一個 Chunk
// 返回 true 如果成功解析，false 如果失敗 (例如，到達檔案末尾或讀取錯誤)
bool parse_one_chunk(std::ifstream &ifs, size_t chunk_offset, ChunkInfo &chunk,
                     std::ostream &error) {
  auto read_bytes = [&](std::streamoff offset, char *buffer,
                        std::streamsize size,
                        const std::string &context) -> bool {
    ifs.seekg(offset);
    if (!ifs.read(buffer, size)) {
      error << "錯誤：在位移 0x" << std::hex << offset << std::dec << " 讀取 "
            << context << " 時";
      if (ifs.eof() && ifs.gcount() < size) {
        error << " 到達檔案結尾。\n";
      } else if (!ifs.eof()) {
        error << " 讀取失敗 (非 EOF)。\n";
      } else {
        error << " 發生未知錯誤。\n";
      }
      return false;
    }
    return true;
  };
  char magic_temp[4] = {0}; // 改為4個字元，與 magic 大小一致
  if (!read_bytes(chunk_offset, magic_temp, 4, "chunk 類型 (magic)"))
    return false;
  std::memcpy(chunk.magic, magic_temp, 4);

  char payload_size_temp[4];
  if (!read_bytes(chunk_offset + 4, payload_size_temp, 4,
                  "Chunk '" + std::string(chunk.magic, 4) +
                      "' 的 Payload 大小"))
    return false;

  chunk.payload_size =
      (static_cast<uint32_t>(static_cast<unsigned char>(payload_size_temp[0]))
       << 24) |
      (static_cast<uint32_t>(static_cast<unsigned char>(payload_size_temp[1]))
       << 16) |
      (static_cast<uint32_t>(static_cast<unsigned char>(payload_size_temp[2]))
       << 8) |
      (static_cast<uint32_t>(static_cast<unsigned char>(payload_size_temp[3])));
  chunk.payload_data.resize(chunk.payload_size);
  if (!read_bytes(
          chunk_offset + 8, chunk.payload_data.data(), chunk.payload_size,
          "Chunk '" + std::string(chunk.magic, 4) + "' 的 Payload 內容"))
    return false;
  return true;
}

IVF_Info parse_IVF(std::vector<char> &data, std::ostream &error) {
  if (data.size() < 32) {
    error << "IVF header資料長度不足(32/" << std::dec << data.size()
          << "bytes)";
    throw std::range_error("IVF header資料長度不足。");
  }
  if (std::memcmp(data.data(), "DKIF", 4) != 0) {
    error << "與預期的magic(DKIF)不符合，停止分析\n";
    throw std::logic_error("與預期magic(DKIF)不符。");
  }
  return IVF_Info(data, 0);
}
// 分析payload的實際data的標誌
bool parse_flag(uint8_t &flag, bool &enable_dataII, DATA_TYPE &type,
                std::ostream &error, size_t &useBytes) {
  uint8_t h3 = flag & 0b11100000;
  uint8_t l5 = flag & 0b00011111;
  //  啟用數據II 010.....
  // 不啟用數據II 001.....

  if (h3 == 0b01000000) {
    enable_dataII = true;
  } else if (h3 == 0b00100000) {
    enable_dataII = false;
  } else {
    return false;
  }

  const DATA_TYPE types[] = {
      DATA_TYPE::CHAR,  DATA_TYPE::UCHAR,  DATA_TYPE::SHORT,  DATA_TYPE::USHORT,
      DATA_TYPE::INT,   DATA_TYPE::UINT,   DATA_TYPE::LONG,   DATA_TYPE::ULONG,
      DATA_TYPE::FLOAT, DATA_TYPE::DOUBLE, DATA_TYPE::STRING, DATA_TYPE::BYTE};
  const size_t uses[] = {1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 0, 0};
  if (l5 >= 0b00010000 && l5 <= 0b00011011) {
    type = types[l5 - 0b00010000];
    useBytes = uses[l5 - 0b00010000];
  } else {
    return false;
  }
  return true;
}

bool getOutput_payload_data_for1(PayloadInfo &payload, std::ostream &output) {
  if (payload.data.size() < 4) {
    output << "      錯誤：@UTF 數據過短，無法讀取 Magic。\n";
    return false;
  }
  if (payload.data.size() < 8) { // @UTF + size
    output << "      錯誤：@UTF 數據過短，無法讀取總大小。\n";
    return false;
  }
  if (payload.data.size() < 8 + 24) { // 至少需要讀到 array_size
    output << "      錯誤：@UTF 數據過短，無法讀取表頭元數據。\n";
    return false;
  }
  std::string magic(payload.data.data(), 4);
  if (magic != "@UTF") {
    output << "      警告：預期Magic: @UTF，但得到 '" << magic << "'\n";
    return false;
  }
  output << "    @UTF 表格詳細解析：\n";
  output << "      Magic ID：" << magic << "\n";

  uint32_t internal_utf_payload_size = char_to_uint<uint32_t>(payload.data, 4);
  output << "      @UTF內部Payload大小：" << internal_utf_payload_size
         << " bytes\n";

  // 偏移量定義，從 payload_info.data 的第 8 個字節開始是 UTF header 的數據部分
  size_t utf_header_ofs = 8;
  uint32_t dataII_offset = // dataII 在@UTF header之後的偏移
      char_to_uint<uint32_t>(payload.data, utf_header_ofs + 0);
  uint32_t string_offset = // string stream 在@UTF header之後的偏移
      char_to_uint<uint32_t>(payload.data, utf_header_ofs + 4);
  uint32_t byte_stream_offset = // byte stream 在@UTF header之後的偏移
      char_to_uint<uint32_t>(payload.data, utf_header_ofs + 8);
  uint32_t table_name_offset = // UTF表 在@UTF header之後的偏移
      char_to_uint<uint32_t>(payload.data, utf_header_ofs + 12);
  uint16_t columns_per_row = // 每行有多少欄位
      char_to_uint<uint16_t>(payload.data, utf_header_ofs + 16);
  uint16_t row_size_in_dataII = // 每行用了dataII多少資料 (不知道意義在哪)
      char_to_uint<uint16_t>(payload.data, utf_header_ofs + 18);
  uint32_t total_rows = // 總共有幾行 (不知道什麼意思)
      char_to_uint<uint32_t>(payload.data, utf_header_ofs + 20);

  const std::vector<std::string> utf_field_labels = {
      "資料II區偏移 (相對於@UTF內容起始)：",
      "字串區偏移 (相對於@UTF內容起始)：",
      "字節流區偏移 (相對於@UTF內容起始)：",
      "表格名稱字串偏移 (相對於字串區起始)：",
      "每行欄位數：",
      "每行於資料II區大小 (bytes)：",
      "總行數："};

  output << "      " << utf_field_labels[0] << dataII_offset << "\n";
  output << "      " << utf_field_labels[1] << string_offset << "\n";
  output << "      " << utf_field_labels[2] << byte_stream_offset << "\n";
  output << "      " << utf_field_labels[3] << table_name_offset << "\n";
  output << "      " << utf_field_labels[4] << columns_per_row << "\n";
  output << "      " << utf_field_labels[5] << row_size_in_dataII << "\n";
  output << "      " << utf_field_labels[6] << total_rows << "\n";

  // 定義各數據區域的真實起始偏移 (相對於 payload_info.data[0])

  // 24 == 各種標記總和需要的byte
  size_t region_start_dataI = utf_header_ofs + 24;
  size_t region_start_dataII = utf_header_ofs + dataII_offset;
  size_t region_start_string_data = utf_header_ofs + string_offset;
  size_t region_start_byte_stream_data = utf_header_ofs + byte_stream_offset;

  // 表格名稱
  if (region_start_string_data + table_name_offset < payload.data.size()) {
    std::string table_name_str = char_to_string(
        payload.data, region_start_string_data + table_name_offset);
    output << "      表格名稱：" << table_name_str << "\n";
  }
  output << "      欄位數據：\n";

  // 目前指向的數據 從@UTF頭開始 的偏移
  size_t currRow_dataOfs = region_start_dataI;
  size_t dataII_current_usage_offset = 0; // 用於追蹤在 Data II 中消耗的數據

  for (uint32_t row = 0 /*行數*/; row < total_rows; ++row) {
    output << "        第 " << (row + 1) << " 行：\n";
    for (uint16_t col = 0 /*欄位*/; col < columns_per_row; ++col) {
      if (currRow_dataOfs >= region_start_dataII) {
        output << "          警告：Data I 偏移 (" << currRow_dataOfs
               << ") 已達到或超過 Data II 起始 (" << region_start_dataII
               << ")，提前結束行解析。\n";
        return true;
      }
      if (currRow_dataOfs + 1 > payload.data.size()) { // 至少需要讀 flag
        output << "          錯誤：數據不足以讀取第 " << col + 1
               << " 欄的標誌位。\n";
        return true;
      }
      if (currRow_dataOfs + 1 + 4 > payload.data.size()) { // flag + title_ptr
        output << "          錯誤：數據不足以讀取第 " << col + 1
               << " 欄的標題指針。\n";
        return true;
      }
      // 資料標誌
      uint8_t flag = payload.data[currRow_dataOfs];
      // 資料名稱offset(相對於字串的<NULL>頭)
      uint32_t data_title_name_offset =
          char_to_uint<uint32_t>(payload.data, currRow_dataOfs + 1);
      size_t bytes_in_dataI_storge = 0; // 此欄位在 Data I 中佔用的本地數據大小
      bool use_dataII_storage;          // 是否使用dataII儲存資料
      DATA_TYPE data_type;              // 資料型別

      if (!parse_flag(flag, use_dataII_storage, data_type, output,
                      bytes_in_dataI_storge)) {
        output << "          錯誤：解析第 " << col + 1
               << " 欄標誌位失敗 (flag: " << std::bitset<8>(flag) << ")"
               << " 目前偏移：" << currRow_dataOfs << "\n";
        return true;
      }

      std::string column_title_str = "未知欄位";
      if (region_start_string_data + data_title_name_offset <
          payload.data.size()) {
        column_title_str = char_to_string(
            payload.data, region_start_string_data + data_title_name_offset);
      }

      output << "          欄位名 '" << column_title_str
             << "' 類型: " << dataTypeToString(data_type)
             << ", 使用DataII: " << (use_dataII_storage ? "是" : "否")
             << ", 儲存大小: " << bytes_in_dataI_storge << "B: ";

      // 此欄位的消耗量 預設 flag + title_ptr
      size_t consumed_in_data_I_for_this_column = 1 + 4;
      if (use_dataII_storage) {
        // 標記目前dataII用到哪裡了 從@UTF頭開始
        size_t data_offset_in_dataII =
            region_start_dataII + dataII_current_usage_offset;

        if (data_type == DATA_TYPE::STRING) {
          uint32_t string_ptr =
              char_to_uint<uint32_t>(payload.data, data_offset_in_dataII);
          output << char_to_string(payload.data,
                                   region_start_string_data + string_ptr);
          dataII_current_usage_offset += 4;
          // 根據CRI spec，通常字串用指針
        } else if (data_type == DATA_TYPE::BYTE) { // Byte stream in Data II?
          output << " (DataII 中的byte stream，處理方式待確認)";
        } else { // 數值類型
          if (data_offset_in_dataII + bytes_in_dataI_storge >
                  payload.data.size() ||
              data_offset_in_dataII + bytes_in_dataI_storge >
                  region_start_string_data) { // 避免越界到string區
            output << "錯誤：讀取DataII數據時越界。";
          } else {
            size_t number = std::accumulate(
                payload.data.begin() + data_offset_in_dataII,
                payload.data.begin() + data_offset_in_dataII +
                    bytes_in_dataI_storge,
                0ULL, [](size_t acc, char byte) {
                  return (acc << 8) | static_cast<unsigned char>(byte);
                });
            output << std::dec << number;
          }
        }
        // 更新 Data II 已用偏移
        // Data I 中此欄位不佔用額外本地數據空間
        dataII_current_usage_offset += bytes_in_dataI_storge;
      } else {
        // 數據儲存在 Data I 本地 (flag + title_ptr 後面的字節)
        size_t local_data_start_in_data_I =
            currRow_dataOfs + consumed_in_data_I_for_this_column;
        if (data_type == DATA_TYPE::STRING) {
          if (local_data_start_in_data_I + 4 >
              payload.data.size()) { // 指針本身需要4B
            output << "錯誤：讀取字串指針時越界。";
          } else {
            uint32_t str_actual_offset = char_to_uint<uint32_t>(
                payload.data, local_data_start_in_data_I);
            if (region_start_string_data + str_actual_offset <
                payload.data.size()) {
              output << "\""
                     << char_to_string(payload.data, region_start_string_data +
                                                         str_actual_offset)
                     << "\"";
            } else {
              output << "錯誤：字串指針越界。";
            }
          }
          consumed_in_data_I_for_this_column += 4; // 字串指針佔4B
        } else if (data_type == DATA_TYPE::BYTE) {
          if (local_data_start_in_data_I + 8 >
              payload.data.size()) { // 頭尾指針共8B
            output << "錯誤：讀取字節流指針時越界。";
          } else {
            uint32_t byte_start_ptr = char_to_uint<uint32_t>(
                payload.data, local_data_start_in_data_I);
            uint32_t byte_end_ptr = char_to_uint<uint32_t>(
                payload.data, local_data_start_in_data_I + 4);
            output << "[字節流：從 " << byte_start_ptr << " 到 " << byte_end_ptr
                   << " (於字節流區)] ";
            // 實際數據在 byte_stream_data_region_start + byte_start_ptr
            // 可以選擇性地打印部分字節
          }
          consumed_in_data_I_for_this_column += 8; // 字節流指針佔8B
        } else {                                   // 數值類型，直接存儲
          if (local_data_start_in_data_I + bytes_in_dataI_storge >
              payload.data.size()) {
            output << "錯誤：讀取本地數據時越界。";
          } else {
            size_t number = std::accumulate(
                payload.data.begin() + local_data_start_in_data_I,
                payload.data.begin() + local_data_start_in_data_I +
                    bytes_in_dataI_storge,
                0ULL, [](size_t acc, char byte) {
                  return (acc << 8) | static_cast<unsigned char>(byte);
                });
            output << std::dec << number;
          }
          consumed_in_data_I_for_this_column += bytes_in_dataI_storge;
        }
      }
      output << std::dec << "\n";
      // 更新 Data I 中的偏移到下一個欄位
      currRow_dataOfs += consumed_in_data_I_for_this_column;
    }
  }
  return true;
}

std::vector<ChunkInfo> parse_chunks(const std::string &filepath,
                                    std::ostream &error) {
  std::ifstream file(filepath, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    error << "錯誤：無法打開檔案 '" << filepath << "'\n";
    return {};
  }

  std::streamsize total_file_size_ss = file.tellg();
  if (total_file_size_ss == -1) {
    error << "錯誤：無法獲取檔案大小 '" << filepath << "'\n";
    file.close();
    return {};
  } else if (total_file_size_ss == 0) {
    error << "資訊：檔案 '" << filepath << "' 為空。\n";
    file.close();
    return {};
  }
  if (total_file_size_ss < 8) { // 檔案甚至不夠一個 chunk 的 header
    error << "警告：檔案過小 (" << total_file_size_ss
          << " bytes)，不足以包含一個完整的 Chunk Header (8 bytes)。"
          << "\n";
    return {};
  }
  // 檔案大小
  uint64_t total_file_size = static_cast<uint64_t>(total_file_size_ss);

  std::vector<ChunkInfo> chunks; // 儲存所有解析過的chunk
  uint64_t current_offset = 0;   // 目前解析到哪

  while (current_offset < total_file_size) {
    // 如果剩下的byte不夠 跳出循環
    if (current_offset + CHUNK_HEADER_SIZE >= total_file_size) {
      break;
    }
    ChunkInfo chunk;
    // 如果解析失敗 直接跳出
    if (!parse_one_chunk(file, current_offset, chunk, error))
      break;

    // 注意 payload 大小為 0 的情況
    if (chunk.payload_size == 0) {
      error << "注意：Chunk '" << std::string(chunk.magic, 4)
            << "' 聲明 Payload 大小為 0。\n";
    }

    chunks.push_back(chunk); // 將解析完成的chunk放進chunks內
    // 下一個chunk的起始位置
    current_offset += chunk.payload_size + CHUNK_HEADER_SIZE;

    // 邊界檢查：Chunk 是否聲稱其結尾超出了檔案實際大小
    if (current_offset > total_file_size) {
      error << "警告：Chunk '" << std::string(chunk.magic, 4)
            << "' 的計算大小 (" << chunk.payload_size + CHUNK_HEADER_SIZE
            << ") 將使其總結尾 (0x" << std::hex << current_offset << std::dec
            << ") 超出檔案實際大小 (0x" << std::hex << total_file_size
            << std::dec << ")。可能檔案損壞或已到結尾的填充數據。\n";
      break;
    }
  }

  if (chunks.empty()) {
    // 如果檔案不為空但沒有解析到chunk，上面的警告（如檔案過小）可能已經給出
    // 如果檔案大於8字節但仍未解析到，這裡可以再加一個通用提示
    if (total_file_size >= 8) {
      error << "未能解析出任何 Chunk 結構，儘管檔案大小足夠。\n";
    } // 其他關於檔案大小的問題 在開頭就已偵測過
    file.close();
    return {};
  }
  file.close();
  return chunks;
}
void getOutput_Chunks(std::string filepath, std::ostream &output, int length,
                      int start_chunk, int end_chunk) {
  std::vector<ChunkInfo> chunks = parse_chunks(filepath, output);
  output << "--- USM 檔案分析結果 ---\n";
  for (int i = start_chunk; i <= end_chunk; i++) {
    if (i >= chunks.size())
      break;                      // 額外保護
    ChunkInfo &chunk = chunks[i]; // 使用引用避免複製
    PayloadInfo payload(chunk.payload_data);

    output << std::dec << "--- Chunk #"
           << std::setw(std::to_string(chunks.size()).length())
           << std::setfill('0') << (i + 1) << " ---\n";
    output << "  Chunk 類型 (Magic)：" << std::string(chunk.magic, 4) << "\n";
    output << "  Payload 資訊：\n";
    output << "    原始類型ID：" << static_cast<int>(payload.type_raw) << " ("
           << (KNOWN_PAYLOAD_TYPES.count(payload.type_raw)
                   ? KNOWN_PAYLOAD_TYPES.at(payload.type_raw)
                   : "unknown (" +
                         std::to_string(static_cast<int>(payload.type_raw)) +
                         ")")
           << ")\n";
    output << "    內容數據偏移 (於Payload內)："
           << static_cast<int>(payload.data_offset) << " bytes\n";
    output << "    區塊結尾填充大小：" << payload.padding << " bytes"
           << "\n";
    output << "    通道號：" << static_cast<int>(payload.channel) << "\n";
    output << "    幀時間/計數：" << payload.frame_time << "\n";
    output << "    幀率：" << payload.frame_rate << "\n";

    size_t data_size = payload.data.size();
    size_t display_length =
        (length < 0 || static_cast<size_t>(length) > data_size)
            ? data_size
            : static_cast<size_t>(length);

    if ((payload.type_raw == 0x01 || payload.type_raw == 0x03) &&
        getOutput_payload_data_for1(payload, output)) {
    } else {
      output << "  Payload 內容 (前 " << display_length << " / " << data_size
             << " byte)：\n";
      // section_end 或 seek
      if (payload.type_raw == 0x02 || payload.type_raw == 0x03) {
        output << "    ";
        for (size_t k = 0; k < display_length; ++k) {
          isprint(static_cast<unsigned char>(payload.data[k]))
              ? output << payload.data[k]
              : output << "."; // 非可列印字元用 . 表示
        }
        output << "\n";
      } else { // 其他 stream 數據
        output << "    ";
        for (size_t k = 0; k < display_length; ++k) {
          output << std::hex << std::setw(2) << std::setfill('0')
                 << static_cast<unsigned int>(
                        static_cast<unsigned char>(payload.data[k]))
                 << " ";
          if ((k + 1) % 16 == 0 && k + 1 < display_length)
            output << std::endl << "    "; // 每16字節換行
        }
        output << std::dec << "\n";
      }
    }
    output << "--- End of Chunk #" << (i + 1) << " ---" << std::endl << "\n";
  }
}

void outputFile_IVF(std::string in_file, std::ostream &output,
                    std::ofstream &out_file) {
  std::vector<ChunkInfo> chunks = parse_chunks(in_file, output);
  size_t offset = 32;
  for (auto &chunk : chunks) {
    PayloadInfo payload(chunk.payload_data);
    if (payload.type_raw == 0) {
      // 修正：write 需要兩個參數，分別是指標與長度
      out_file.write(reinterpret_cast<const char *>(payload.data.data()),
                     payload.data.size());
      // IVF_frame_data frame(payload.data, offset);
      // output << frame.size << ", " << frame.timestamp << ", "
      //        << payload.data.size() << "\n";
      // offset = 0;
    }
  }
}
int main(int argc, char *argv[]) {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
#endif

  std::string usm_file_path;
  std::string output_file_path = "usm_analysis_log.txt"; // 預設輸出檔案名

  if (argc == 3) {
    usm_file_path = argv[1];
    output_file_path = argv[2];
  } else {
    return 1;
  }

  std::ofstream log_file(output_file_path);
  if (!log_file.is_open()) {
    std::cerr << "錯誤：無法打開日誌檔案 '" << output_file_path
              << "' 。分析結果將輸出到控制台。" << std::endl;
    if (!usm_file_path.empty()) {
      getOutput_Chunks(usm_file_path, std::cout, 256, 0, 20);
    }
    return 1;
  }
  std::cout << "分析結果正在寫入檔案: " << output_file_path << "\n";
  if (!usm_file_path.empty()) {
    getOutput_Chunks(usm_file_path, log_file, -1, 5, 5);
    // outputFile_IVF(usm_file_path, std::cout, log_file);
  }
  log_file.close();
  std::cout << "分析完成，結果已保存到: " << output_file_path << "\n";

  return 0;
}