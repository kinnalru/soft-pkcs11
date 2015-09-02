
#include <string>
#include <memory>
#include <vector>
#include <map>

#include "attribute.h"

typedef std::vector<char> Bytes;
typedef std::vector<CK_OBJECT_HANDLE> Handles;
typedef std::function<CK_OBJECT_HANDLE()> handle_iterator_t;

typedef std::map<CK_ATTRIBUTE_TYPE, attribute_t> Attributes;
typedef std::map<CK_OBJECT_HANDLE, Attributes> Objects;

// typedef std::map<CK_ATTRIBUTE_TYPE, std::string> MetaAttributes;
// typedef std::map<std::string, MetaAttributes> MetaAttributesList;

struct descriptor_t;
typedef std::shared_ptr<descriptor_t> descriptor_p;

