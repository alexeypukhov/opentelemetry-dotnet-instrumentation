/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OTEL_CLR_PROFILER_TYPE_NAME_ASSEMBLY_REFERENCE_PARSER_H_
#define OTEL_CLR_PROFILER_TYPE_NAME_ASSEMBLY_REFERENCE_PARSER_H_

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace trace
{

// Borrows a region of one original type-name string. Child slices retain that source, so their offsets always
// refer to the original input. The source storage must remain alive and unchanged while any slice is used.
class TypeNameSlice
{
public:
    explicit TypeNameSlice(std::string_view source) noexcept : source_(source), view_(source) {}

    bool Empty() const noexcept
    {
        return view_.empty();
    }

    size_t Size() const noexcept
    {
        return view_.size();
    }

    // Index within this slice; as with string_view, index must be less than Size().
    char operator[](size_t index) const noexcept
    {
        return view_[index];
    }

    std::string_view View() const noexcept
    {
        return view_;
    }

    size_t Begin() const noexcept
    {
        // An empty root may have a null data pointer; do not subtract null pointers. Every nonempty-source child
        // is derived through Substr, including empty children anchored at the source's end.
        return source_.empty() ? 0 : static_cast<size_t>(view_.data() - source_.data());
    }

    size_t End() const noexcept
    {
        return Begin() + Size();
    }

    TypeNameSlice Substr(size_t offset, size_t count = std::string_view::npos) const
    {
        return TypeNameSlice(source_, view_.substr(offset, count));
    }

    TypeNameSlice Trimmed() const;

private:
    // Only slice operations can pair a subview with its original source.
    TypeNameSlice(std::string_view source, std::string_view view) noexcept : source_(source), view_(view) {}

    std::string_view source_;
    std::string_view view_;
};

struct ParsedAssemblyReference
{
    std::string                  assembly_name;
    size_t                       insert_version_at;
    std::optional<TypeNameSlice> version_slice;
};

// Malformed syntax and resource-budget failures share one exception type so the rewriting boundary can catch
// parser rejections without treating a missing qualifier or an unqualified type as an error.
class TypeNameParseError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

// Finds assembly qualifications in a reflection type name, including those inside generic arguments. Assembly names
// are owned and unescaped; version slices borrow the original input, which must remain alive and unchanged while
// those slices are used. Insertion positions and slice offsets refer to that input. Throws TypeNameParseError for
// malformed syntax or an exceeded per-input budget: 8 MiB of UTF-8 text, 4,096 unescaped opening brackets, or 8,192
// scheduled types, including the root. No assembly qualifications means an empty vector; failure returns no partial
// results. These resource budgets do not impose a separate generic-nesting-depth limit.
// Reference order is unspecified; consumers applying edits must order them by source position.
std::vector<ParsedAssemblyReference> ParseTypeNameAssemblyReferences(std::string_view type_name);

} // namespace trace

#endif // OTEL_CLR_PROFILER_TYPE_NAME_ASSEMBLY_REFERENCE_PARSER_H_
