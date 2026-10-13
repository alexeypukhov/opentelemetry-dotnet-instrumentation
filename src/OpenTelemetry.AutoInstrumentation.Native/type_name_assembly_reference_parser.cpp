/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "type_name_assembly_reference_parser.h"

#include <optional>
#include <stack>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ascii_string_utils.h"

namespace trace
{

// A SerString contains UTF-8 bytes. The reflection type-name delimiters inspected below are all ASCII, while every
// non-ASCII UTF-8 byte has its high bit set, so byte-wise syntax parsing is safe. Keeping whitespace and case handling
// ASCII-only also makes it independent of the host process locale.
TypeNameSlice TypeNameSlice::Trimmed() const
{
    const auto is_ascii_space = [](const char character)
    {
        return character == ' ' || character == '\t' || character == '\n' || character == '\v' || character == '\f' ||
               character == '\r';
    };
    size_t begin = 0;
    auto   end   = Size();
    while (begin < end && is_ascii_space(view_[begin]))
    {
        begin++;
    }
    while (begin < end && is_ascii_space(view_[end - 1]))
    {
        end--;
    }
    return Substr(begin, end - begin);
}

namespace
{

// Per-input resource budgets for untrusted metadata. Bytes bound scanning and owned assembly-name text; opening
// brackets bound both the index and unmatched-opening stack; scheduled types bound total visits and pending work.
// Check each budget before allocating its corresponding storage. Traversal is iterative, so no depth limit is needed.
constexpr size_t max_type_name_bytes = 8 * 1024 * 1024;
constexpr size_t max_bracket_groups  = 4096;
constexpr size_t max_scheduled_types = 8192;

// Each group is a slice including both delimiters. Keying by its source-relative opening position keeps lookup simple
// and storage proportional to the number of matched groups, rather than the number of bytes in the input.
using BracketIndex = std::unordered_map<size_t, TypeNameSlice>;

// Stateless helpers. Their declarations and the parser's method declarations below form an implementation outline
// and allow definitions to be rearranged independently.
BracketIndex                           IndexBracketSlices(const TypeNameSlice& type_name);
std::optional<ParsedAssemblyReference> ParseAssemblyQualification(const TypeNameSlice& qualification);
TypeNameSlice                          GetNextQualifierPart(TypeNameSlice& remaining);
std::optional<size_t>                  FindUnescaped(const TypeNameSlice& value, char expected);
std::string                            Unescape(std::string_view value);

// One instance is created for each input. It borrows the original string and owns the bracket index, pending
// type slices and scheduling budget for that parse. Returned references borrow the input, not this object.
class TypeNameAssemblyReferenceParser
{
public:
    explicit TypeNameAssemblyReferenceParser(const TypeNameSlice& type_name);
    // A parse attempt consumes the instance, even if it fails. Further calls throw std::logic_error.
    std::vector<ParsedAssemblyReference> Parse();

private:
    // Inspect a slice's immediate delimiters using the immutable bracket index.
    const TypeNameSlice&  GetBracketSlice(const TypeNameSlice& remaining) const;
    std::optional<size_t> FindTopLevelComma(const TypeNameSlice& type) const;

    // Visit complete types and schedule their arguments for iterative processing.
    void                                   ScheduleType(const TypeNameSlice& type);
    std::optional<ParsedAssemblyReference> VisitType(const TypeNameSlice& input_type);
    void                                   ProcessTypeSimpleName(const TypeNameSlice& type_simple_name);
    void                                   ScheduleBracketContentTypes(const TypeNameSlice& input_arguments);

    const TypeNameSlice       root_;
    const BracketIndex        brackets_;
    std::stack<TypeNameSlice> pending_;
    size_t                    remaining_types_ = max_scheduled_types;
    bool                      started_         = false;
};

TypeNameAssemblyReferenceParser::TypeNameAssemblyReferenceParser(const TypeNameSlice& type_name)
    : root_(type_name), brackets_(IndexBracketSlices(root_))
{
}

// Delimiter positions returned by the scanners are relative to the supplied slice. Only Begin()/End() convert
// to original-input offsets; passing a separate string alongside a region is never necessary.
std::optional<size_t> FindUnescaped(const TypeNameSlice& slice, const char expected)
{
    const auto value            = slice.View();
    auto       current_position = size_t{0};
    while (current_position < value.size())
    {
        switch (value[current_position])
        {
            case '\\':
                if (current_position + 1 == value.size())
                {
                    throw TypeNameParseError("Dangling escape in assembly qualification.");
                }
                current_position += 2;
                break;
            case '[':
            case ']':
                // Brackets in an assembly qualification must be escaped.
                throw TypeNameParseError("Unescaped bracket in assembly qualification.");
            default:
                if (value[current_position] == expected)
                {
                    return current_position;
                }
                current_position++;
                break;
        }
    }
    return std::nullopt;
}

// Index unescaped bracket groups once. Unmatched openings have no slice. This is an index, not a
// whole-input validator: an empty assembly name deliberately ignores its remaining qualification, even if that
// tail contains unmatched brackets or a dangling escape. Traversal validates only the slices it actually visits.
BracketIndex IndexBracketSlices(const TypeNameSlice& type_name)
{
    BracketIndex       brackets;
    std::stack<size_t> openings;
    const auto         value         = type_name.View();
    size_t             opening_count = 0;
    for (size_t position = 0; position < value.size(); position++)
    {
        switch (value[position])
        {
            case '\\':
                if (position + 1 < value.size())
                {
                    position++; // An escaped bracket is a name character, not a delimiter.
                }
                break;
            case '[':
                // Count all unescaped openings, even if never closed or inside an ignored qualification tail.
                // Counting only completed pairs would allow openings to grow without consuming budget.
                if (opening_count == max_bracket_groups)
                {
                    throw TypeNameParseError("Type name exceeds the bracket budget.");
                }
                opening_count++;
                openings.push(position);
                break;
            case ']':
                if (!openings.empty())
                {
                    const auto bracket = type_name.Substr(openings.top(), position + 1 - openings.top());
                    brackets.emplace(bracket.Begin(), bracket);
                    openings.pop();
                }
                break;
            default:
                break;
        }
    }
    return brackets;
}

// Return the complete group only if it lies inside the caller's remaining slice. Its end is already the next byte
// after ']', so callers can skip a group directly or strip its two delimiters to inspect the contents.
// The index remains unchanged throughout traversal, so the returned reference borrows its stored slice safely.
const TypeNameSlice& TypeNameAssemblyReferenceParser::GetBracketSlice(const TypeNameSlice& remaining) const
{
    const auto bracket = brackets_.find(remaining.Begin());
    if (bracket == brackets_.end() || bracket->second.End() > remaining.End())
    {
        throw TypeNameParseError("Bracket group is unclosed or extends beyond the type slice.");
    }
    return bracket->second;
}

// Inspect only the current level, jumping over nested groups rather than rescanning their contents. For a type
// slice, a comma starts its assembly qualification; for a bracket-content slice, a comma separates entries.
std::optional<size_t> TypeNameAssemblyReferenceParser::FindTopLevelComma(const TypeNameSlice& type) const
{
    const auto value            = type.View();
    auto       current_position = size_t{0};
    while (current_position < value.size())
    {
        const auto current = value[current_position];
        switch (current)
        {
            case '\\':
                if (current_position + 1 == value.size())
                {
                    throw TypeNameParseError("Dangling escape in type name.");
                }
                current_position += 2;
                continue;
            case '[':
            {
                const auto& bracket = GetBracketSlice(type.Substr(current_position));
                current_position    = bracket.End() - type.Begin();
                continue;
            }
            case ']':
                throw TypeNameParseError("Unexpected closing bracket in type name.");
            default:
                if (current == ',')
                {
                    return current_position;
                }
                break;
        }
        current_position++;
    }

    return std::nullopt;
}

TypeNameSlice GetNextQualifierPart(TypeNameSlice& remaining)
{
    const auto separator_position = FindUnescaped(remaining, ',');
    const auto part               = remaining.Substr(0, separator_position.value_or(remaining.Size())).Trimmed();
    remaining                     = remaining.Substr(separator_position ? *separator_position + 1 : remaining.Size());
    return part;
}

// For Outer`2[[First, First.Assembly],Second], the arguments slice covers "[First, First.Assembly],Second".
// Split at this level's commas, unwrap each qualified argument independently, and schedule complete type slices.
// Array suffixes intentionally use the same operation: [] and [,] produce no entries; [*] produces an opaque,
// unqualified entry. Array dimensions contain no assembly qualifications, so their semantics need not be parsed.
void TypeNameAssemblyReferenceParser::ScheduleBracketContentTypes(const TypeNameSlice& input_arguments)
{
    // Advance a local cursor without changing the caller's slice.
    auto remaining_arguments = input_arguments;
    while (!remaining_arguments.Empty())
    {
        const auto separator  = FindTopLevelComma(remaining_arguments);
        auto current_argument = remaining_arguments.Substr(0, separator.value_or(remaining_arguments.Size())).Trimmed();
        remaining_arguments   = remaining_arguments.Substr(separator ? *separator + 1 : remaining_arguments.Size());
        if (current_argument.Empty())
        {
            continue;
        }

        // Assembly-qualified generic arguments have their own brackets. Decide per argument so mixed lists such as
        // Outer`2[[First, First.Assembly],Second] are parsed correctly.
        if (current_argument.View().front() == '[')
        {
            const auto& bracket = GetBracketSlice(current_argument);
            if (bracket.End() != current_argument.End())
            {
                throw TypeNameParseError("Qualified argument has text outside its bracket wrapper.");
            }
            current_argument = bracket.Substr(1, bracket.Size() - 2);
        }

        ScheduleType(current_argument);
    }
}

std::string Unescape(const std::string_view value)
{
    std::string result;
    result.reserve(value.size());
    auto position = size_t{0};
    while (position < value.size())
    {
        if (value[position] == '\\' && position + 1 < value.size())
        {
            position++;
        }
        result.push_back(value[position++]);
    }
    return result;
}

std::optional<ParsedAssemblyReference> ParseAssemblyQualification(const TypeNameSlice& qualification)
{
    // Parsing consumes fields from a local cursor; the caller's qualification stays unchanged.
    auto       remaining     = qualification;
    const auto assembly_name = GetNextQualifierPart(remaining);
    if (assembly_name.Empty())
    {
        return std::nullopt;
    }

    ParsedAssemblyReference reference{Unescape(assembly_name.View()), assembly_name.End(), std::nullopt};
    while (!remaining.Empty())
    {
        const auto qualifier = GetNextQualifierPart(remaining);
        const auto equals    = FindUnescaped(qualifier, '=');
        if (!reference.version_slice && equals &&
            EqualsIgnoreAsciiCase(qualifier.Substr(0, *equals).Trimmed().View(), std::string_view("Version")))
        {
            reference.version_slice = qualifier.Substr(*equals + 1).Trimmed();
        }
    }
    return reference;
}

// Limit total pushes, including the root, rather than current stack size. This bounds total visits as well as
// pending storage for wide lists. Each type splits at most one bracket group, so splitting needs no separate charge.
void TypeNameAssemblyReferenceParser::ScheduleType(const TypeNameSlice& type)
{
    if (remaining_types_ == 0)
    {
        throw TypeNameParseError("Type name exceeds the type scheduling budget.");
    }
    pending_.push(type);
    remaining_types_--;
}

// A complete type has two relevant parts: an opaque type body (possibly containing an argument list), followed by
// an optional assembly qualification. Names, generic arity, pointer/by-reference suffixes and array dimensions
// remain uninterpreted. Every slice retains the original source so rewriting can preserve all other bytes.
std::optional<ParsedAssemblyReference> TypeNameAssemblyReferenceParser::VisitType(const TypeNameSlice& input_type)
{
    const auto type = input_type.Trimmed();
    if (type.Empty())
    {
        return std::nullopt;
    }

    // Find this type's qualification while skipping all nested groups.
    const auto assembly_separator = FindTopLevelComma(type);
    // The name part includes generic arguments and suffixes; an unqualified type has an empty qualifier slice.
    const auto type_simple_name   = type.Substr(0, assembly_separator.value_or(type.Size()));
    const auto assembly_qualifier = type.Substr(assembly_separator ? *assembly_separator + 1 : type.Size());

    // Parse this type's qualification immediately. Reference order is irrelevant: the rewriter sorts edits
    // by original-input position. An unqualified outer type still needs its arguments visited below.
    auto reference = ParseAssemblyQualification(assembly_qualifier);
    ProcessTypeSimpleName(type_simple_name);
    return reference;
}

// Find type arguments in the simple name, if present, and schedule them for processing.
void TypeNameAssemblyReferenceParser::ProcessTypeSimpleName(const TypeNameSlice& type_simple_name)
{
    auto position = size_t{0};
    while (position < type_simple_name.Size())
    {
        switch (type_simple_name[position])
        {
            case '\\':
                if (position + 1 == type_simple_name.Size())
                {
                    throw TypeNameParseError("Dangling escape in type name.");
                }
                position += 2;
                break;
            case '[':
            {
                const auto& bracket = GetBracketSlice(type_simple_name.Substr(position));
                ScheduleBracketContentTypes(bracket.Substr(1, bracket.Size() - 2));
                // Only the first unescaped group can contain generic arguments. Later groups are array suffixes
                // with no assembly references, so there is no further work at this level.
                return;
            }
            default:
                position++;
                break;
        }
    }
}

// The stack contains only complete types. Each visit extracts its qualification and splits its first bracket
// group to schedule argument types, skipping nested groups through the index. No recursive calls are needed.
// Reference order is unspecified; every location refers to the original source.
std::vector<ParsedAssemblyReference> TypeNameAssemblyReferenceParser::Parse()
{
    if (started_)
    {
        throw std::logic_error("Parser instance can only be used once.");
    }
    started_ = true;

    std::vector<ParsedAssemblyReference> references;
    ScheduleType(root_);
    while (!pending_.empty())
    {
        // Copy the borrowed slice before pop destroys the stack entry; helpers can then push new work safely.
        const auto type = pending_.top();
        pending_.pop();
        auto reference = VisitType(type);
        if (reference)
        {
            references.push_back(std::move(*reference));
        }
    }
    return references;
}

} // namespace

std::vector<ParsedAssemblyReference> ParseTypeNameAssemblyReferences(const std::string_view type_name)
{
    // Reject oversized input before indexing or allocating parser work. Limits apply to the original UTF-8 bytes,
    // including whitespace and otherwise ignored text, rather than to a trimmed or reconstructed name.
    if (type_name.size() > max_type_name_bytes)
    {
        throw TypeNameParseError("Type name exceeds the byte budget.");
    }
    // Index boundaries once, then traverse the indexed type/argument slices. Together these passes take expected
    // O(n) time and O(n) auxiliary storage. Borrowed results retain that same source.
    return TypeNameAssemblyReferenceParser(TypeNameSlice(type_name)).Parse();
}

} // namespace trace
