package protocols

import (
	"encoding/binary"
	"fmt"
	"maps"
	"slices"
)

type amqpHeaderBinding struct {
	any    bool
	fields map[string]string
}

func parseAMQPHeaderBinding(table []byte) (amqpHeaderBinding, string, *amqpChannelFailure) {
	fields, ok := parseAMQPTable(table)
	if !ok {
		return amqpHeaderBinding{}, "", &amqpChannelFailure{406, "PRECONDITION_FAILED - invalid headers binding"}
	}
	binding := amqpHeaderBinding{fields: fields}
	if match, exists := fields["x-match"]; exists {
		if len(match) < 5 || match[0] != 'S' {
			return binding, "", &amqpChannelFailure{406, "PRECONDITION_FAILED - x-match must be a string"}
		}
		switch match[5:] {
		case "all":
		case "any":
			binding.any = true
		default:
			return binding, "", &amqpChannelFailure{406, fmt.Sprintf("PRECONDITION_FAILED - Invalid x-match field value %s, expected all or any", match[5:])}
		}
	}
	var canonical []byte
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		canonical = appendAMQPShort(canonical, key)
		canonical = appendAMQPLong(canonical, []byte(fields[key]))
	}
	delete(fields, "x-match")
	return binding, string(canonical), nil
}

func (b amqpHeaderBinding) matches(headers map[string]string) bool {
	if headers == nil {
		return false
	}
	for key, expected := range b.fields {
		value, exists := headers[key]
		matched := exists && (expected == "V" || expected == value)
		if matched == b.any {
			return matched
		}
	}
	return !b.any
}

func amqpPublicationHeaders(header []byte) map[string]string {
	flags := binary.BigEndian.Uint16(header[12:14])
	if flags&0x2000 == 0 {
		return nil
	}
	args := amqpArgs{data: header[14:]}
	if flags&0x8000 != 0 {
		args.short()
	}
	if flags&0x4000 != 0 {
		args.short()
	}
	table := args.table()
	if args.bad {
		return nil
	}
	fields, _ := parseAMQPTable(table)
	return fields
}

func parseAMQPTable(table []byte) (map[string]string, bool) {
	fields := make(map[string]string)
	args := amqpArgs{data: table}
	for len(args.data) != 0 && !args.bad {
		key := args.short()
		start := args.data
		kind := args.flags()
		switch kind {
		case 'V':
			// A void table entry carries only its type.
		case 't', 'b', 'B':
			args.take(1)
		case 's', 'u', 'U':
			args.take(2)
		case 'I', 'i', 'f':
			args.take(4)
		case 'D':
			args.take(5)
		case 'L', 'l', 'd', 'T':
			args.take(8)
		case 'S', 'x', 'A', 'F':
			args.table()
		default:
			return nil, false
		}
		if args.bad {
			return nil, false
		}
		fields[key] = string(start[:len(start)-len(args.data)])
	}
	return fields, args.done()
}
