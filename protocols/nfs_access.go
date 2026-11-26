package protocols

import "io/fs"

const (
	nfsAccessRead uint32 = 1 << iota
	nfsAccessLookup
	nfsAccessModify
	nfsAccessExtend
	nfsAccessDelete
	nfsAccessExecute
)

const (
	nfsPermissionExecute uint32 = 1 << iota
	nfsPermissionWrite
	nfsPermissionRead
)

func nfsAccessMask(info fs.FileInfo, requested uint32, permitted func(uint32) (bool, error)) (uint32, error) {
	change := nfsAccessModify | nfsAccessExtend
	write := nfsPermissionWrite
	search := nfsAccessExecute
	switch {
	case info.IsDir():
		change |= nfsAccessDelete
		write |= nfsPermissionExecute
		search = nfsAccessLookup
	case !info.Mode().IsRegular():
		return 0, nil
	}
	rules := [...]struct {
		bits       uint32
		permission uint32
	}{
		{nfsAccessRead, nfsPermissionRead},
		{search, nfsPermissionExecute},
		{change, write},
	}
	var allowed uint32
	for _, rule := range rules {
		bits := requested & rule.bits
		if bits == 0 {
			continue
		}
		ok, err := permitted(rule.permission)
		if err != nil {
			return 0, err
		}
		if ok {
			allowed |= bits
		}
	}
	return allowed, nil
}
