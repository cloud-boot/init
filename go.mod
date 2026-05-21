module github.com/cloud-boot/init

go 1.25.1

require (
	github.com/go-filesystems/btrfs v0.0.0
	github.com/go-filesystems/ext4 v0.0.0
	github.com/go-filesystems/interface v0.0.0
	github.com/go-filesystems/xfs v0.0.0
	github.com/go-filesystems/zfs v0.0.0-00010101000000-000000000000
	github.com/hashicorp/hcl/v2 v2.21.0
	github.com/insomniacslk/dhcp v0.0.0-20240829085014-a3a4c1f04475
	github.com/klauspost/compress v1.18.6
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.0
	github.com/vishvananda/netlink v1.3.0
	github.com/zclconf/go-cty v1.13.0
	golang.org/x/net v0.39.0
	golang.org/x/sys v0.44.0
)

// Local sibling checkouts — until the repos are published.
replace github.com/go-coff/peln => ../../go-coff/peln

replace github.com/go-filesystems/interface => ../../../../../dev-temp/GitHub/mock/pkg/go-filesystems/interface

replace github.com/go-filesystems/ext4 => ../../../../../dev-temp/GitHub/mock/pkg/go-filesystems/ext4

replace github.com/go-filesystems/xfs => ../../../../../dev-temp/GitHub/mock/pkg/go-filesystems/xfs

replace github.com/go-filesystems/btrfs => ../../../../../dev-temp/GitHub/mock/pkg/go-filesystems/btrfs

replace github.com/go-filesystems/zfs => ../../../../../dev-temp/GitHub/mock/pkg/go-filesystems/zfs

require (
	github.com/agext/levenshtein v1.2.1 // indirect
	github.com/apparentlymart/go-textseg/v13 v13.0.0 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/go-filesystems/interface v0.0.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/packet v1.1.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/mitchellh/go-wordwrap v0.0.0-20150314170334-ad45545899c7 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	golang.org/x/tools v0.32.0 // indirect
)
