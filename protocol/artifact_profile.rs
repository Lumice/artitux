//! Versioned Artifact CPU metadata; no host CPU state is changed here.
use crate::cpuid::{Registers, Vendor};

/// Validate a PE64 header before using it to attribute an anonymous code view.
pub fn pe_image_contains(base: u64, address: u64, dos: &[u8], pe: &[u8]) -> bool {
    if base & 0xffff != 0
        || dos.len() < 64
        || pe.len() < 84
        || &dos[..2] != b"MZ"
        || &pe[..4] != b"PE\0\0"
        || u16::from_le_bytes([pe[4], pe[5]]) != 0x8664
        || u16::from_le_bytes([pe[24], pe[25]]) != 0x20b
    {
        return false;
    }
    let header = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]);
    let size = u32::from_le_bytes([pe[80], pe[81], pe[82], pe[83]]);
    (64..=0x1000).contains(&header)
        && (0x1000..=0x80000000).contains(&size)
        && base
            .checked_add(u64::from(size))
            .is_some_and(|end| (base..end).contains(&address))
}

/// Unknown mappings retain the previous conservative address-range policy.
pub fn native_wine_view(address: u64, path: Option<&[u8]>) -> bool {
    if let Some(path) = path {
        let path = path.strip_suffix(b" (deleted)").unwrap_or(path);
        let name = path.rsplit(|b| *b == b'/').next().unwrap_or_default();
        let contains = |part: &[u8]| path.windows(part.len()).any(|w| w == part);
        if contains(b"/wine/x86_64-windows/") || contains(b"/wine/x86_64-unix/") {
            return true;
        }
        if (contains(b"/windows/system32/") || contains(b"/windows/syswow64/"))
            && [
                b"ntdll.dll".as_slice(),
                b"kernel32.dll",
                b"kernelbase.dll",
                b"win32u.dll",
            ]
            .iter()
            .any(|n| name.eq_ignore_ascii_case(n))
        {
            return true;
        }
        let extension = name.get(name.len().saturating_sub(4)..).unwrap_or_default();
        if extension.eq_ignore_ascii_case(b".exe") || extension.eq_ignore_ascii_case(b".dll") {
            return false;
        }
    }
    crate::cpuid::is_wine_system_rip(address)
}

/// CPUID reply for an Artifact query: hypervisor identity and brand leaves,
/// XSAVE/AVX bits masked in leaf 1, a zeroed high-leaf range, and native
/// words for everything else.
pub fn reply(
    vendor: Vendor,
    leaf: u32,
    subleaf: u32,
    native: impl FnOnce() -> Registers,
) -> [u64; 4] {
    if vendor == Vendor::Unknown {
        return crate::artifact_cpu::native_words(vendor, native());
    }
    if leaf == 1 {
        let mut words = crate::artifact_cpu::reply(vendor, leaf, subleaf, native);
        words[2] &=
            !((1 << 12) | (1 << 25) | (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29) | (1 << 30));
        return words;
    }
    if (0x8000_0002..=0x8000_0004).contains(&leaf) {
        return crate::artifact_cpu::reply(vendor, leaf, subleaf, native);
    }
    if (0x0033_6934..0x8000_0000).contains(&leaf) {
        return [0; 4];
    }
    crate::artifact_cpu::native_words(vendor, native())
}

/// KUSER_SHARED_DATA writes for Artifact: the shared identity fields, then
/// the processor-feature and XSTATE fields cleared. Wine's clock fields and
/// the gaps between ranges are left alone.
pub fn visit_writes(vendor: Vendor, mut write: impl FnMut(usize, u8)) -> bool {
    if !crate::kuser::visit_artifact_writes(vendor, &mut write) {
        return false;
    }
    for at in [0x285, 0x290, 0x294, 0x295, 0x297, 0x29b, 0x29c] {
        write(at, 0);
    }
    for range in [0x3d8..0x3e8, 0x3ec..0x600, 0x604..0x804, 0x808..0x818] {
        for at in range {
            write(at, 0);
        }
    }
    true
}

/// After registering, the Artifact build that uses the 0x1337 bypass (seen
/// in Anno 117) polls this KUSER_SHARED_DATA marker and sleeps in 100 ms
/// waitable-timer waits until it appears. Other builds must not see it.
pub const READY_MARKER_OFFSET: usize = 0xffc;
pub const READY_MARKER: u32 = 0x1337_1337;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_code_requires_a_valid_bounded_pe64_image() {
        let base = 0x6fffff6d0000;
        let mut dos = [0u8; 64];
        dos[..2].copy_from_slice(b"MZ");
        dos[0x3c..].copy_from_slice(&0x80u32.to_le_bytes());
        let mut pe = [0u8; 84];
        pe[..4].copy_from_slice(b"PE\0\0");
        pe[4..6].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[24..26].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[80..84].copy_from_slice(&0x22000u32.to_le_bytes());
        assert!(pe_image_contains(base, base + 0x8b80, &dos, &pe));
        assert!(!pe_image_contains(base, base + 0x23000, &dos, &pe));
        assert!(!pe_image_contains(base, base - 1, &dos, &pe));
        assert!(!pe_image_contains(
            u64::MAX - 0xffff,
            u64::MAX - 1,
            &dos,
            &pe
        ));
        assert!(!pe_image_contains(base, base + 0x1000, &dos[..10], &pe));
        pe[4..6].copy_from_slice(&0x14cu16.to_le_bytes());
        assert!(!pe_image_contains(base, base + 0x8b80, &dos, &pe));
    }

    #[test]
    fn observed_high_application_image_is_not_a_wine_system_caller() {
        assert!(!native_wine_view(
            0x6fffff6d8b80,
            Some(b"/private test/native-profile-fixture.exe")
        ));
        assert!(!native_wine_view(
            0x6fffff6d8b80,
            Some(b"/game/artifact.dll (deleted)")
        ));
    }

    #[test]
    fn attributed_wine_cpu_state_modules_keep_the_native_view() {
        for path in [
            b"/proton/files/lib/wine/x86_64-unix/ntdll.so".as_slice(),
            b"/prefix/drive_c/windows/system32/ntdll.dll".as_slice(),
        ] {
            assert!(native_wine_view(0x7f0000001000, Some(path)));
        }
    }

    #[test]
    fn unattributed_addresses_keep_the_existing_safe_fallback() {
        assert!(native_wine_view(0x6fffff6d8b80, None));
        assert!(!native_wine_view(0x140001000, None));
    }

    #[test]
    fn leaf_one_matches_new_sources_for_both_vendors() {
        for (vendor, eax, ecx, edx) in [
            (Vendor::Amd, 0xa20f12, 0x00f8220b, 0x178bfbff),
            (Vendor::Intel, 0xd0670, 0x01faebff, 0xbfebfbff),
        ] {
            assert_eq!(
                reply(vendor, 1, 0, || Registers::new(0, 0xf3000000, 0, 0)),
                [eax, 0xf3100800, ecx, edx]
            );
        }
    }

    #[test]
    fn removed_tables_use_native_words_including_signed_intel() {
        for vendor in [Vendor::Amd, Vendor::Intel] {
            for (leaf, subleaf) in [(0, 0), (7, 0), (7, 1), (0xd, 0), (0x80000001, 0)] {
                let native = Registers::new(0x80000000, 0xffffffff, 3, 0x80000001);
                let expected = if vendor == Vendor::Intel {
                    [0xffffffff80000000, u64::MAX, 3, 0xffffffff80000001]
                } else {
                    [0x80000000, 0xffffffff, 3, 0x80000001]
                };
                assert_eq!(reply(vendor, leaf, subleaf, || native), expected);
            }
        }
    }

    #[test]
    fn retains_brand_overrides_and_high_leaf_zero_range() {
        assert_eq!(
            reply(Vendor::Intel, 0x80000004, 0, || panic!("fixed reply")),
            [0; 4]
        );
        for vendor in [Vendor::Amd, Vendor::Intel] {
            assert_eq!(reply(vendor, 0x336934, 0, || panic!("zero range")), [0; 4]);
            assert_eq!(
                reply(vendor, 0x80000002, 0, || panic!("brand")),
                crate::artifact_cpu::reply(vendor, 0x80000002, 0, || panic!("brand"))
            );
        }
    }

    #[test]
    fn kuser_clears_exact_source_xstate_ranges_preserving_wine_clock_and_gaps() {
        for vendor in [Vendor::Amd, Vendor::Intel] {
            let mut page = [0xa5; crate::kuser::PAGE_SIZE];
            assert!(visit_writes(vendor, |at, byte| page[at] = byte));
            for at in [0x285, 0x290, 0x294, 0x295, 0x297, 0x29b, 0x29c] {
                assert_eq!(page[at], 0);
            }
            for range in [0x3d8..0x3e8, 0x3ec..0x600, 0x604..0x804, 0x808..0x818] {
                assert!(page[range].iter().all(|b| *b == 0));
            }
            assert!(
                page[READY_MARKER_OFFSET..READY_MARKER_OFFSET + 4]
                    .iter()
                    .all(|b| *b == 0xa5)
            );
            for range in [
                0x3c6..0x3c8,
                0x3e8..0x3ec,
                0x600..0x604,
                0x804..0x808,
                0x818..0x820,
            ] {
                assert!(page[range].iter().all(|b| *b == 0xa5));
            }
        }
    }

    #[test]
    fn unknown_vendor_is_not_supported() {
        assert!(!visit_writes(Vendor::Unknown, |_, _| panic!(
            "unsupported vendor"
        )));
    }
}
