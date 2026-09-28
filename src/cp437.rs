//! Code page 437: how zip archives without the UTF-8 flag encode names.

/// Characters for bytes 0x80..=0xFF.
const UPPER_HALF: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";

/// Decode a code page 437 name.
pub(crate) fn decode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b < 0x80 {
                char::from(b)
            } else {
                UPPER_HALF
                    .chars()
                    .nth(usize::from(b - 0x80))
                    .unwrap_or('\u{fffd}')
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_covers_the_upper_half() {
        assert_eq!(UPPER_HALF.chars().count(), 128);
    }

    #[test]
    fn decodes_ascii_and_accents() {
        assert_eq!(decode(b"caf\x82.txt"), "café.txt");
        assert_eq!(decode(b"\x8e"), "Ä");
    }
}
