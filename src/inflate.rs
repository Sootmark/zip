//! DEFLATE (RFC 1951) and Deflate64 decompression, streaming.

use std::io::{self, Read};

/// Longest Huffman code in DEFLATE.
const MAX_BITS: usize = 15;
const TABLE_SIZE: usize = 1 << MAX_BITS;
/// Deflate64 uses a 64 KiB window (DEFLATE needs 32 KiB).
const WINDOW_SIZE: usize = 1 << 16;
const END_OF_BLOCK: u16 = 256;
const INPUT_BUFFER: usize = 8192;

/// Base lengths and extra bits for length symbols 257..=285.
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// Base distances and extra bits for distance symbols 0..=31 (30 and 31
/// exist only in Deflate64).
const DISTANCE_BASE: [u32; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];
const DISTANCE_EXTRA: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];
/// Order in which code-length code lengths are stored in a dynamic header.
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Which variant of the format to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Standard DEFLATE (zip method 8).
    Deflate,
    /// Deflate64 (zip method 9): 64 KiB window, longer lengths and distances.
    Deflate64,
}

/// A streaming DEFLATE decoder over compressed input.
pub struct Inflate<R> {
    bits: BitReader<R>,
    variant: Variant,
    state: State,
    window: Box<[u8]>,
    window_position: usize,
    produced: u64,
    /// A back-reference not fully copied yet: `(remaining, distance)`.
    pending_copy: Option<(usize, usize)>,
    last_block: bool,
}

enum State {
    BlockHeader,
    Stored {
        remaining: usize,
    },
    Huffman {
        literals: Huffman,
        distances: Huffman,
    },
    Done,
}

impl<R: Read> Inflate<R> {
    /// Decode `variant` data read from `input`.
    pub fn new(input: R, variant: Variant) -> Self {
        Self {
            bits: BitReader::new(input),
            variant,
            state: State::BlockHeader,
            window: vec![0; WINDOW_SIZE].into_boxed_slice(),
            window_position: 0,
            produced: 0,
            pending_copy: None,
            last_block: false,
        }
    }

    fn emit(&mut self, byte: u8, out: &mut [u8], written: &mut usize) {
        self.window[self.window_position] = byte;
        self.window_position = (self.window_position + 1) % WINDOW_SIZE;
        self.produced += 1;
        out[*written] = byte;
        *written += 1;
    }

    fn read_block_header(&mut self) -> io::Result<()> {
        if self.last_block {
            self.state = State::Done;
            return Ok(());
        }
        self.last_block = self.bits.take(1)? == 1;
        self.state = match self.bits.take(2)? {
            0 => {
                self.bits.align_to_byte();
                let length = self.bits.take(16)?;
                let complement = self.bits.take(16)?;
                if length != !complement & 0xffff {
                    return Err(corrupt("stored block length check failed"));
                }
                State::Stored {
                    remaining: length as usize,
                }
            }
            1 => State::Huffman {
                literals: Huffman::fixed_literals()?,
                distances: Huffman::fixed_distances()?,
            },
            2 => self.dynamic_tables()?,
            _ => return Err(corrupt("reserved block type")),
        };
        Ok(())
    }

    fn dynamic_tables(&mut self) -> io::Result<State> {
        let literal_count = self.bits.take(5)? as usize + 257;
        let distance_count = self.bits.take(5)? as usize + 1;
        let code_length_count = self.bits.take(4)? as usize + 4;
        let mut code_length_lengths = [0u8; 19];
        for &symbol in &CODE_LENGTH_ORDER[..code_length_count] {
            code_length_lengths[symbol] = self.bits.take(3)? as u8;
        }
        let code_lengths = Huffman::new(&code_length_lengths)?;
        let mut lengths = vec![0u8; literal_count + distance_count];
        let mut i = 0;
        while i < lengths.len() {
            let symbol = code_lengths.decode(&mut self.bits)?;
            let (value, repeat) = match symbol {
                0..=15 => (symbol as u8, 1),
                16 => {
                    let previous = *lengths
                        .get(i.wrapping_sub(1))
                        .ok_or_else(|| corrupt("repeat with no previous length"))?;
                    (previous, 3 + self.bits.take(2)? as usize)
                }
                17 => (0, 3 + self.bits.take(3)? as usize),
                _ => (0, 11 + self.bits.take(7)? as usize),
            };
            let end = i + repeat;
            if end > lengths.len() {
                return Err(corrupt("code lengths overflow the table"));
            }
            lengths[i..end].fill(value);
            i = end;
        }
        if lengths[usize::from(END_OF_BLOCK)] == 0 {
            return Err(corrupt("no end-of-block code"));
        }
        let (literal_lengths, distance_lengths) = lengths.split_at(literal_count);
        Ok(State::Huffman {
            literals: Huffman::new(literal_lengths)?,
            distances: Huffman::new(distance_lengths)?,
        })
    }

    /// Length and distance of the back-reference introduced by `symbol`.
    fn back_reference(&mut self, symbol: u16, distances: &Huffman) -> io::Result<(usize, usize)> {
        let index = usize::from(symbol - 257);
        let length = if self.variant == Variant::Deflate64 && symbol == 285 {
            3 + self.bits.take(16)? as usize
        } else {
            let base = *LENGTH_BASE
                .get(index)
                .ok_or_else(|| corrupt("invalid length symbol"))?;
            usize::from(base) + self.bits.take(LENGTH_EXTRA[index])? as usize
        };
        let distance_symbol = usize::from(distances.decode(&mut self.bits)?);
        let usable = if self.variant == Variant::Deflate64 {
            32
        } else {
            30
        };
        if distance_symbol >= usable {
            return Err(corrupt("invalid distance symbol"));
        }
        let distance = DISTANCE_BASE[distance_symbol] as usize
            + self.bits.take(DISTANCE_EXTRA[distance_symbol])? as usize;
        if distance as u64 > self.produced {
            return Err(corrupt("distance points before the start of the data"));
        }
        Ok((length, distance))
    }
}

impl<R: Read> Read for Inflate<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < out.len() {
            if let Some((remaining, distance)) = self.pending_copy {
                let count = remaining.min(out.len() - written);
                for _ in 0..count {
                    let byte =
                        self.window[(self.window_position + WINDOW_SIZE - distance) % WINDOW_SIZE];
                    self.emit(byte, out, &mut written);
                }
                self.pending_copy = (remaining > count).then(|| (remaining - count, distance));
                continue;
            }
            match std::mem::replace(&mut self.state, State::Done) {
                State::Done => break,
                State::BlockHeader => self.read_block_header()?,
                State::Stored { remaining: 0 } => self.state = State::BlockHeader,
                State::Stored { remaining } => {
                    let byte = self.bits.byte()?;
                    self.emit(byte, out, &mut written);
                    self.state = State::Stored {
                        remaining: remaining - 1,
                    };
                }
                State::Huffman {
                    literals,
                    distances,
                } => {
                    match literals.decode(&mut self.bits)? {
                        literal @ 0..=255 => self.emit(literal as u8, out, &mut written),
                        END_OF_BLOCK => {
                            self.state = State::BlockHeader;
                            continue;
                        }
                        symbol => {
                            self.pending_copy = Some(self.back_reference(symbol, &distances)?);
                        }
                    }
                    self.state = State::Huffman {
                        literals,
                        distances,
                    };
                }
            }
        }
        Ok(written)
    }
}

/// A canonical Huffman code, decoded with a direct lookup table indexed by
/// the next 15 input bits (least significant bit first, as DEFLATE stores them).
struct Huffman {
    /// `symbol << 4 | length`, or 0 for bit patterns no code starts with.
    table: Box<[u16]>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> io::Result<Self> {
        let mut counts = [0u16; MAX_BITS + 1];
        for &length in lengths {
            counts[usize::from(length)] += 1;
        }
        counts[0] = 0;
        // Reject over-subscribed codes (more codes than bit patterns).
        let mut left: i32 = 1;
        for &count in &counts[1..] {
            left = left * 2 - i32::from(count);
            if left < 0 {
                return Err(corrupt("over-subscribed Huffman code"));
            }
        }
        let mut next_code = [0u16; MAX_BITS + 1];
        let mut code = 0u16;
        for bits in 1..=MAX_BITS {
            code = (code + counts[bits - 1]) << 1;
            next_code[bits] = code;
        }
        let mut table = vec![0u16; TABLE_SIZE].into_boxed_slice();
        for (symbol, &length) in lengths.iter().enumerate() {
            if length == 0 {
                continue;
            }
            let length = usize::from(length);
            let code = next_code[length];
            next_code[length] += 1;
            let reversed = usize::from(code.reverse_bits() >> (16 - length));
            let entry = ((symbol as u16) << 4) | length as u16;
            for slot in (reversed..TABLE_SIZE).step_by(1 << length) {
                table[slot] = entry;
            }
        }
        Ok(Self { table })
    }

    fn fixed_literals() -> io::Result<Self> {
        let mut lengths = [0u8; 288];
        lengths[..144].fill(8);
        lengths[144..256].fill(9);
        lengths[256..280].fill(7);
        lengths[280..].fill(8);
        Self::new(&lengths)
    }

    fn fixed_distances() -> io::Result<Self> {
        Self::new(&[5u8; 32])
    }

    fn decode<R: Read>(&self, bits: &mut BitReader<R>) -> io::Result<u16> {
        let (peeked, available) = bits.peek(MAX_BITS as u32)?;
        let entry = self.table[peeked as usize];
        let length = u32::from(entry & 0xf);
        if length == 0 || length > available {
            return Err(corrupt("invalid Huffman code"));
        }
        bits.consume(length);
        Ok(entry >> 4)
    }
}

/// Reads bits least significant first, buffering input.
struct BitReader<R> {
    inner: R,
    buffer: Box<[u8]>,
    buffer_position: usize,
    buffer_length: usize,
    bits: u64,
    count: u32,
    exhausted: bool,
}

impl<R: Read> BitReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: vec![0; INPUT_BUFFER].into_boxed_slice(),
            buffer_position: 0,
            buffer_length: 0,
            bits: 0,
            count: 0,
            exhausted: false,
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        while self.count <= 56 {
            if self.buffer_position == self.buffer_length {
                if self.exhausted {
                    break;
                }
                self.buffer_length = self.inner.read(&mut self.buffer[..])?;
                self.buffer_position = 0;
                if self.buffer_length == 0 {
                    self.exhausted = true;
                    break;
                }
            }
            self.bits |= u64::from(self.buffer[self.buffer_position]) << self.count;
            self.buffer_position += 1;
            self.count += 8;
        }
        Ok(())
    }

    /// The next `n` bits (zero-padded past the end) and how many are real.
    fn peek(&mut self, n: u32) -> io::Result<(u64, u32)> {
        if self.count < n {
            self.fill()?;
        }
        Ok((self.bits & ((1u64 << n) - 1), self.count.min(n)))
    }

    fn consume(&mut self, n: u32) {
        self.bits >>= n;
        self.count -= n;
    }

    fn take(&mut self, n: u8) -> io::Result<u32> {
        let n = u32::from(n);
        if n == 0 {
            return Ok(0);
        }
        let (value, available) = self.peek(n)?;
        if available < n {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "compressed data ended early",
            ));
        }
        self.consume(n);
        Ok(value as u32)
    }

    fn align_to_byte(&mut self) {
        let drop = self.count % 8;
        self.consume(drop);
    }

    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(8)? as u8)
    }
}

fn corrupt(what: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("corrupt compressed data: {what}"),
    )
}
