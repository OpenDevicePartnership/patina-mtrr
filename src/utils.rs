pub fn lshift_u64(value: u64, shift: u32) -> u64 {
    value << shift
}

pub fn rshift_u64(value: u64, shift: u32) -> u64 {
    value >> shift
}

pub fn mult_u64x32(value: u64, multiplier: u32) -> u64 {
    value * multiplier as u64
}

pub fn get_power_of_two_64(value: u64) -> u64 {
    // Finds the highest power of two less than or equal to the value
    // value.next_power_of_two() / 2
    if value == 0 {
        return 0;
    }

    1u64 << high_bit_set_64(value)
}

pub fn is_pow2(length: u64) -> bool {
    length != 0 && (length & (length - 1)) == 0
}

/// Returns the bit position of the highest bit set in a 64-bit value.
/// Equivalent to log2(x).
///
/// # Arguments
///
/// * `operand` - The 64-bit operand to evaluate.
///
/// # Returns
///
/// * A value between 0 and 63 if the highest bit is found.
/// * -1 if `operand` is zero.
pub fn high_bit_set_64(operand: u64) -> i32 {
    if operand == 0 {
        return -1; // Equivalent to returning -1 for zero
    }

    if operand <= u32::MAX as u64 {
        // If operand is just a 32-bit integer
        return high_bit_set_32(operand as u32);
    }

    // Operand is a 64-bit integer
    if core::mem::size_of::<usize>() == core::mem::size_of::<u32>() {
        // 32-bit architecture
        let high_bits = ((operand >> 32) & u32::MAX as u64) as u32;
        return high_bit_set_32(high_bits) + 32;
    } else {
        // 64-bit architecture
        return high_bit_set_32((operand >> 32) as u32) + 32;
    }
}

/// Returns the bit position of the highest bit set in a 32-bit value.
/// Equivalent to log2(x).
pub fn high_bit_set_32(operand: u32) -> i32 {
    if operand == 0 {
        return -1; // No bits set
    }

    let mut pos = 0;
    let mut value = operand;

    // Find the highest bit set
    while value != 0 {
        pos += 1;
        value >>= 1;
    }

    pos - 1
}
