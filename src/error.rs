// pub type MtrrResult<T> = Result<T, MtrrError>;

// #[derive(Debug, PartialEq)]
// pub enum MtrrError {
//     // MTRR Disabled
//     MtrrDisabled,

//     // Unaligned Address
//     UnalignedAddress,

//     // Unaligned Memory Range
//     UnalignedMemoryRange,

//     // Above 1MB Memory Range
//     Above1MBMemoryRange,

//     // Invalid memory length
//     InvalidMemoryRange,
// }

const MAX_BIT: u64 = 0x8000000000000000; // Assuming MAX_BIT represents the highest bit in a 32-bit integer
pub type ReturnStatus = u64; // Assuming ReturnStatus is a 32-bit integer
const fn encode_error(status_code: u64) -> ReturnStatus {
    (MAX_BIT | status_code) as ReturnStatus
}

pub const fn return_error(status_code: u64) -> bool {
    (status_code & (!MAX_BIT)) > 0
}

pub const RETURN_SUCCESS: u64 = 0;
// pub const RETURN_LOAD_ERROR: u64 = encode_error(1);
pub const RETURN_INVALID_PARAMETER: u64 = encode_error(2);
pub const RETURN_UNSUPPORTED: u64 = encode_error(3);
// pub const RETURN_BAD_BUFFER_SIZE: u64 = encode_error(4);
pub const RETURN_BUFFER_TOO_SMALL: u64 = encode_error(5);
// pub const RETURN_NOT_READY: u64 = encode_error(6);
// pub const RETURN_DEVICE_ERROR: u64 = encode_error(7);
// pub const RETURN_WRITE_PROTECTED: u64 = encode_error(8);
pub const RETURN_OUT_OF_RESOURCES: u64 = encode_error(9);
// pub const RETURN_VOLUME_CORRUPTED: u64 = encode_error(10);
// pub const RETURN_VOLUME_FULL: u64 = encode_error(11);
// pub const RETURN_NO_MEDIA: u64 = encode_error(12);
// pub const RETURN_MEDIA_CHANGED: u64 = encode_error(13);
// pub const RETURN_NOT_FOUND: u64 = encode_error(14);
// pub const RETURN_ACCESS_DENIED: u64 = encode_error(15);
// pub const RETURN_NO_RESPONSE: u64 = encode_error(16);
// pub const RETURN_NO_MAPPING: u64 = encode_error(17);
// pub const RETURN_TIMEOUT: u64 = encode_error(18);
// pub const RETURN_NOT_STARTED: u64 = encode_error(19);
pub const RETURN_ALREADY_STARTED: u64 = encode_error(20);
// pub const RETURN_ABORTED: u64 = encode_error(21);
// pub const RETURN_ICMP_ERROR: u64 = encode_error(22);
// pub const RETURN_TFTP_ERROR: u64 = encode_error(23);
// pub const RETURN_PROTOCOL_ERROR: u64 = encode_error(24);
// pub const RETURN_INCOMPATIBLE_VERSION: u64 = encode_error(25);
// pub const RETURN_SECURITY_VIOLATION: u64 = encode_error(26);
// pub const RETURN_CRC_ERROR: u64 = encode_error(27);
// pub const RETURN_END_OF_MEDIA: u64 = encode_error(28);
// pub const RETURN_END_OF_FILE: u64 = encode_error(31);
// pub const RETURN_INVALID_LANGUAGE: u64 = encode_error(32);
// pub const RETURN_COMPROMISED_DATA: u64 = encode_error(33);
// pub const RETURN_IP_ADDRESS_CONFLICT: u64 = encode_error(34);
// pub const RETURN_HTTP_ERROR: u64 = encode_error(35);
