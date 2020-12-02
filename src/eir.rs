//! This module provides functionality to parse Extended Inquiry Response (EIR) Data.
//!
//! This code follows Bluetooth Core Specification (CS) v5.2 and Core
//! Specification Supplement (CSS) v9
//! (https://www.bluetooth.com/specifications/bluetooth-core-specification/).

use bytes::buf::BufExt;
use bytes::*;
use enumflags2::BitFlags;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;

/// See CSS v9 Part A 1.3.2 for flag meaning.
#[repr(u8)]
#[derive(Debug, Copy, Clone, BitFlags, Eq, PartialEq)]
pub enum EIRFlags {
    LELimitedDiscoverableMode = 1 << 0,
    LEGeneralDiscoverableMode = 1 << 1,
    BREDRNotSupported = 1 << 2,
    ControllerSimultaneousLEBREDR = 1 << 3,
    HostSimultaneousLEBREDR = 1 << 4,
}

#[derive(Debug)]
pub struct EIRName {
    name: String,
    complete: bool,
}

impl EIRName {
    fn short_name(name: String) -> Self {
        EIRName {
            name: name,
            complete: false,
        }
    }
    fn complete_name(name: String) -> Self {
        EIRName {
            name: name,
            complete: true,
        }
    }
}

#[derive(Debug)]
pub struct ManufacturerSpecificData {
    company_identifier_code: u16,
    data: Bytes,
}

#[derive(Debug)]
pub enum EIR {
    Flags(BitFlags<EIRFlags>),
    Uuid16(Vec<u16>),
    Uuid32(Vec<u32>),
    Uuid128(Vec<u128>),
    Name(String, bool),
    TxPowerLevel(Vec<i8>),
    Uri(Vec<String>),
    ManufacturerSpecificData(Vec<ManufacturerSpecificData>),
}

#[derive(Error, Debug)]
pub enum EIRError {
    #[error("More than one flag block found.")]
    RepeatedFlag,
    #[error("More than one name block found.")]
    RepeatedName,
    #[error("Unexpected data length {}.", len)]
    UnexpectedDataLength { len: usize },
    #[error("UTF-8 encoding error in URI.")]
    InvalidURI,
}

#[repr(u8)]
#[derive(FromPrimitive)]
#[non_exhaustive]
enum EIRDataTypes {
    Flags = 0x01,
    UUID16Incomplete = 0x02,
    UUID16Complete = 0x03,
    UUID32Incomplete = 0x04,
    UUID32Complete = 0x05,
    UUID128Incomplete = 0x06,
    UUID128Complete = 0x07,
    NameShort = 0x08,
    NameComplete = 0x09,
    TxPowerLevel = 0x0A,
    URI = 0x24,
    ManufacturerSpecificData = 0xFF,
}

/// Parses Extended Inquiry Response (EIR) Data.
///
/// This will silently skip any unknown data types or URIs using
/// encoded schemes.
pub fn parse_eir<T: Buf>(mut buf: T) -> Result<Vec<EIR>, EIRError> {
    let mut eir : Vec<EIR> = Vec::new();
    let mut has_flag = false;
    let mut has_name = false;
    let mut uuid16_idx : Option<usize> = None;

    while buf.has_remaining() {
        // Bluetooth Specification Version 5.2, Vol 3, part C, 8 EXTENDED INQUIRY RESPONSE DATA FORMAT
        // [EIRStructure0, EIRStructure1, ..., EIRStructureN, 0...]
        // EIRStructure:
        //  -- 1 octet --  -- Length octets --
        // [  Length     ,     Data           ]
        // Data:
        //  -- n octet --  -- Length - n octets --
        // [ EIRDataType , EIRData                ]
        let len = buf.get_u8();
        if len == 0 {
            break;
        }

        // data types are all 1 octet
        let data_type = buf.get_u8();
        let mut data = buf.take((len - 1).into());

        // Core Specification Supplement
        // EIRDataType values https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile/
        match FromPrimitive::from_u8(data_type) {
            Some(EIRDataTypes::Flags) => {
                if has_flag {
                    return Err(EIRError::RepeatedFlag);
                }
                has_flag = true;
                eir.push(EIR::Flags(BitFlags::from_bits_truncate(data.get_u8())));
            }
            Some(EIRDataTypes::UUID16Incomplete) | Some(EIRDataTypes::UUID16Complete) => {
                if data.remaining() % 2 != 0 {
                    return Err(EIRError::UnexpectedDataLength {
                        len: data.remaining(),
                    });
                }
                if uuid16_idx.is_none() {
                    uuid16_idx = Some(eir.len());
                    eir.push(EIR::Uuid16(Vec::new()));
                }
                if let EIR::Uuid16(mut uuid16data) = &eir[uuid16_idx.unwrap()] {
                    while data.has_remaining() {
                        uuid16data.push(data.get_u16_le());
                    }
                }
            }
            // Some(EIRDataTypes::UUID32Incomplete) | Some(EIRDataTypes::UUID32Complete) => {
            //     if data.remaining() % 4 != 0 {
            //         return Err(EIRError::UnexpectedDataLength {
            //             len: data.remaining(),
            //         });
            //     }
            //     while data.has_remaining() {
            //         eir.uuid32.push(data.get_u32_le());
            //     }
            // }
            // Some(EIRDataTypes::UUID128Incomplete) | Some(EIRDataTypes::UUID128Complete) => {
            //     if data.remaining() % 16 != 0 {
            //         return Err(EIRError::UnexpectedDataLength {
            //             len: data.remaining(),
            //         });
            //     }
            //     while data.has_remaining() {
            //         eir.uuid128.push(data.get_u128_le());
            //     }
            // }
            Some(EIRDataTypes::NameShort) => {
                if has_name {
                    return Err(EIRError::RepeatedName);
                }
                has_name = true;
                eir.push(EIR::Name(
                    String::from_utf8_lossy(data.bytes()).to_string(),
                    false,
                ));
            }
            Some(EIRDataTypes::NameComplete) => {
                if has_name {
                    return Err(EIRError::RepeatedName);
                }
                has_name = true;
                eir.push(EIR::Name(
                    String::from_utf8_lossy(data.bytes()).to_string(),
                    true,
                ));
            }
            // Some(EIRDataTypes::TxPowerLevel) => {
            //     eir.tx_power_level.push(data.get_i8());
            // }
            // Some(EIRDataTypes::URI) => {
            //     let uri_scheme = data.get_u8();
            //     if uri_scheme == 0x01 {
            //         let uri = String::from_utf8(data.bytes().to_vec());
            //         if uri.is_err() {
            //             return Err(EIRError::InvalidURI);
            //         }
            //         eir.uri.push(uri.unwrap());
            //     } else {
            //         // TODO: URI scheme translation. Skip for now.
            //     }
            // }
            // Some(EIRDataTypes::ManufacturerSpecificData) => {
            //     if data.remaining() < 2 {
            //         return Err(EIRError::UnexpectedDataLength {
            //             len: data.remaining(),
            //         });
            //     }
            //     eir.manufacturer_specific_data
            //         .push(ManufacturerSpecificData {
            //             company_identifier_code: data.get_u16_le(),
            //             data: Bytes::copy_from_slice(data.bytes()),
            //         });
            // }
            _ => {
                // Skip unknown data
            }
        }
        data.advance(data.remaining());
        buf = data.into_inner();
    }

    Ok(eir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn eir_name_test() {
        let input = Bytes::copy_from_slice(b"\x04\x09ABC");
        let eir = parse_eir(input);
        assert!(eir.is_ok());
        let eir = eir.unwrap();
        assert_eq!(eir.len(), 1);
        if let EIR::Name(name, complete) = &eir[0] {
            assert_eq!(name, "ABC");
            assert!(!complete);
        } else {
            assert!(false);
        }
    }

    // #[test]
    // pub fn eir_multiple_test() {
    //     let input = Bytes::copy_from_slice(b"\x02\x01\x06\x03\x03\xAB\xAC\x03\x08Hi");
    //     let eir = parse_eir(input);
    //     assert!(eir.is_ok());
    //     let eir = eir.unwrap();
    //     assert!(eir.flags.is_some());
    //     let flags = eir.flags.unwrap();
    //     assert_eq!(
    //         flags,
    //         EIRFlags::BREDRNotSupported | EIRFlags::LEGeneralDiscoverableMode
    //     );
    //     assert!(!eir.uuid16.is_empty());
    //     assert_eq!(eir.uuid16, vec![0xACAB]);
    //     assert!(eir.uuid32.is_empty());
    //     assert!(eir.uuid128.is_empty());
    //     assert!(eir.name.is_some());
    //     let name = eir.name.unwrap();
    //     assert!(!name.complete);
    //     assert_eq!(name.name, "Hi");
    //     assert!(eir.tx_power_level.is_empty());
    //     assert!(eir.uri.is_empty());
    //     assert!(eir.manufacturer_specific_data.is_empty());
    // }
}
