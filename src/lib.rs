#![allow(non_camel_case_types)]

mod celevel;
mod s1ap;

use asn1_codecs::aper::AperCodec;
use std::os::raw::{c_char, c_uint};
use entropic::prelude::*;

/*
#[cfg(test)]
mod tests {
    use hex::FromHex;
    use crate::s1ap;
    use asn1_codecs::aper::AperCodec;

    #[test]
    fn malformed_1() {
        env_logger::init();
        let bytes = Vec::from_hex("e023ff3c46dd525400594cf60800450200a40003400040842121ac10020a0a8c600a83378e3c0fd333e2268197ef000300829da6487e00000001000000000028406e0000040136400403e85abc0081401d00bcbcbc4000000000bcbcbcbcbc00bcbcbc400000000064bcbcbcbc400081401d00bcbcbc4000000000bcbcbcbcbc00bcbcbc4000000000bcbcbcbcbc400081401d00bcbcbc4000000000bcbcbcbcbc00bcbcbc4004000000bcbcbcbcbc400000").expect("invalid hex");
        let mut data = asn1_codecs::PerCodecData::from_slice_aper(bytes.as_slice());
        let decoded = match s1ap::S1AP_PDU::aper_decode(&mut data) {
            Ok(val) => print!("{:?}", val),
            Err(e) => print!("{:?}", e),
        };
    }
}
*/

/*
/// An arbitrary sequence of messages
#[derive(Debug)]
struct OgsMessages(Vec<s1ap::S1AP_PDU>);

impl<'a> arbitrary::Arbitrary<'a> for OgsMessages {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let vec_length = u.int_in_range(0..=6)?;
        let mut v = Vec::new();
        for _ in 0..vec_length {
            v.push(u.arbitrary()?);
        }
        Ok(OgsMessages(v))
    }
}
*/

// const S1AP_ERR_UNSPECIFIED: isize = -1;
const S1AP_ERR_INVALID_ARG: isize = -2;
const S1AP_ERR_ARBITRARY_FAIL: isize = -3;
const S1AP_ERR_APER_ENCODING: isize = -4;
const S1AP_ERR_OUTPUT_TRUNC: isize = -5;
const S1AP_ERR_EXCLUDED_PDU: isize = -6;

const INITIATING_MESSAGE_EXCL_ID: usize = 1 << 8;
const SUCCESSFUL_OUTCOME_EXCL_ID: usize = 2 << 8;
const UNSUCCESSFUL_OUTCOME_EXCL_ID: usize = 3 << 8;

#[no_mangle]
pub unsafe extern "C" fn s1ap_arbitrary_to_structured(buf_in: *mut c_char, in_len: isize, buf_out: *mut c_char, out_max: isize) -> isize {
    let in_len: usize = match in_len.try_into() {
        Ok(l) => l,
        Err(_) => return S1AP_ERR_INVALID_ARG,
    };

    let out_max: usize = match out_max.try_into() {
        Ok(l) => l,
        Err(_) => return S1AP_ERR_INVALID_ARG,
    };

    let in_slice = std::slice::from_raw_parts(buf_in as *const u8, in_len);
    let out_slice = std::slice::from_raw_parts_mut(buf_out as *mut u8, out_max);

    let in_iter = in_slice.iter().chain(std::iter::repeat(&0u8).take(200_000 - in_slice.len())); // Cap total entropy to 200,000 bytes for performance

    let Ok(s1ap_message) = s1ap::S1AP_PDU::from_finite_entropy(&mut FiniteEntropySource::from_iter(in_iter)) else {
        return S1AP_ERR_ARBITRARY_FAIL
    };

    let mut encoded = asn1_codecs::PerCodecData::new_aper();
    match s1ap_message.aper_encode(&mut encoded) {
        Ok(()) => (),
        _ => return S1AP_ERR_APER_ENCODING // If the encoding isn't successful, short-circuit this test
    }

    let aper_message_bytes = encoded.into_bytes();
    let aper_message_slice = aper_message_bytes.as_slice();
    if aper_message_slice.len() > out_max {
        return S1AP_ERR_OUTPUT_TRUNC
    }

    out_slice[..aper_message_slice.len()].copy_from_slice(aper_message_slice);

    match aper_message_slice.len().try_into() {
        Ok(l) => l,
        Err(_) => S1AP_ERR_OUTPUT_TRUNC
    }
}

#[no_mangle]
pub unsafe extern "C" fn s1ap_arbitrary_to_structured_exclude(buf_in: *mut c_char, in_len: isize, pdus: *mut isize, pdus_len: isize, buf_out: *mut c_char, out_max: isize) -> isize {
    let pdus_len: usize = match pdus_len.try_into() {
        Ok(l) => l,
        Err(_) => return S1AP_ERR_INVALID_ARG
    };

    let in_len: usize = match in_len.try_into() {
        Ok(l) => l,
        Err(_) => return S1AP_ERR_INVALID_ARG,
    };

    let out_max: usize = match out_max.try_into() {
        Ok(l) => l,
        Err(_) => return S1AP_ERR_INVALID_ARG,
    };

    let in_slice = std::slice::from_raw_parts(buf_in as *const u8, in_len);
    let pdus_slice = std::slice::from_raw_parts(pdus as *const usize, pdus_len);
    let out_slice = std::slice::from_raw_parts_mut(buf_out as *mut u8, out_max);

    let s1ap_message = s1ap::S1AP_PDU::from_entropy(&mut EntropySource::from_slice(in_slice));

    let pdu_id = match &s1ap_message {
        s1ap::S1AP_PDU::InitiatingMessage(init_msg) => INITIATING_MESSAGE_EXCL_ID + init_msg.procedure_code.0 as usize,
        s1ap::S1AP_PDU::SuccessfulOutcome(success_msg) => SUCCESSFUL_OUTCOME_EXCL_ID + success_msg.procedure_code.0 as usize,
        s1ap::S1AP_PDU::UnsuccessfulOutcome(unsuccess_msg) => UNSUCCESSFUL_OUTCOME_EXCL_ID + unsuccess_msg.procedure_code.0 as usize,
    };

    for excluded_pdu in pdus_slice {
        if pdu_id == *excluded_pdu {
            return S1AP_ERR_EXCLUDED_PDU
        }
    }

    let mut encoded = asn1_codecs::PerCodecData::new_aper();
    match s1ap_message.aper_encode(&mut encoded) {
        Ok(()) => (),
        _ => return S1AP_ERR_APER_ENCODING // If the encoding isn't successful, short-circuit this test
    }

    let aper_message_bytes = encoded.into_bytes();
    let aper_message_slice = aper_message_bytes.as_slice();
    if aper_message_slice.len() > out_max {
        return S1AP_ERR_OUTPUT_TRUNC
    }

    out_slice[..aper_message_slice.len()].copy_from_slice(aper_message_slice);

    match aper_message_slice.len().try_into() {
        Ok(l) => l,
        Err(_) => S1AP_ERR_OUTPUT_TRUNC
    }
}

#[repr(C)]
pub struct StructuredOutput {
    buf: *mut c_char,
    len: isize,
}

/*
#[no_mangle]
pub unsafe extern "C" fn s1ap_arbitrary_to_multistructured(buf_in: *mut c_char, in_len: isize, buf_out: *mut StructuredOutput, out_len: isize) -> isize {
    let in_len: usize = match in_len.try_into() {
        Ok(l) => l,
        Err(_) => return S1AP_ERR_INVALID_ARG,
    };

    let out_len: usize = match out_len.try_into() {
        Ok(l) => l,
        Err(_) => return S1AP_ERR_INVALID_ARG,
    };

    let in_slice = std::slice::from_raw_parts(buf_in as *const u8, in_len);
    let messages_slice = std::slice::from_raw_parts_mut(buf_out, out_len);
    let entropy = Entropy::from_slice(in_slice);

    let s1ap_messages = match OgsMessages::(&mut Unstructured::new(in_slice)) {
        Ok(msg) => msg,
        Err(_) => return S1AP_ERR_ARBITRARY_FAIL,
    };

    let mut idx = 0;
    for message in s1ap_messages.0.iter() {
        if idx >= messages_slice.len() {
            break
        }

        let out_slice = std::slice::from_raw_parts_mut(messages_slice[idx].buf as *mut u8, messages_slice[idx].len as usize);
        
        let mut encoded = asn1_codecs::PerCodecData::new_aper();
        match message.aper_encode(&mut encoded) {
            Ok(()) => (),
            _ => {
                continue
                // If the encoding isn't successful, skip the message
            }
        }
        
        let aper_message_bytes = encoded.into_bytes();
        let aper_message_slice = aper_message_bytes.as_slice();
        if aper_message_slice.len() > out_len {
            continue
        }

        out_slice[..aper_message_slice.len()].copy_from_slice(aper_message_slice);
        idx += 1
    }

    idx as isize
}
*/

#[no_mangle]
pub unsafe extern "C" fn s1ap_msg_len(buf_in: *mut c_char, in_len: isize) -> isize {
    if in_len <= 0 {
        return -1;
    }

    let s = std::slice::from_raw_parts(buf_in as *const u8, in_len as usize);

    // The current implementation just decodes the whole bytes, then encodes it and measures
    // the length in bytes.

    let mut data = asn1_codecs::PerCodecData::from_slice_aper(s);
    let decoded = match s1ap::S1AP_PDU::aper_decode(&mut data) {
        Ok(val) => val,
        Err(_) => return -1
    };

    let mut encode_data = asn1_codecs::PerCodecData::new_aper();
    match decoded.aper_encode(&mut encode_data) {
        Ok(_) => (),
        Err(_) => return -1,
    }

    encode_data.length_in_bytes() as isize
}

const S1AP_MSG_INITIATING: c_uint = 1 << 14;
const S1AP_MSG_SUCCESS: c_uint = 2 << 14;
// const S1AP_MSG_FAILURE: c_uint = 0 << 14; // Implicit

const S1AP_RESP_CATEGORY_ENB_CONFIG_UPDATE: c_uint = 3 << 11;
const S1AP_RESP_CATEGORY_HANDOVER_PREP: c_uint = 4 << 11;
const S1AP_RESP_CATEGORY_INIT_CTX_SETUP: c_uint = 5 << 11;
const S1AP_RESP_CATEGORY_UE_CONTEXT_RESUME: c_uint = 6 << 11;
const S1AP_RESP_CATEGORY_UE_CONTEXT_MODIFICATION: c_uint = 7 << 11;
const S1AP_RESP_CATEGORY_MME_CONFIGURATION_UPDATE: c_uint = 8 << 11;
const S1AP_RESP_CATEGORY_PATH_SWITCH_REQ: c_uint = 9 << 11;
const S1AP_RESP_CATEGORY_S1_SETUP: c_uint = 10 << 11;
const S1AP_RESP_CATEGORY_HANDOVER: c_uint = 11 << 11;


const CODE_CATEGORY_RADIO_NETWORK: c_uint = 1 << 8;
const CODE_CATEGORY_TRANSPORT: c_uint = 2 << 8;
const CODE_CATEGORY_NAS: c_uint = 3 << 8;
const CODE_CATEGORY_PROTOCOL: c_uint = 4 << 8;
const CODE_CATEGORY_MISC: c_uint = 5 << 8;
const CODE_CATEGORY_MISSING: c_uint = 6 << 8;




#[no_mangle]
pub unsafe extern "C" fn s1ap_response_code(buf_in: *mut c_char, in_len: isize) -> c_uint {
    if in_len <= 0 {
        return 0;
    }

    let s = std::slice::from_raw_parts_mut(buf_in as *mut u8, in_len as usize);

    let mut data = asn1_codecs::PerCodecData::from_slice_aper(s);
    let decoded = match s1ap::S1AP_PDU::aper_decode(&mut data) {
        Ok(val) => val,
        Err(_) => return 0
    };

    match decoded {
        s1ap::S1AP_PDU::InitiatingMessage(i) => S1AP_MSG_INITIATING + match i.value {
            s1ap::InitiatingMessageValue::Id_CellTrafficTrace(_) => 1,
            s1ap::InitiatingMessageValue::Id_ConnectionEstablishmentIndication(_) => 2,
            s1ap::InitiatingMessageValue::Id_DeactivateTrace(_) => 3,
            s1ap::InitiatingMessageValue::Id_DownlinkS1cdma2000tunnelling(_) => 4,
            s1ap::InitiatingMessageValue::Id_E_RABModificationIndication(_) => 5,
            s1ap::InitiatingMessageValue::Id_E_RABModify(_) => 6,
            s1ap::InitiatingMessageValue::Id_E_RABRelease(_) => 7,
            s1ap::InitiatingMessageValue::Id_E_RABReleaseIndication(_) => 8,
            s1ap::InitiatingMessageValue::Id_E_RABSetup(_) => 9,
            s1ap::InitiatingMessageValue::Id_ENBConfigurationUpdate(_) => 10,
            s1ap::InitiatingMessageValue::Id_ErrorIndication(_) => 11,
            s1ap::InitiatingMessageValue::Id_HandoverCancel(_) => 12,
            s1ap::InitiatingMessageValue::Id_HandoverNotification(_) => 13,
            s1ap::InitiatingMessageValue::Id_HandoverPreparation(_) => 14,
            s1ap::InitiatingMessageValue::Id_HandoverResourceAllocation(_) => 15,
            s1ap::InitiatingMessageValue::Id_HandoverSuccess(_) => 16,
            s1ap::InitiatingMessageValue::Id_InitialContextSetup(_) => 17,
            s1ap::InitiatingMessageValue::Id_Kill(_) => 18,
            s1ap::InitiatingMessageValue::Id_LocationReport(_) => 19,
            s1ap::InitiatingMessageValue::Id_LocationReportingControl(_) => 20,
            s1ap::InitiatingMessageValue::Id_LocationReportingFailureIndication(_) => 21,
            s1ap::InitiatingMessageValue::Id_MMECPRelocationIndication(_) => 22,
            s1ap::InitiatingMessageValue::Id_MMEConfigurationTransfer(_) => 23,
            s1ap::InitiatingMessageValue::Id_MMEConfigurationUpdate(_) => 24,
            s1ap::InitiatingMessageValue::Id_MMEDirectInformationTransfer(_) => 25,
            s1ap::InitiatingMessageValue::Id_MMEEarlyStatusTransfer(_) => 26,
            s1ap::InitiatingMessageValue::Id_MMEStatusTransfer(_) => 27,
            s1ap::InitiatingMessageValue::Id_NASDeliveryIndication(_) => 28,
            s1ap::InitiatingMessageValue::Id_NASNonDeliveryIndication(_) => 29,
            s1ap::InitiatingMessageValue::Id_OverloadStart(_) => 30,
            s1ap::InitiatingMessageValue::Id_OverloadStop(_) => 31,
            s1ap::InitiatingMessageValue::Id_PWSFailureIndication(_) => 32,
            s1ap::InitiatingMessageValue::Id_PWSRestartIndication(_) => 33,
            s1ap::InitiatingMessageValue::Id_Paging(_) => 34,
            s1ap::InitiatingMessageValue::Id_PathSwitchRequest(_) => 35,
            s1ap::InitiatingMessageValue::Id_RerouteNASRequest(_) => 37,
            s1ap::InitiatingMessageValue::Id_Reset(_) => 38,
            s1ap::InitiatingMessageValue::Id_RetrieveUEInformation(_) => 39,
            s1ap::InitiatingMessageValue::Id_S1Setup(_) => 40,
            s1ap::InitiatingMessageValue::Id_SecondaryRATDataUsageReport(_) => 41,
            s1ap::InitiatingMessageValue::Id_TraceFailureIndication(_) => 42,
            s1ap::InitiatingMessageValue::Id_TraceStart(_) => 43,
            s1ap::InitiatingMessageValue::Id_UECapabilityInfoIndication(_) => 44,
            s1ap::InitiatingMessageValue::Id_UEContextModification(_) => 45,
            s1ap::InitiatingMessageValue::Id_UEContextModificationIndication(_) => 46,
            s1ap::InitiatingMessageValue::Id_UEContextRelease(_) => 47,
            s1ap::InitiatingMessageValue::Id_UEContextReleaseRequest(_) => 48,
            s1ap::InitiatingMessageValue::Id_UEContextResume(_) => 49,
            s1ap::InitiatingMessageValue::Id_UEContextSuspend(_) => 50,
            s1ap::InitiatingMessageValue::Id_UEInformationTransfer(_) => 51,
            s1ap::InitiatingMessageValue::Id_UERadioCapabilityIDMapping(_) => 52,
            s1ap::InitiatingMessageValue::Id_UERadioCapabilityMatch(_) => 53,
            s1ap::InitiatingMessageValue::Id_UplinkS1cdma2000tunnelling(_) => 54,
            s1ap::InitiatingMessageValue::Id_WriteReplaceWarning(_) => 55,
            s1ap::InitiatingMessageValue::Id_downlinkNASTransport(_) => 56,
            s1ap::InitiatingMessageValue::Id_downlinkNonUEAssociatedLPPaTransport(_) => 57,
            s1ap::InitiatingMessageValue::Id_downlinkUEAssociatedLPPaTransport(_) => 58,
            s1ap::InitiatingMessageValue::Id_eNBCPRelocationIndication(_) => 59,
            s1ap::InitiatingMessageValue::Id_eNBConfigurationTransfer(_) => 60,
            s1ap::InitiatingMessageValue::Id_eNBDirectInformationTransfer(_) => 61,
            s1ap::InitiatingMessageValue::Id_eNBEarlyStatusTransfer(_) => 62,
            s1ap::InitiatingMessageValue::Id_eNBStatusTransfer(_) => 63,
            s1ap::InitiatingMessageValue::Id_initialUEMessage(_) => 64,
            s1ap::InitiatingMessageValue::Id_uplinkNASTransport(_) => 65,
            s1ap::InitiatingMessageValue::Id_uplinkNonUEAssociatedLPPaTransport(_) => 66,
            s1ap::InitiatingMessageValue::Id_uplinkUEAssociatedLPPaTransport(_) => 67,
            _ => 68,
        },
        s1ap::S1AP_PDU::SuccessfulOutcome(s) => S1AP_MSG_SUCCESS + match s.value {
            s1ap::SuccessfulOutcomeValue::Id_E_RABModificationIndication(_) => 1,
            s1ap::SuccessfulOutcomeValue::Id_E_RABModify(_) => 2,
            s1ap::SuccessfulOutcomeValue::Id_E_RABRelease(_) => 3,
            s1ap::SuccessfulOutcomeValue::Id_E_RABSetup(_) => 4,
            s1ap::SuccessfulOutcomeValue::Id_ENBConfigurationUpdate(_) => 5,
            s1ap::SuccessfulOutcomeValue::Id_HandoverCancel(_) => 6,
            s1ap::SuccessfulOutcomeValue::Id_HandoverPreparation(_) => 7,
            s1ap::SuccessfulOutcomeValue::Id_HandoverResourceAllocation(_) => 8,
            s1ap::SuccessfulOutcomeValue::Id_InitialContextSetup(_) => 9,
            s1ap::SuccessfulOutcomeValue::Id_Kill(_) => 10,
            s1ap::SuccessfulOutcomeValue::Id_MMEConfigurationUpdate(_) => 11,
            s1ap::SuccessfulOutcomeValue::Id_PathSwitchRequest(_) => 12,
            s1ap::SuccessfulOutcomeValue::Id_Reset(_) => 13,
            s1ap::SuccessfulOutcomeValue::Id_S1Setup(_) => 14,
            s1ap::SuccessfulOutcomeValue::Id_UEContextModification(_) => 15,
            s1ap::SuccessfulOutcomeValue::Id_UEContextModificationIndication(_) => 16,
            s1ap::SuccessfulOutcomeValue::Id_UEContextRelease(_) => 17,
            s1ap::SuccessfulOutcomeValue::Id_UEContextResume(_) => 18,
            s1ap::SuccessfulOutcomeValue::Id_UEContextSuspend(_) => 19, 
            s1ap::SuccessfulOutcomeValue::Id_UERadioCapabilityIDMapping(_) => 20,
            s1ap::SuccessfulOutcomeValue::Id_UERadioCapabilityMatch(_) => 21,
            s1ap::SuccessfulOutcomeValue::Id_WriteReplaceWarning(_) => 22,
        },
        s1ap::S1AP_PDU::UnsuccessfulOutcome(uo) => match uo.value {
            s1ap::UnsuccessfulOutcomeValue::Id_ENBConfigurationUpdate(f) => {
                for ie in f.protocol_i_es.0 {
                    match ie.value {
                        s1ap::ENBConfigurationUpdateFailureProtocolIEs_EntryValue::Id_Cause(cause) => return S1AP_RESP_CATEGORY_ENB_CONFIG_UPDATE + match cause {
                            s1ap::Cause::RadioNetwork(rn) => CODE_CATEGORY_RADIO_NETWORK + rn.0 as c_uint,
                            s1ap::Cause::Transport(t) => CODE_CATEGORY_TRANSPORT + t.0 as c_uint,
                            s1ap::Cause::Nas(n) => CODE_CATEGORY_NAS + n.0 as c_uint,
                            s1ap::Cause::Protocol(p) => CODE_CATEGORY_PROTOCOL + p.0 as c_uint,
                            s1ap::Cause::Misc(m) => CODE_CATEGORY_MISC + m.0 as c_uint,
                        },
                        _ => continue
                    }
                }

                S1AP_RESP_CATEGORY_ENB_CONFIG_UPDATE + CODE_CATEGORY_MISSING
            },
            s1ap::UnsuccessfulOutcomeValue::Id_HandoverPreparation(f) => {
                for ie in f.protocol_i_es.0 {
                    match ie.value {
                        s1ap::HandoverPreparationFailureProtocolIEs_EntryValue::Id_Cause(cause) => return S1AP_RESP_CATEGORY_HANDOVER_PREP + match cause {
                            s1ap::Cause::RadioNetwork(rn) => rn.0 as c_uint,
                            s1ap::Cause::Transport(t) => t.0 as c_uint,
                            s1ap::Cause::Nas(n) => n.0 as c_uint,
                            s1ap::Cause::Protocol(p) => p.0 as c_uint,
                            s1ap::Cause::Misc(m) => m.0 as c_uint,
                        },
                        _ => continue
                    }
                }
                S1AP_RESP_CATEGORY_HANDOVER_PREP + CODE_CATEGORY_MISSING
            },
            s1ap::UnsuccessfulOutcomeValue::Id_HandoverResourceAllocation(f) => {
                for ie in f.protocol_i_es.0 {
                    match ie.value {
                        s1ap::HandoverFailureProtocolIEs_EntryValue::Id_Cause(cause) => return S1AP_RESP_CATEGORY_HANDOVER + match cause {
                            s1ap::Cause::RadioNetwork(rn) => rn.0 as c_uint,
                            s1ap::Cause::Transport(t) => t.0 as c_uint,
                            s1ap::Cause::Nas(n) => n.0 as c_uint,
                            s1ap::Cause::Protocol(p) => p.0 as c_uint,
                            s1ap::Cause::Misc(m) => m.0 as c_uint,
                        },
                        _ => continue
                    }
                }

                S1AP_RESP_CATEGORY_HANDOVER + CODE_CATEGORY_MISSING
            },
            s1ap::UnsuccessfulOutcomeValue::Id_InitialContextSetup(f) => {
                for ie in f.protocol_i_es.0 {
                    match ie.value {
                        s1ap::InitialContextSetupFailureProtocolIEs_EntryValue::Id_Cause(cause) => return S1AP_RESP_CATEGORY_INIT_CTX_SETUP + match cause {
                            s1ap::Cause::RadioNetwork(rn) => rn.0 as c_uint,
                            s1ap::Cause::Transport(t) => t.0 as c_uint,
                            s1ap::Cause::Nas(n) => n.0 as c_uint,
                            s1ap::Cause::Protocol(p) => p.0 as c_uint,
                            s1ap::Cause::Misc(m) => m.0 as c_uint,
                        },
                        _ => continue
                    }
                }
                S1AP_RESP_CATEGORY_INIT_CTX_SETUP + CODE_CATEGORY_MISSING
            },
            s1ap::UnsuccessfulOutcomeValue::Id_MMEConfigurationUpdate(f) => {
                for ie in f.protocol_i_es.0 {
                    match ie.value {
                        s1ap::MMEConfigurationUpdateFailureProtocolIEs_EntryValue::Id_Cause(cause) => return S1AP_RESP_CATEGORY_MME_CONFIGURATION_UPDATE + match cause {
                            s1ap::Cause::RadioNetwork(rn) => rn.0 as c_uint,
                            s1ap::Cause::Transport(t) => t.0 as c_uint,
                            s1ap::Cause::Nas(n) => n.0 as c_uint,
                            s1ap::Cause::Protocol(p) => p.0 as c_uint,
                            s1ap::Cause::Misc(m) => m.0 as c_uint,
                        },
                        _ => continue
                    }
                }

                S1AP_RESP_CATEGORY_MME_CONFIGURATION_UPDATE + CODE_CATEGORY_MISSING
            },
            s1ap::UnsuccessfulOutcomeValue::Id_PathSwitchRequest(f) => {
                for ie in f.protocol_i_es.0 {
                    match ie.value {
                        s1ap::PathSwitchRequestFailureProtocolIEs_EntryValue::Id_Cause(cause) => return S1AP_RESP_CATEGORY_PATH_SWITCH_REQ + match cause {
                            s1ap::Cause::RadioNetwork(rn) => rn.0 as c_uint,
                            s1ap::Cause::Transport(t) => t.0 as c_uint,
                            s1ap::Cause::Nas(n) => n.0 as c_uint,
                            s1ap::Cause::Protocol(p) => p.0 as c_uint,
                            s1ap::Cause::Misc(m) => m.0 as c_uint,
                        },
                        _ => continue
                    }
                }

                S1AP_RESP_CATEGORY_PATH_SWITCH_REQ + CODE_CATEGORY_MISSING
            },
            s1ap::UnsuccessfulOutcomeValue::Id_S1Setup(f) => {
                for ie in f.protocol_i_es.0 {
                    match ie.value {
                        s1ap::S1SetupFailureProtocolIEs_EntryValue::Id_Cause(cause) => return S1AP_RESP_CATEGORY_S1_SETUP + match cause {
                            s1ap::Cause::RadioNetwork(rn) => rn.0 as c_uint,
                            s1ap::Cause::Transport(t) => t.0 as c_uint,
                            s1ap::Cause::Nas(n) => n.0 as c_uint,
                            s1ap::Cause::Protocol(p) => p.0 as c_uint,
                            s1ap::Cause::Misc(m) => m.0 as c_uint,
                        },
                        _ => continue
                    }
                }

                S1AP_RESP_CATEGORY_S1_SETUP + CODE_CATEGORY_MISSING
            },
            s1ap::UnsuccessfulOutcomeValue::Id_UEContextModification(f) => {
                for ie in f.protocol_i_es.0 {
                    match ie.value {
                        s1ap::UEContextModificationFailureProtocolIEs_EntryValue::Id_Cause(cause) => return S1AP_RESP_CATEGORY_UE_CONTEXT_MODIFICATION + match cause {
                            s1ap::Cause::RadioNetwork(rn) => rn.0 as c_uint,
                            s1ap::Cause::Transport(t) => t.0 as c_uint,
                            s1ap::Cause::Nas(n) => n.0 as c_uint,
                            s1ap::Cause::Protocol(p) => p.0 as c_uint,
                            s1ap::Cause::Misc(m) => m.0 as c_uint,
                        },
                        _ => continue
                    }
                }

                S1AP_RESP_CATEGORY_UE_CONTEXT_MODIFICATION + CODE_CATEGORY_MISSING
            },
            s1ap::UnsuccessfulOutcomeValue::Id_UEContextResume(f) => {
                for ie in f.protocol_i_es.0 {
                    match ie.value {
                        s1ap::UEContextResumeFailureProtocolIEs_EntryValue::Id_Cause(cause) => return S1AP_RESP_CATEGORY_UE_CONTEXT_RESUME + match cause {
                            s1ap::Cause::RadioNetwork(rn) => rn.0 as c_uint,
                            s1ap::Cause::Transport(t) => t.0 as c_uint,
                            s1ap::Cause::Nas(n) => n.0 as c_uint,
                            s1ap::Cause::Protocol(p) => p.0 as c_uint,
                            s1ap::Cause::Misc(m) => m.0 as c_uint,
                        },
                        _ => continue
                    }
                }

                S1AP_RESP_CATEGORY_UE_CONTEXT_RESUME + CODE_CATEGORY_MISSING
            },
        },
    }
}

