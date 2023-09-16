use entropic::prelude::*;

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "SEQUENCE", extensible = false)]
pub struct UEPagingCoverageInformation {
    pub critical_extensions: UEPagingCoverageInformationCriticalExtensions,
}

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "SEQUENCE", extensible = false, optional_fields = 2)]
pub struct UEPagingCoverageInformation_r13_IEs {
    #[asn(optional_idx = 0)]
    pub mpdcch_num_repetition_r13:
        Option<UEPagingCoverageInformation_r13_IEsMpdcch_NumRepetition_r13>,
    #[asn(optional_idx = 1)]
    pub non_critical_extension: Option<UEPagingCoverageInformation_r13_IEsNonCriticalExtension>,
}

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "NULL")]
pub struct UEPagingCoverageInformationCriticalExtensions_c1_spare7;

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "NULL")]
pub struct UEPagingCoverageInformationCriticalExtensions_c1_spare6;

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "NULL")]
pub struct UEPagingCoverageInformationCriticalExtensions_c1_spare5;

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "NULL")]
pub struct UEPagingCoverageInformationCriticalExtensions_c1_spare4;

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "NULL")]
pub struct UEPagingCoverageInformationCriticalExtensions_c1_spare3;

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "NULL")]
pub struct UEPagingCoverageInformationCriticalExtensions_c1_spare2;

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "NULL")]
pub struct UEPagingCoverageInformationCriticalExtensions_c1_spare1;

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "CHOICE", lb = "0", ub = "7", extensible = false)]
pub enum UEPagingCoverageInformationCriticalExtensions_c1 {
    #[asn(key = 0, extended = false)]
    UePagingCoverageInformation_r13(UEPagingCoverageInformation_r13_IEs),
    #[asn(key = 1, extended = false)]
    Spare7(UEPagingCoverageInformationCriticalExtensions_c1_spare7),
    #[asn(key = 2, extended = false)]
    Spare6(UEPagingCoverageInformationCriticalExtensions_c1_spare6),
    #[asn(key = 3, extended = false)]
    Spare5(UEPagingCoverageInformationCriticalExtensions_c1_spare5),
    #[asn(key = 4, extended = false)]
    Spare4(UEPagingCoverageInformationCriticalExtensions_c1_spare4),
    #[asn(key = 5, extended = false)]
    Spare3(UEPagingCoverageInformationCriticalExtensions_c1_spare3),
    #[asn(key = 6, extended = false)]
    Spare2(UEPagingCoverageInformationCriticalExtensions_c1_spare2),
    #[asn(key = 7, extended = false)]
    Spare1(UEPagingCoverageInformationCriticalExtensions_c1_spare1),
}

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "SEQUENCE", extensible = false)]
pub struct UEPagingCoverageInformationCriticalExtensions_criticalExtensionsFuture {}

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "CHOICE", lb = "0", ub = "1", extensible = false)]
pub enum UEPagingCoverageInformationCriticalExtensions {
    #[asn(key = 0, extended = false)]
    C1(UEPagingCoverageInformationCriticalExtensions_c1),
    #[asn(key = 1, extended = false)]
    CriticalExtensionsFuture(
        UEPagingCoverageInformationCriticalExtensions_criticalExtensionsFuture,
    ),
}

#[derive(
    asn1_codecs_derive :: AperCodec,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "INTEGER", lb = "1", ub = "256")]
pub struct UEPagingCoverageInformation_r13_IEsMpdcch_NumRepetition_r13(pub u16);
/*
impl<'a> arbitrary::Arbitrary<'a> for UEPagingCoverageInformation_r13_IEsMpdcch_NumRepetition_r13 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(UEPagingCoverageInformation_r13_IEsMpdcch_NumRepetition_r13(
            u.int_in_range(1..=256)?,
        ))
    }
}
*/

impl entropic::Entropic for UEPagingCoverageInformation_r13_IEsMpdcch_NumRepetition_r13 {
    fn from_finite_entropy<'a, S: EntropyScheme, I: Iterator<Item = &'a u8>>(
        source: &mut entropic::FiniteEntropySource<'a, S, I>,
    ) -> Result<Self, entropic::Error> {
        Ok(Self(source.get_uniform_range(1..=256)?))
    }
    fn to_finite_entropy<'a, S: EntropyScheme, I: Iterator<Item = &'a mut u8>>(
        &self,
        sink: &mut FiniteEntropySink<'a, S, I>,
    ) -> Result<usize, Error> {
        Ok(sink.put_uniform_range(1..=256 as u16, self.0)?)
    }
}

#[derive(
    asn1_codecs_derive :: AperCodec,
    entropic :: Entropic,
    Eq,
    PartialEq,
    Debug,
    Clone,
)]
#[asn(type = "SEQUENCE", extensible = false)]
pub struct UEPagingCoverageInformation_r13_IEsNonCriticalExtension {}
