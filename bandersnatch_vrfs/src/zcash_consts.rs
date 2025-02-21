use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::MontFp;
use ring::ring::Ring;

use crate::bls12_381;
use crate::ring::PADDING_POINT;

// KZG verification key formed using zcash powers of tau setup,
// see https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony/
// This depends only on the trapdoor tau and doesn't change with the SRS size.
pub const ZCASH_KZG_VK: crate::ring::KzgVk = {
    const ZCASH_TAU_G2: bls12_381::G2Affine = {
        const TAU_G2_X_C0: bls12_381::Fq = MontFp!("186544079744757791750913777923182116923406997981176124505869835669370349308168084101869919858020293159217147453183");
        const TAU_G2_X_C1: bls12_381::Fq = MontFp!("2680951345815209329447762511030627858997446358927866220189443219836425021933771668894483091748402109907600527683136");
        const TAU_G2_Y_C0: bls12_381::Fq = MontFp!("2902268288386460594512721059125470579172313681349425350948444194000638363935297586336373516015117406788334505343385");
        const TAU_G2_Y_C1: bls12_381::Fq = MontFp!("1813420068648567014729235095042931383392721750833188405957278380281750025472382039431377469634297470981522036543739");
        const TAU_G2_X: bls12_381::Fq2 = bls12_381::Fq2::new(TAU_G2_X_C0, TAU_G2_X_C1);
        const TAU_G2_Y: bls12_381::Fq2 = bls12_381::Fq2::new(TAU_G2_Y_C0, TAU_G2_Y_C1);
        bls12_381::G2Affine::new_unchecked(TAU_G2_X, TAU_G2_Y)
    };
    crate::ring::KzgVk {
        g1: bls12_381::g1::Config::GENERATOR,
        g2: bls12_381::g2::Config::GENERATOR,
        tau_in_g2: ZCASH_TAU_G2,
    }
};

pub const EMPTY_RING_ZCASH_16: crate::ring::RingCommitment  = {
    const CX: bls12_381::G1Affine = {
        const CX_X: bls12_381::Fq = MontFp!("2271230172102541955969592026708522732816980112608671860954309290742978991706832755971256823933122682800740522481860");
        const CX_Y: bls12_381::Fq = MontFp!("1451160555012815595581641288036282401679141549782163957406756639101297218732596236439585850847136161178154583796356");
        bls12_381::G1Affine::new_unchecked(CX_X, CX_Y)
    };

    const CY: bls12_381::G1Affine = {
        const CY_X: bls12_381::Fq = MontFp!("210502150726635936788225292819898046945247356224019957633607849993798175385143298172931778288939245296702012317114");
        const CY_Y: bls12_381::Fq = MontFp!("339558997085922717543036920782594012537592745281460796203395373853351840576277204324189839255298796803807128100030");
        bls12_381::G1Affine::new_unchecked(CY_X, CY_Y)
    };

    const SELECTOR: bls12_381::G1Affine = {
        const S_X: bls12_381::Fq = MontFp!("1782119914953303272451532413343785016217423941022111405224636116706617268932874941495968306638218277903118171292714");
        const S_Y: bls12_381::Fq = MontFp!("980603551794328446316569624808467604586898338411909681693214961643826527471799191709185815907315792552509777449194");
        bls12_381::G1Affine::new_unchecked(S_X, S_Y)
    };

    Ring::empty_unchecked(1 << 16, CX, CY, SELECTOR, PADDING_POINT)
};

pub const EMPTY_RING_ZCASH_9: crate::ring::RingCommitment  = {
    const CX: bls12_381::G1Affine = {
        const CX_X: bls12_381::Fq = MontFp!("25067020623266226069293680201341409069685170792657027071105325182283424248121597516309878107842269342953295380172");
        const CX_Y: bls12_381::Fq = MontFp!("2786470400352098173681160931184245347175103580667428779551246731456476153414924235466513036103971345006240974715965");
        bls12_381::G1Affine::new_unchecked(CX_X, CX_Y)
    };

    const CY: bls12_381::G1Affine = {
        const CY_X: bls12_381::Fq = MontFp!("3655217819916431569601863487330017596905116639547685402148521885416864908113451092089295341171099708948618108233108");
        const CY_Y: bls12_381::Fq = MontFp!("1362280744092768055774074209527126603251732475301687131635661183202797349281862817858852079871103831478153253586119");
        bls12_381::G1Affine::new_unchecked(CY_X, CY_Y)
    };

    const SELECTOR: bls12_381::G1Affine = {
        const S_X: bls12_381::Fq = MontFp!("2908850075820590559825558591796489926137468891350244723135070577033834833074699096095104618216690855741912718144719");
        const S_Y: bls12_381::Fq = MontFp!("436343574607707198583869582232412021753441754571435491281710311907340647898134029725340232367691953082908705963261");
        bls12_381::G1Affine::new_unchecked(S_X, S_Y)
    };

    Ring::empty_unchecked(1 << 9, CX, CY, SELECTOR, PADDING_POINT)
};


#[cfg(all(test, feature = "std"))]
mod tests {
    use ark_serialize::CanonicalDeserialize;
    use ring::ring::RingBuilderKey;

    use super::*;

    fn build_empty_ring(log_domain_size: usize) -> crate::ring::RingCommitment {
        let piop_params = crate::ring::make_piop_params(1 << log_domain_size);
        let vk = crate::ring::StaticVerifierKey::deserialize_uncompressed_unchecked(
            std::fs::read(format!("zcash-{}.vk", log_domain_size)).unwrap().as_slice()
        ).unwrap();
        let rbk = RingBuilderKey {
            lis_in_g1: vk.lag_g1,
            g1: ZCASH_KZG_VK.g1.into(),
        };
        crate::ring::RingCommitment::with_keys(
            &piop_params,
            &[],
            &rbk,
        )
    }

    #[test]
    fn check_empty_ring_16() {
        assert_eq!(EMPTY_RING_ZCASH_16, build_empty_ring(16));
    }

    #[test]
    fn check_empty_ring_9() {
        assert_eq!(EMPTY_RING_ZCASH_9, build_empty_ring(9));
    }
}
