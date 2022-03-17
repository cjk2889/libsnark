/** @file
 *****************************************************************************

 Implementation of functionality that runs the R1CS GG-ppzkSNARK for
 a given R1CS example.

 See run_r1cs_gg_ppzksnark.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_R1CS_GG_PPZKSNARK_TCC_
#define RUN_R1CS_GG_PPZKSNARK_TCC_

#include <iostream>
#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

using namespace std;

namespace libsnark {

template<typename ppT>
typename std::enable_if<ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_gg_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS GG-ppzkSNARK Affine Verifier");
    const bool answer = r1cs_gg_ppzksnark_affine_verifier_weak_IC<ppT>(vk, primary_input, proof);
    assert(answer == expected_answer);
}

template<typename ppT>
typename std::enable_if<!ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_gg_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS GG-ppzkSNARK Affine Verifier");
    libff::UNUSED(vk, primary_input, proof, expected_answer);
    printf("Affine verifier is not supported; not testing anything.\n");
}

/**
 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_gg_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization)
{
    libff::enter_block("Call to run_r1cs_gg_ppzksnark");

    libff::print_header("R1CS GG-ppzkSNARK Generator");
    r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<r1cs_gg_ppzksnark_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<r1cs_gg_ppzksnark_verification_key<ppT> >(keypair.vk);
        pvk = libff::reserialize<r1cs_gg_ppzksnark_processed_verification_key<ppT> >(pvk);
        libff::leave_block("Test serialization of keys");
    }

    libff::print_header("R1CS GG-ppzkSNARK Prover");
    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        proof = libff::reserialize<r1cs_gg_ppzksnark_proof<ppT> >(proof);
        libff::leave_block("Test serialization of proof");
    }

    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS GG-ppzkSNARK Online Verifier");
    const bool ans2 = r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);

    test_affine_verifier<ppT>(keypair.vk, example.primary_input, proof, ans);

    libff::leave_block("Call to run_r1cs_gg_ppzksnark");

    cout << "proof.g_A :: ";
    proof.g_A.print();

    cout << "proof.g_B :: ";
    proof.g_B.print();

    cout << "proof.g_C :: ";
    proof.g_C.print();

// bls12_381
//    proof.g_A ::
//      (2146322161932427543931342525891626585426461896570243068894397822296737595540759106944212941474370884764299590988069 ,
//      1389788839269729493627718510084155809021333847529565826514474888905826786018904065590927752935775120256643194392049)
//
//    proof.g_B ::
//      (1561652735627035471006507283281513408530878027472384330664918329098492751983227754924803256292534827211814833447550*z
//      + 1667936972832580104825166037575019086366719414926687742686205178949757272663398921568912172079886964692153536505155 ,
//      209080178266387202501602792153165175662461779816804253923610945153476076553664252846290329884011241837449466287704*z
//      + 1544576335246447914017491474913657933566949662351035907964960264307377096571105635445392255170449410210468111792099)
//
//    proof.g_C ::
//      (54420556130887044404120337128424733508053859896979813660628490937013410237604379263002350773952438645603588145393 ,
//      3620482034567377661969594680711467170073640629872489004504882571495068357546454992728329258476724998075572971846694)


// bn128
//    proof.g_A ::
//      (16517085286694491290207981878365460489108768954367381488932027722739866910652 ,
//      19195574750115117169694497086819397492687234191018561181925324321710510836516)
//
//    proof.g_B ::
//      (10662778862720664182674154520399124946848898400584741107392831815699780220096*z
//      + 12956207802718335130141450756102715362385156463491649368371040391433559648879 ,
//      11205601953876241015819498855092997957109849228793418462507715911657591719423*z
//      + 11177158307732231723788859972026463071129764347344968921131468807696423470028)
//
//    proof.g_C ::
//      (599200516484424661541792933364320879488357435529744128154787513069950553875 ,
//      885475787181754453557582445380208871824926790267853334026077443137698828262)


    return ans;
}

} // libsnark

#endif // RUN_R1CS_GG_PPZKSNARK_TCC_
