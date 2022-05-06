package main

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
	"os"
	"testing"
)

type merkleCircuit struct {
	RootHash     frontend.Variable `gnark:",public"`
	Path, Helper []frontend.Variable
}

func (circuit *merkleCircuit) Define(api frontend.API) error {
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	merkle.VerifyProof(api, hFunc, circuit.RootHash, circuit.Path, circuit.Helper)
	return nil
}

func TestVerify(t *testing.T) {

	// generate random data
	// makes sure that each chunk of 64 bits fits in a fr modulus, otherwise there are bugs due to the padding (domain separation)
	var buf bytes.Buffer
	for i := 0; i < 10; i++ {
		var leaf fr.Element
		if _, err := leaf.SetRandom(); err != nil {
			t.Fatal(err)
		}
		b := leaf.Bytes()
		buf.Write(b[:])
	}

	// build & verify proof for an elmt in the file
	//你想证明的节点是哪一个 在前面生成的10个里面的哪一个
	proofIndex := uint64(0)
	segmentSize := 32
	merkleRoot, proof, numLeaves, err := merkletree.BuildReaderProof(&buf, bn254.NewMiMC(), segmentSize, proofIndex)
	if err != nil {
		t.Fatal(err)
		os.Exit(-1)
	}
	proofHelper := merkle.GenerateProofHelper(proof, proofIndex, numLeaves)

	verified := merkletree.VerifyProof(bn254.NewMiMC(), merkleRoot, proof, proofIndex, numLeaves)
	if !verified {
		t.Fatal("The merkle proof in plain go should pass")
	}

	// create cs
	circuit := merkleCircuit{
		Path:   make([]frontend.Variable, len(proof)),
		Helper: make([]frontend.Variable, len(proof)-1),
	}

	witness := merkleCircuit{
		Path:     make([]frontend.Variable, len(proof)),
		Helper:   make([]frontend.Variable, len(proof)-1),
		RootHash: (merkleRoot),
	}

	for i := 0; i < len(proof); i++ {
		witness.Path[i] = (proof[i])
	}
	for i := 0; i < len(proof)-1; i++ {
		witness.Helper[i] = (proofHelper[i])
	}
	validWitness, err := frontend.NewWitness(&witness, ecc.BN254)

	validPublicWitness, err := frontend.NewWitness(&witness, ecc.BN254, frontend.PublicOnly())
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	pk, vk, err := groth16.Setup(ccs)

	proof2, err := groth16.Prove(ccs, pk, validWitness)
	err = groth16.Verify(proof2, vk, validPublicWitness)
	if err != nil {
		fmt.Print("not ok")
	} else {
		fmt.Print("ok")
	}
}
