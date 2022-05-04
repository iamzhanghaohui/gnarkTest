package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	eddsa2 "github.com/consensys/gnark/std/signature/eddsa"
	"math/rand"
	"time"
)

type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKey eddsa2.PublicKey  `gnark:",public"`
	Signature eddsa2.Signature  `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {

	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	return eddsa2.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}

func main() {
	seed := time.Now().Unix()
	randomness := rand.New(rand.NewSource(seed))
	// instantiate hash function
	hFunc := hash.MIMC_BN254.New()

	// create a eddsa key pair
	privateKey, _ := eddsa.New(tedwards.BN254, randomness)
	publicKey := privateKey.Public()

	// note that the message is on 4 bytes
	msg := []byte{0xde, 0xad, 0xf0, 0x0d}

	// sign the message
	signature, _ := privateKey.Sign(msg, hFunc)

	// verifies signature
	isValid, _ := publicKey.Verify(signature, msg, hFunc)
	if !isValid {
		fmt.Println("1. invalid signature")
	} else {
		fmt.Println("1. valid signature")
	}
	//Compile the circuit
	var circuit eddsaCircuit
	circuit.curveID = tedwards.BN254
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	// generating pk, vk
	pk, vk, err := groth16.Setup(r1cs)

	// declare the witness
	var assignment eddsaCircuit

	// assign message value
	assignment.Message = msg

	// public key bytes
	_publicKey := publicKey.Bytes()

	// assign public key values
	assignment.PublicKey.Assign(ecc.BN254, _publicKey[:32])

	// assign signature values
	assignment.Signature.Assign(ecc.BN254, signature)
	// witness
	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	publicWitness, err := witness.Public()
	// generate the proof
	proof, err := groth16.Prove(r1cs, pk, witness)

	// verify the proof
	err = groth16.Verify(proof, vk, publicWitness)

	if err != nil {
		// invalid proof
	} else {
		println("ok")
	}
}
