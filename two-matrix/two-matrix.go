package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const SIZE = 4

type Circuit struct {
	inputA [][]frontend.Variable
	inputB [][]frontend.Variable
	output []frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	for i := 0; i < SIZE; i++ {
		for j := 0; j < SIZE; j++ {
			for k := 0; k < SIZE; k++ {
				api.AssertIsEqual(api.Mul(circuit.inputA[i][j], circuit.inputB[i][j]), circuit.output[k])
			}
		}
	}
	return nil
}
func doPanic() {
	err := recover()
	if err != nil {
		fmt.Println("捕获到panic")
	}
}
func main() {
	defer doPanic()
	temp := make([][]frontend.Variable, SIZE)
	temp2 := make([][]frontend.Variable, SIZE)
	for i := range temp {
		temp[i] = make([]frontend.Variable, SIZE)
		temp2[i] = make([]frontend.Variable, SIZE)
	}
	witness := Circuit{
		inputA: temp,
		inputB: temp2,
		output: make([]frontend.Variable, SIZE),
	}

	for i := 0; i < SIZE; i++ {
		for j := 0; j < SIZE; j++ {
			witness.inputA[i][j] = 1
			witness.inputB[i][j] = 1
		}
		witness.output[i] = 1
	}
	validWitness, err := frontend.NewWitness(&witness, ecc.BN254)

	validPublicWitness, err := frontend.NewWitness(&witness, ecc.BN254, frontend.PublicOnly())
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &witness)
	pk, vk, err := groth16.Setup(ccs)

	proof2, err := groth16.Prove(ccs, pk, validWitness)
	err = groth16.Verify(proof2, vk, validPublicWitness)
	if err != nil {
		fmt.Print("not ok")
	} else {
		fmt.Print("ok")
	}
}
