package combination

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Circuit struct {
	RootHash     frontend.Variable `gnark:",public"`
	Path, Helper []frontend.Variable
	hight        frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(circuit.hight, 150)
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	merkle.VerifyProof(api, hFunc, circuit.RootHash, circuit.Path, circuit.Helper)
	return nil
}
