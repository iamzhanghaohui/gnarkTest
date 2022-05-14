package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const (
	ImageW  = 5
	ImageH  = 5
	KernelW = 2
	KernelH = 2
)

type Point struct {
	x frontend.Variable
	y frontend.Variable
}
type Output struct {
	Point     Point
	min_delta frontend.Variable
}

//todo what do u want to prove? which variable is public?
type Circuit struct {
	image  []frontend.Variable `gnark:",public"`
	kernel []frontend.Variable
	output Output `gnark:",public"`
}

func (circuit *Circuit) diff(x, y int, api frontend.API) frontend.Variable {
	totalDiff := frontend.Variable(0)
	for kpx := 0; kpx < KernelH; kpx++ {
		for kpy := 0; kpy < KernelW; kpy++ {

			localDiff := api.Div(circuit.image[ImageW], circuit.kernel[KernelH])
			//abs
			localDiff = api.Select(api.Cmp(localDiff, 0), api.Neg(localDiff), localDiff)
			totalDiff = api.Add(totalDiff, localDiff)
		}
	}
	return totalDiff
}

func (circuit *Circuit) Define(api frontend.API) error {

	temp := circuit.diff(0, 0, api)
	var tempy, tempx frontend.Variable
	for y := 0; y < ImageH-KernelH+1; y++ {
		for x := 0; x < ImageW-KernelW+1; x++ {
			delta := circuit.diff(x, y, api)
			tempy = api.Select(api.Cmp(delta, temp), circuit.output.Point.y, frontend.Variable(y))
			tempx = api.Select(api.Cmp(delta, temp), circuit.output.Point.x, frontend.Variable(x))
			temp = api.Select(api.Cmp(delta, temp), temp, delta)
		}
	}
	api.AssertIsEqual(circuit.output.min_delta, temp)
	api.AssertIsEqual(circuit.output.Point.x, tempx)
	api.AssertIsEqual(circuit.output.Point.y, tempy)
	return nil
}

func main() {

	output := Output{
		Point:     Point{x: frontend.Variable(1), y: frontend.Variable(2)},
		min_delta: frontend.Variable(0),
	}

	witness := Circuit{
		image:  make([]frontend.Variable, ImageW*ImageH),
		kernel: make([]frontend.Variable, KernelW*KernelH),
		output: output,
	}

	for i := 0; i < ImageW*ImageH; i++ {
		witness.image[i] = 1
	}
	for i := 0; i < KernelW*KernelH; i++ {
		witness.kernel[i] = 1
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
