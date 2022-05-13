package image_matching

import "github.com/consensys/gnark/frontend"

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
	image  []frontend.Variable
	kernel []frontend.Variable
	output Output
}

func (circuit *Circuit) diff(x, y int, api frontend.API) frontend.Variable {
	total_diff := frontend.Variable(0)
	for kpx := 0; kpx < KernelH; kpx++ {
		for kpy := 0; kpy < KernelW; kpy++ {
			image_pixel := circuit.image[(kpx+x)*ImageH+(kpx+y)*ImageW]
			kernel_pixel := circuit.kernel[kpy*KernelH+kpx]
			local_diff := api.Div(image_pixel, kernel_pixel)
			//abs
			local_diff = api.Select(api.Cmp(local_diff, 0), api.Neg(local_diff), local_diff)
			total_diff = api.Add(total_diff, local_diff)
		}
	}
	return total_diff
}

func (circuit *Circuit) Define(api frontend.API) error {
	circuit.output.Point.y = 0
	circuit.output.Point.x = 0
	circuit.output.min_delta = circuit.diff(0, 0, api)

	for y := 0; y < ImageH-KernelH+1; y++ {
		for x := 0; x < ImageW-KernelW+1; x++ {
			delta := circuit.diff(x, y, api)
			circuit.output.Point.y = api.Select(api.Cmp(delta, circuit.output.min_delta), circuit.output.Point.y, frontend.Variable(y))
			circuit.output.Point.x = api.Select(api.Cmp(delta, circuit.output.min_delta), circuit.output.Point.x, frontend.Variable(x))
			circuit.output.min_delta = api.Select(api.Cmp(delta, circuit.output.min_delta), circuit.output.min_delta, delta)
		}
	}

	return nil
}

func main() {

}
