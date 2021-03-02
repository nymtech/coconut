// TODO: move/rename the file because its not idiomatic go

// TODOs:
/*
	- move params to other file because go is really bitchy about cyclic imports
	- change SVDW map to increment and check for rust compatibility
	- figure out which places should use Affine points rather than Jacobian
	- tests
	- move files around to more nicely deal with the cycles. having `CoconutGo.Parameters` and `coconut.VerificationKey` uses in the same file looks disgusting
	- make comments notation consistent, i.e. either stick to g * r and g + h or g ^ r and g * h

*/

package coconut
