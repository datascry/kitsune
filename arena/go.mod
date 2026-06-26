module github.com/datascry/kitsune/arena

go 1.26

require (
	github.com/datascry/kitsune/evaders/pow v0.0.0
	golang.org/x/image v0.43.0
)

require (
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
)

replace github.com/datascry/kitsune/evaders/pow => ../evaders/pow
