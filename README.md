# Leaf

[![GoDoc](https://godoc.org/github.com/joeshaw/leaf?status.svg)](http://godoc.org/github.com/joeshaw/leaf)

`leaf` is a Go package and command-line tool providing access to
the Nissan Leaf North American NissanConnect EV API.

Through this API you can ask your vehicle for the latest battery status,
start charging remotely, start or stop climate control remotely, and retrieve the last known location of the vehicle.

This repo replaces my [Carwings](https://github.com/joeshaw/carwings)
project, which implemented an older but global API.  This API only works
for North American vehicles (and I've only tested on a vehicle in the
US, so it may not work in Canada).

## Command-line tool

The `leaf` tool can be installed with:

    go get github.com/joeshaw/leaf/cmd/leaf

Run `leaf` by itself to see full usage information.

To update vehicle information:

    leaf -username <username> -password <password> update

To get latest battery status:

    leaf -username <username> -password <password> battery

This will print something like:

    Getting last updated battery status...
    Battery status as of 2020-12-26 11:35:58 -0500 EST:
      Battery remaining: 91%
      Cruising range: 88 miles (83 miles with heat/AC)
      Plug-in state: connected
      Charging status: yes
      Time to full:
        Level 1 charge: 8h30m
        Level 2 charge: 3h0m
        Level 2 at 6 kW: 2h0m

For some people the username is an email address.  For others it's a
distinct username.

Config values can be provided through environment variables (such as
`LEAF_USERNAME`) or in a `~/.leaf` file in the format:

```
username <username>
password <password>
country US
```

## NissanConnect North America protocol

Ben Woodford put together the first [protocol
reference](https://gist.github.com/BenWoodford/141ca350445e994e69a70aabfb6db942),
and several people have added onto that Gist.

Tobias Westergaard Kjeldsen has created a [Dart library](https://gitlab.com/tobiaswkjeldsen/dartnissanconnectna) for this API which he uses in his [My Leaf](https://gitlab.com/tobiaswkjeldsen/carwingsflutter) app for Android and iOS.

## Contributing

Issues and pull requests are welcome.  When filing a PR, please make
sure the code has been run through `gofmt`.

## License

Copyright 2017-2020 Joe Shaw

`leaf` is licensed under the MIT License.  See the LICENSE file
for details.
