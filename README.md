# authz

A lightweight static authorization framework in Go.

[![Go Report Card](https://goreportcard.com/badge/github.com/adrianosela/authz)](https://goreportcard.com/report/github.com/adrianosela/authz)
[![Documentation](https://godoc.org/github.com/adrianosela/authz?status.svg)](https://godoc.org/github.com/adrianosela/authz)
[![GitHub issues](https://img.shields.io/github/issues/adrianosela/authz.svg)](https://github.com/adrianosela/authz/issues)
[![license](https://img.shields.io/github/license/adrianosela/authz.svg)](https://github.com/adrianosela/authz/blob/master/LICENSE)

Essentially:
- you define `role`s and `resource`s in a yaml file
- at start-up, the yaml file gets compiled onto a structure that can be queried (i.e. ` Authorize(user string, groups []string, resource string, permission string) bool`) with O(n) for n group memberships
- the structure is cached as json in the file system, S3, or other storage as to avoid re-processing the policy on the next run of the app. The json includes a field for the hash of the original policy to detect whether re-processing is necessary
- the policy need not be processed by the actual application itself -- the json cache can be generated separately and have the application always consume a pre-compiled/cached file.

### Usage:

> 🚧 🚧 🚧 TODO 🚧 🚧 🚧

Meanwhile, see the [`./example`](https://github.com/adrianosela/authz/tree/main/example) directory. There you fill find:
- a [sample policy](https://github.com/adrianosela/authz/blob/main/example/policy.yaml) and 
- a [sample generated authz json](https://github.com/adrianosela/authz/blob/main/example/.authz.json)
