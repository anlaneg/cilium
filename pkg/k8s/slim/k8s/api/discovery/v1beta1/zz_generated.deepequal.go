//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by main. DO NOT EDIT.

package v1beta1

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *Endpoint) DeepEqual(other *Endpoint) bool {
	if other == nil {
		return false
	}

	if ((in.Addresses != nil) && (other.Addresses != nil)) || ((in.Addresses == nil) != (other.Addresses == nil)) {
		in, other := &in.Addresses, &other.Addresses
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	if !in.Conditions.DeepEqual(&other.Conditions) {
		return false
	}

	if ((in.Topology != nil) && (other.Topology != nil)) || ((in.Topology == nil) != (other.Topology == nil)) {
		in, other := &in.Topology, &other.Topology
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for key, inValue := range *in {
				if otherValue, present := (*other)[key]; !present {
					return false
				} else {
					if inValue != otherValue {
						return false
					}
				}
			}
		}
	}

	if (in.NodeName == nil) != (other.NodeName == nil) {
		return false
	} else if in.NodeName != nil {
		if *in.NodeName != *other.NodeName {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *EndpointConditions) DeepEqual(other *EndpointConditions) bool {
	if other == nil {
		return false
	}

	if (in.Ready == nil) != (other.Ready == nil) {
		return false
	} else if in.Ready != nil {
		if *in.Ready != *other.Ready {
			return false
		}
	}

	if (in.Serving == nil) != (other.Serving == nil) {
		return false
	} else if in.Serving != nil {
		if *in.Serving != *other.Serving {
			return false
		}
	}

	if (in.Terminating == nil) != (other.Terminating == nil) {
		return false
	} else if in.Terminating != nil {
		if *in.Terminating != *other.Terminating {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *EndpointPort) DeepEqual(other *EndpointPort) bool {
	if other == nil {
		return false
	}

	if (in.Name == nil) != (other.Name == nil) {
		return false
	} else if in.Name != nil {
		if *in.Name != *other.Name {
			return false
		}
	}

	if (in.Protocol == nil) != (other.Protocol == nil) {
		return false
	} else if in.Protocol != nil {
		if *in.Protocol != *other.Protocol {
			return false
		}
	}

	if (in.Port == nil) != (other.Port == nil) {
		return false
	} else if in.Port != nil {
		if *in.Port != *other.Port {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *EndpointSlice) DeepEqual(other *EndpointSlice) bool {
	if other == nil {
		return false
	}

	if in.TypeMeta != other.TypeMeta {
		return false
	}

	if !in.ObjectMeta.DeepEqual(&other.ObjectMeta) {
		return false
	}

	if in.AddressType != other.AddressType {
		return false
	}
	if ((in.Endpoints != nil) && (other.Endpoints != nil)) || ((in.Endpoints == nil) != (other.Endpoints == nil)) {
		in, other := &in.Endpoints, &other.Endpoints
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	if ((in.Ports != nil) && (other.Ports != nil)) || ((in.Ports == nil) != (other.Ports == nil)) {
		in, other := &in.Ports, &other.Ports
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *EndpointSliceList) DeepEqual(other *EndpointSliceList) bool {
	if other == nil {
		return false
	}

	if in.TypeMeta != other.TypeMeta {
		return false
	}

	if !in.ListMeta.DeepEqual(&other.ListMeta) {
		return false
	}

	if ((in.Items != nil) && (other.Items != nil)) || ((in.Items == nil) != (other.Items == nil)) {
		in, other := &in.Items, &other.Items
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}
