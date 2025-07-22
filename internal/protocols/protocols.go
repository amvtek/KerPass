package protocols

// ProtocolFSM is the interface implemented by protocol state machines.
// It defines a single method Update which allows changing the inner state of the protocol.
//
// Update process incoming Event and returns a Command that can be executed by an event loop
// or external runtime. The result of the Command shall be passed to Update to continue
// protocol execution...
//
// Update shall not execute any blocking operation directly. It shall instead return Command
// that describes such operations.
type ProtocolFSM interface {
	Update(evt Event) (cmd Command, err error)
}

// Protocol is an alias of the ProtocolFSM type.
type Protocol = ProtocolFSM

// T is an alias of the ProtocolFSM type.
type T = ProtocolFSM
