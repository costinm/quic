package crypto

import (
	"github.com/costinm/quic/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NullAEAD", func() {
	It("selects the right FVN variant", func() {
		connID := protocol.ConnectionID(0x42)
		Expect(NewNullAEAD(protocol.PerspectiveClient, connID, protocol.Version39)).To(Equal(&nullAEADFNV128a{
			perspective: protocol.PerspectiveClient,
		}))
		Expect(NewNullAEAD(protocol.PerspectiveClient, connID, protocol.VersionTLS)).To(BeAssignableToTypeOf(&aeadAESGCM{}))
	})
})
