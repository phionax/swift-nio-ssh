//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import XCTest

@testable import NIOSSH

final class NIOSSHSignatureTests: XCTestCase {
    /// Builds the wire representation of an ECDSA signature with attacker-chosen `r` and `s` values.
    ///
    /// Format is `string signature-identifier` followed by `string(mpint r || mpint s)`, matching what
    /// `readECDSAP*Signature()` expects.
    private func ecdsaSignatureBuffer(identifier: String, r: [UInt8], s: [UInt8]) -> ByteBuffer {
        var inner = ByteBufferAllocator().buffer(capacity: r.count + s.count + 8)
        inner.writeSSHString(r)
        inner.writeSSHString(s)

        var buffer = ByteBufferAllocator().buffer(capacity: inner.readableBytes + identifier.utf8.count + 8)
        buffer.writeSSHString(Array(identifier.utf8))
        buffer.writeSSHString(&inner)
        return buffer
    }

    func testOversizedECDSARComponentIsRejected() throws {
        // `r` is far wider than the P-256 point size (32 bytes). Leading byte is non-zero so `mpIntView`
        // does not strip it, keeping the length oversized.
        var buffer = self.ecdsaSignatureBuffer(
            identifier: "ecdsa-sha2-nistp256",
            r: Array(repeating: 0x01, count: 4096),
            s: Array(repeating: 0x02, count: 32)
        )

        XCTAssertThrowsError(try buffer.readSSHSignature()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testOversizedECDSASComponentIsRejected() throws {
        var buffer = self.ecdsaSignatureBuffer(
            identifier: "ecdsa-sha2-nistp256",
            r: Array(repeating: 0x01, count: 32),
            s: Array(repeating: 0x02, count: 4096)
        )

        XCTAssertThrowsError(try buffer.readSSHSignature()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    /// Positive boundary: a full-width `r`/`s` (exactly the curve point size) and the classic
    /// 33-byte mpint with a leading zero sign byte must both still parse. The guard added for
    /// GHSA-998x-vgvp-xwpc must not reject legitimate signatures.
    func testFullWidthAndSignPaddedComponentsAreAccepted() throws {
        let priv = NIOSSHPrivateKey(p256Key: .init())
        var signed = ByteBufferAllocator().buffer(capacity: 256)
        // Sign until we produce an r or s whose mpint encoding carries the 0x00 sign byte, so the
        // padded form is exercised as well as the plain full-width form.
        for _ in 0..<64 {
            var buffer = ByteBufferAllocator().buffer(capacity: 256)
            let signature = try priv.sign(digest: SHA256.hash(data: Array("hello".utf8)))
            buffer.writeSSHSignature(signature)
            signed = buffer
            XCTAssertNotNil(try signed.readSSHSignature())
        }
    }
}
