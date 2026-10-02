//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
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
@testable import NIOSSH
import XCTest

final class SSHPacketParserTests: XCTestCase {
    /// Feed the SSH version to a packet parser and verify the output.
    ///
    /// Usually used to set up an appropriate state.
    private func feedVersion(to parser: inout SSHPacketParser, file: StaticString = #filePath, line: UInt = #line) {
        var version = ByteBuffer.of(string: "SSH-2.0-OpenSSH_7.9\r\n")
        parser.append(bytes: &version)

        var packet: SSHMessage?
        XCTAssertNoThrow(packet = try parser.nextPacket(), file: file, line: line)

        switch packet {
        case .some(.version(let string)):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.9", file: file, line: line)
        default:
            XCTFail("Expecting .version", file: file, line: line)
        }
    }

    func testReadVersion() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "SSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.9\r\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.9")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithExtraLines() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xxxx\r\nyyyy\r\nSSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.9\r\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.9")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithoutCarriageReturn() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "SSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.4\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.4")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithExtraLinesWithoutCarriageReturn() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xxxx\nyyyy\nSSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.4\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.4")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithPrecedingBannerLines() throws {
        // RFC 4253 section 4.2: the server MAY send other lines before the version
        // string. The parsed version string must be only the version line: preceding
        // banner lines must not leak into the version exchanged in the key exchange
        // hash (phionax/moterm#74).
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())

        var bannerAndVersion = ByteBuffer.of(string: "Use of this network is not authorized.\r\nSSH-2.0-OpenSSH_8.2\r\n")
        parser.append(bytes: &bannerAndVersion)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_8.2")
        default:
            XCTFail("Expecting .version")
        }

        // Consumption boundary: the reader must have consumed the banner and the
        // version line together, through the version line's \n. A following binary
        // packet must parse from the next byte; banner residue would otherwise be
        // misread as a packet length.
        var serviceRequest = ByteBuffer.of(bytes: [0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207])
        parser.append(bytes: &serviceRequest)

        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
    }

    func testBinaryInParts() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        var part1 = ByteBuffer.of(bytes: [0, 0, 0])
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(bytes: [28])
        parser.append(bytes: &part2)

        XCTAssertNil(try parser.nextPacket())
        var part3 = ByteBuffer.of(bytes: [10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97])
        parser.append(bytes: &part3)
        XCTAssertNil(try parser.nextPacket())

        var part4 = ByteBuffer.of(bytes: [117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207])
        parser.append(bytes: &part4)

        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
    }

    func testBinaryFull() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        var part1 = ByteBuffer.of(bytes: [0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207])
        parser.append(bytes: &part1)

        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
    }

    func testBinaryTwoMessages() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        var part = ByteBuffer.of(bytes: [0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207, 0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207])
        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
    }

    func testWeReclaimStorage() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)
        XCTAssertNoThrow(try parser.nextPacket())

        let part = ByteBuffer.of(bytes: [0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207])

        let neededParts = 2048 / part.readableBytes

        for _ in 0 ..< neededParts {
            var partCopy = part
            parser.append(bytes: &partCopy)
        }

        // The version field is in the buffer, and we can't really prevent it being there.
        let startingOffset = parser._discardableBytes
        for i in 0 ..< (neededParts / 2) {
            XCTAssertEqual(parser._discardableBytes, (i * part.readableBytes) + startingOffset)
            XCTAssertNoThrow(try parser.nextPacket())
        }

        // Now we should have cleared up.
        XCTAssertEqual(parser._discardableBytes, 0)
    }

    func testMaximumPacketSizeInVersion() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator(), maximumPacketSize: 1 << 15)
        let longVersionString = String(repeating: "z", count: SSHPacketParser.maximumAllowedVersionSize + 256)
        var version = ByteBuffer.of(string: longVersionString + "\r\n")
        parser.append(bytes: &version)

        XCTAssertThrowsError(try parser.nextPacket())
    }
}

public extension ByteBuffer {
    static func of(string: String) -> ByteBuffer {
        var buffer = ByteBufferAllocator().buffer(capacity: string.count)
        buffer.writeString(string)
        return buffer
    }

    static func of(bytes: [UInt8]) -> ByteBuffer {
        var buffer = ByteBufferAllocator().buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        return buffer
    }
}


extension SSHPacketParserTests {
    private var gcmSchemes: [(NIOSSHTransportProtection.Type, SymmetricKeySize)] {
        [(AES128GCMOpenSSHTransportProtection.self, .bits128),
         (AES256GCMOpenSSHTransportProtection.self, .bits256)]
    }

    private func parserWithGCM(_ scheme: NIOSSHTransportProtection.Type,
                               keySize: SymmetricKeySize) throws -> (SSHPacketParser, NIOSSHTransportProtection) {
        let keys = NIOSSHSessionKeys(initialInboundIV: .init(randomBytes: 12),
                                    initialOutboundIV: .init(randomBytes: 12),
                                    inboundEncryptionKey: SymmetricKey(size: keySize),
                                    outboundEncryptionKey: SymmetricKey(size: keySize),
                                    inboundMACKey: SymmetricKey(size: .bits128),
                                    outboundMACKey: SymmetricKey(size: .bits128))
        let encryptor = try scheme.init(initialKeys: keys, mac: nil)
        let decryptor = try scheme.init(initialKeys: keys.inverted, mac: nil)
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)
        parser.addEncryption(decryptor)
        return (parser, encryptor)
    }

    func testGCMRejectsOverflowingUnauthenticatedLengths() throws {
        for (scheme, keySize) in self.gcmSchemes {
            for length in [UInt32.max, UInt32.max - 15] {
                var (parser, _) = try self.parserWithGCM(scheme, keySize: keySize)
                var header = ByteBufferAllocator().buffer(capacity: 16)
                header.writeInteger(length)
                header.writeRepeatingByte(0, count: 12)
                parser.append(bytes: &header)
                XCTAssertThrowsError(try parser.nextPacket()) { error in
                    XCTAssertEqual((error as? NIOSSHError)?.type, .invalidEncryptedPacketLength)
                }
            }
        }
    }

    func testGCMRejectsEqualAndExcessiveTotalLength() throws {
        for (scheme, keySize) in self.gcmSchemes {
            for length: UInt32 in [131056, 131072, 131088] {
                var (parser, _) = try self.parserWithGCM(scheme, keySize: keySize)
                var header = ByteBufferAllocator().buffer(capacity: 16)
                header.writeInteger(length)
                header.writeRepeatingByte(0, count: 12)
                parser.append(bytes: &header)
                XCTAssertThrowsError(try parser.nextPacket()) { error in
                    XCTAssertEqual((error as? NIOSSHError)?.type, .invalidEncryptedPacketLength)
                }
            }
        }
    }

    func testGCMOverflowingFragmentedHeaderWaitsThenRejects() throws {
        for (scheme, keySize) in self.gcmSchemes {
            var (parser, _) = try self.parserWithGCM(scheme, keySize: keySize)
            var first = ByteBufferAllocator().buffer(capacity: 15)
            first.writeInteger(UInt32.max)
            first.writeRepeatingByte(0, count: 11)
            parser.append(bytes: &first)
            XCTAssertNil(try parser.nextPacket())
            var last = ByteBufferAllocator().buffer(capacity: 1)
            last.writeInteger(UInt8(0))
            parser.append(bytes: &last)
            XCTAssertThrowsError(try parser.nextPacket()) { error in
                XCTAssertEqual((error as? NIOSSHError)?.type, .invalidEncryptedPacketLength)
            }
        }
    }

    func testGCMMaximumAlignedValidPacketAuthenticatesAndParses() throws {
        for (scheme, keySize) in self.gcmSchemes {
            var (parser, encryptor) = try self.parserWithGCM(scheme, keySize: keySize)
            var data = ByteBufferAllocator().buffer(capacity: 131030)
            data.writeRepeatingByte(42, count: 131030)
            let message = SSHMessage.ignore(.init(data: data))
            var packet = ByteBufferAllocator().buffer(capacity: 131060)
            try encryptor.encryptPacket(.init(message: message), to: &packet, sequenceNumber: 0)
            XCTAssertEqual(packet.getInteger(at: packet.readerIndex, as: UInt32.self), 131040)
            XCTAssertEqual(packet.readableBytes, 131060)
            var first = packet.readSlice(length: 15)!
            parser.append(bytes: &first)
            XCTAssertNil(try parser.nextPacket())
            var next = packet.readSlice(length: 1)!
            parser.append(bytes: &next)
            XCTAssertNil(try parser.nextPacket())
            parser.append(bytes: &packet)
            XCTAssertEqual(try parser.nextPacket(), message)
            XCTAssertNil(try parser.nextPacket())
        }
    }
}
