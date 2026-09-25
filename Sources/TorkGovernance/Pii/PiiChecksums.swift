import Foundation

/// Check digits for the country registry.
///
/// The SDK bundle NAMES twenty algorithms and gives weights and a modulus for
/// the eleven that reduce to them; the other nine are marked `kind: "custom"`
/// and carry no specification, so they are ported here by hand from the cloud's
/// `lib/pii/checksums.ts` -- the single implementation the cloud and the
/// country corpus both use. Keeping the arithmetic identical is what makes a
/// receipt block from this SDK byte-identical to one from the JavaScript SDK.
///
/// Every function is pure: a String in, a Bool out. No I/O, no clock.
public enum PiiChecksums {

    private static func digitsOf(_ s: String) -> [UInt8] {
        s.utf8.filter { $0 >= 48 && $0 <= 57 }
    }

    /// Remainder of a long decimal digit string modulo `m`, digit by digit.
    private static func modDigits(_ digits: ArraySlice<UInt8>, _ m: Int) -> Int {
        var r = 0
        for ch in digits { r = (r * 10 + Int(ch - 48)) % m }
        return r
    }

    private static func allSameDigit(_ d: [UInt8]) -> Bool {
        guard let first = d.first else { return false }
        return d.allSatisfy { $0 == first }
    }

    private static func strippedUpper(_ s: String) -> [UInt8] {
        Array(s.replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\t", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .uppercased()
            .utf8)
    }

    /// Luhn / ISO-IEC 7812-1 mod-10.
    public static func luhn(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count >= 2 else { return false }
        var sum = 0
        var dbl = false
        for ch in d.reversed() {
            var n = Int(ch - 48)
            if dbl {
                n *= 2
                if n > 9 { n -= 9 }
            }
            sum += n
            dbl.toggle()
        }
        return sum % 10 == 0
    }

    private static let verhoeffMul: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]

    private static let verhoeffPerm: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]

    /// Verhoeff, the Aadhaar check digit (UIDAI Circular No. 1 of 2018).
    public static func verhoeff(_ input: String) -> Bool {
        let d = digitsOf(input)
        var c = 0
        for (i, ch) in d.reversed().enumerated() {
            c = verhoeffMul[c][verhoeffPerm[i % 8][Int(ch - 48)]]
        }
        return c == 0
    }

    /// Australian TFN (ATO): weights 1,4,3,7,5,8,6,9,10, sum mod 11 == 0.
    public static func auTfn(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count == 9 else { return false }
        let w = [1, 4, 3, 7, 5, 8, 6, 9, 10]
        let sum = (0..<9).reduce(0) { $0 + Int(d[$1] - 48) * w[$1] }
        return sum % 11 == 0
    }

    /// Australian ABN (ABR): subtract 1 from the first digit, weights 10,1,3..19, mod 89.
    public static func auAbn(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count == 11 else { return false }
        let w = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
        var sum = (Int(d[0] - 48) - 1) * w[0]
        for i in 1..<11 { sum += Int(d[i] - 48) * w[i] }
        return sum % 89 == 0
    }

    /// Australian Medicare card number (Services Australia).
    public static func auMedicare(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count >= 10 else { return false }
        guard "23456".utf8.contains(d[0]) else { return false }
        let w = [1, 3, 7, 9, 1, 3, 7, 9]
        let sum = (0..<8).reduce(0) { $0 + Int(d[$1] - 48) * w[$1] }
        return sum % 10 == Int(d[8] - 48)
    }

    /// UK NHS number (NHS Data Model and Dictionary): weights 10..2, check = 11 - (sum mod 11).
    public static func ukNhs(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count == 10 else { return false }
        let sum = (0..<9).reduce(0) { $0 + Int(d[$1] - 48) * (10 - $1) }
        var check = 11 - (sum % 11)
        if check == 11 { check = 0 }
        if check == 10 { return false }
        return check == Int(d[9] - 48)
    }

    /// Brazil CPF (Receita Federal): two sequential mod-11 check digits.
    public static func brCpf(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count == 11, !allSameDigit(d) else { return false }
        func calc(_ len: Int) -> Int {
            let sum = (0..<len).reduce(0) { $0 + Int(d[$1] - 48) * (len + 1 - $1) }
            let r = (sum * 10) % 11
            return r == 10 ? 0 : r
        }
        return calc(9) == Int(d[9] - 48) && calc(10) == Int(d[10] - 48)
    }

    /// Brazil CNPJ (Receita Federal): two mod-11 check digits with different weight vectors.
    public static func brCnpj(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count == 14, !allSameDigit(d) else { return false }
        func calc(_ weights: [Int]) -> Int {
            let sum = weights.indices.reduce(0) { $0 + Int(d[$1] - 48) * weights[$1] }
            let r = sum % 11
            return r < 2 ? 0 : 11 - r
        }
        return calc([5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == Int(d[12] - 48)
            && calc([6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == Int(d[13] - 48)
    }

    /// Japan My Number (MIC Ordinance No. 85 of 2014).
    public static func jpMyNumber(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count == 12 else { return false }
        var sum = 0
        for n in 1...11 {
            let p = Int(d[11 - n] - 48)
            let q = n <= 6 ? n + 1 : n - 5
            sum += p * q
        }
        let r = sum % 11
        let check = r <= 1 ? 0 : 11 - r
        return check == Int(d[11] - 48)
    }

    /// China resident ID (GB 11643-1999): ISO 7064 MOD 11-2, check character may be X.
    public static func cnResidentId(_ input: String) -> Bool {
        let s = strippedUpper(input)
        guard s.count == 18 else { return false }
        guard s[0..<17].allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return false }
        let last = s[17]
        guard (last >= 48 && last <= 57) || last == UInt8(ascii: "X") else { return false }
        let w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        let sum = (0..<17).reduce(0) { $0 + Int(s[$1] - 48) * w[$1] }
        return Array("10X98765432".utf8)[sum % 11] == last
    }

    /// Korea RRN, for numbers issued before 20 Oct 2020.
    ///
    /// ADVISORY ONLY, never a gate: numbers issued from 20 Oct 2020 are
    /// randomly assigned and carry no check digit.
    public static func krRrn(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count == 13 else { return false }
        let w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
        let sum = (0..<12).reduce(0) { $0 + Int(d[$1] - 48) * w[$1] }
        return (11 - (sum % 11)) % 10 == Int(d[12] - 48)
    }

    /// Singapore NRIC/FIN (ICA): weights 2,7,6,5,4,3,2 and a prefix-dependent letter table.
    public static func sgNric(_ input: String) -> Bool {
        let s = strippedUpper(input)
        guard s.count == 9 else { return false }
        guard "STFGM".utf8.contains(s[0]) else { return false }
        guard s[1..<8].allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return false }
        guard s[8] >= UInt8(ascii: "A") && s[8] <= UInt8(ascii: "Z") else { return false }
        let w = [2, 7, 6, 5, 4, 3, 2]
        var sum = (0..<7).reduce(0) { $0 + Int(s[1 + $1] - 48) * w[$1] }
        let prefix = Character(UnicodeScalar(s[0]))
        if prefix == "T" || prefix == "G" { sum += 4 }
        if prefix == "M" { sum += 3 }
        let table: String
        if prefix == "S" || prefix == "T" { table = "JZIHGFEDCBA" }
        else if prefix == "M" { table = "KLJNPQRTUWX" }
        else { table = "XWUTRQPNMLK" }
        return Array(table.utf8)[sum % 11] == s[8]
    }

    private static let cfOdd: [UInt8: Int] = {
        var m: [UInt8: Int] = [:]
        let digitValues = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21]
        for (i, c) in "0123456789".utf8.enumerated() { m[c] = digitValues[i] }
        let letterValues = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18,
                            20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23]
        for (i, c) in "ABCDEFGHIJKLMNOPQRSTUVWXYZ".utf8.enumerated() { m[c] = letterValues[i] }
        return m
    }()

    /// Italy codice fiscale (Agenzia delle Entrate): odd/even tables, mod 26, check letter.
    public static func itCodiceFiscale(_ input: String) -> Bool {
        let s = strippedUpper(input)
        guard s.count == 16 else { return false }
        func isUpper(_ b: UInt8) -> Bool { b >= 65 && b <= 90 }
        func isDigit(_ b: UInt8) -> Bool { b >= 48 && b <= 57 }
        guard s[0..<6].allSatisfy(isUpper),
              s[6..<8].allSatisfy(isDigit),
              isUpper(s[8]),
              s[9..<11].allSatisfy(isDigit),
              isUpper(s[11]),
              s[12..<15].allSatisfy(isDigit),
              isUpper(s[15]) else { return false }
        var sum = 0
        for i in 0..<15 {
            let c = s[i]
            if i % 2 == 0 { sum += cfOdd[c] ?? 0 }
            else if isDigit(c) { sum += Int(c - 48) }
            else { sum += Int(c - 65) }
        }
        return UInt8(65 + (sum % 26)) == s[15]
    }

    /// France NIR (Insee): 97-complement, Corsican 2A/2B mapped to 19/18 first.
    public static func frNir(_ input: String) -> Bool {
        var s = String(decoding: strippedUpper(input), as: UTF8.self)
        guard s.count == 15 else { return false }
        let bytes = Array(s.utf8)
        guard bytes[0] == UInt8(ascii: "1") || bytes[0] == UInt8(ascii: "2") else { return false }
        let dept = String(decoding: bytes[5..<7], as: UTF8.self)
        func isDigit(_ b: UInt8) -> Bool { b >= 48 && b <= 57 }
        guard bytes[1..<5].allSatisfy(isDigit),
              bytes[5..<7].allSatisfy(isDigit) || dept == "2A" || dept == "2B",
              bytes[7..<15].allSatisfy(isDigit) else { return false }
        if let r = s.range(of: "2A") { s.replaceSubrange(r, with: "19") }
        if let r = s.range(of: "2B") { s.replaceSubrange(r, with: "18") }
        let all = Array(s.utf8)
        let key = Int(String(decoding: all[13..<15], as: UTF8.self)) ?? -1
        return 97 - modDigits(all[0..<13], 97) == key
    }

    /// Germany Steuer-IdNr (BZSt): ISO 7064 MOD 11,10 over 10 digits.
    public static func deSteuerId(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count == 11, d[0] != UInt8(ascii: "0") else { return false }
        var product = 10
        for i in 0..<10 {
            var sum = (Int(d[i] - 48) + product) % 10
            if sum == 0 { sum = 10 }
            product = (sum * 2) % 11
        }
        var check = 11 - product
        if check == 10 { check = 0 }
        return check == Int(d[10] - 48)
    }

    /// Thailand national ID (DOPA): weights 13..2, check = (11 - sum mod 11) mod 10.
    public static func thNationalId(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count == 13 else { return false }
        let sum = (0..<12).reduce(0) { $0 + Int(d[$1] - 48) * (13 - $1) }
        return (11 - (sum % 11)) % 10 == Int(d[12] - 48)
    }

    /// Canada SIN (Service Canada): Luhn over 9 digits. Advisory -- community-sourced.
    public static func caSin(_ input: String) -> Bool {
        digitsOf(input).count == 9 && luhn(input)
    }

    /// South Africa ID (SARS PAYE BRS Appendix B 8.3): Luhn over 13 digits.
    public static func zaId(_ input: String) -> Bool {
        digitsOf(input).count == 13 && luhn(input)
    }

    /// UAE Emirates ID (ICP): Luhn over 15 digits starting 784. Advisory.
    public static func aeEmiratesId(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count == 15 else { return false }
        let s = String(decoding: d, as: UTF8.self)
        return s.hasPrefix("784") && luhn(s)
    }

    /// Saudi national ID / iqama: Luhn over 10 digits starting 1 or 2. Advisory.
    public static func saNationalId(_ input: String) -> Bool {
        let d = digitsOf(input)
        guard d.count == 10 else { return false }
        guard d[0] == UInt8(ascii: "1") || d[0] == UInt8(ascii: "2") else { return false }
        return luhn(String(decoding: d, as: UTF8.self))
    }

    /// Keyed by the bundle's `checksum` field.
    ///
    /// Every value is a static function over immutable tables, so this is safe
    /// to read from any thread; it is not typed `@Sendable` because a reference
    /// to a static method is not itself a Sendable function value in Swift 6's
    /// strict-concurrency checking.
    public static let functions: [String: (String) -> Bool] = [
        "luhn": luhn,
        "verhoeff": verhoeff,
        "au_tfn": auTfn,
        "au_abn": auAbn,
        "au_medicare": auMedicare,
        "uk_nhs": ukNhs,
        "br_cpf": brCpf,
        "br_cnpj": brCnpj,
        "jp_my_number": jpMyNumber,
        "cn_resident_id": cnResidentId,
        "kr_rrn": krRrn,
        "sg_nric": sgNric,
        "it_codice_fiscale": itCodiceFiscale,
        "fr_nir": frNir,
        "de_steuer_id": deSteuerId,
        "th_national_id": thNationalId,
        "ca_sin": caSin,
        "za_id": zaId,
        "ae_emirates_id": aeEmiratesId,
        "sa_national_id": saNationalId,
    ]
}
