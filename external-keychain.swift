import Foundation
import Security

func fail(_ code: Int32) -> Never {
    FileHandle.standardError.write(Data("Keychain operation failed (\(code)).\n".utf8))
    exit(1)
}

do {
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard let request = try JSONSerialization.jsonObject(with: input) as? [String: String],
          let action = request["action"], let account = request["account"] else { fail(-50) }
    let native = action == "provide-native"
    guard !native || account == "antigravity" else { fail(-50) }
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: native ? "gemini" : "Antigravity External Login",
        kSecAttrAccount as String: account,
        kSecAttrSynchronizable as String: false
    ]
    if action == "save" || native {
        guard let value = request["value"] else { fail(-50) }
        let attributes: [String: Any] = [kSecValueData as String: Data(value.utf8)]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = Data(value.utf8)
            item[kSecAttrLabel as String] = "Antigravity external login (local)"
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else { fail(status) }
        print("saved")
    } else if action == "load" {
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        guard status == errSecSuccess, let value = result as? Data else { fail(status) }
        FileHandle.standardOutput.write(value)
    } else { fail(-50) }
} catch { fail(-50) }
