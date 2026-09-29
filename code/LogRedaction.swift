//
//  LogRedaction.swift — фрагмент из JenxyVPN (iOS/macOS)
//
//  Журнал диагностики общий для приложения и трёх VPN-расширений, и пользователь
//  пересылает его в мессенджер. Поэтому секреты вырезаются ДО записи в файл,
//  а не при показе: в файле их просто нет.
//
//  Что прячется:
//  - awg://… целиком: секретны и приватный ключ, и параметры обфускации;
//  - строки PrivateKey / PresharedKey / HeaderProtectionKey из wg-quick-конфига;
//  - UUID пользователя VLESS (остаются первые 4 символа — чтобы отличать ключи);
//  - публичный ключ Reality (тоже 4 символа);
//  - пароль и метод из ss://.
//
//  Ссылка вида awg://keychain@host:port — безопасная (секрет лежит в Keychain),
//  её оставляем: по ней видно, какой сервер использовался.
//

import Foundation

enum LogRedaction {

    private static let uuidRegex = try! NSRegularExpression(
        pattern: "\\b([0-9a-fA-F]{4})[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b"
    )
    private static let pbkRegex = try! NSRegularExpression(
        pattern: "(pbk=|publicKey[\"':= ]+)([A-Za-z0-9_\\-]{4})[A-Za-z0-9_\\-]+"
    )
    private static let ssRegex = try! NSRegularExpression(pattern: "\\bss://[^@\\s]+@")
    private static let awgRegex = try! NSRegularExpression(pattern: "(?i)\\bawg://(?!keychain@)\\S+")
    private static let wgSecretLineRegex = try! NSRegularExpression(
        pattern: "(?im)^(\\s*(?:PrivateKey|PresharedKey|HeaderProtectionKey)\\s*=\\s*)\\S+"
    )

    static func redact(_ text: String) -> String {
        var result = text
        result = replace(awgRegex, in: result, with: "awg://***")
        result = replace(wgSecretLineRegex, in: result, with: "$1***")
        result = replace(uuidRegex, in: result, with: "$1…")
        result = replace(pbkRegex, in: result, with: "$1$2…")
        result = replace(ssRegex, in: result, with: "ss://***@")
        return result
    }

    private static func replace(_ regex: NSRegularExpression, in text: String, with template: String) -> String {
        let range = NSRange(text.startIndex..., in: text)
        return regex.stringByReplacingMatches(in: text, range: range, withTemplate: template)
    }
}

// Пример строки в журнале:
//   vless://a1b2…@example.org:443?encryption=none&type=ws#Server
//   awg://***
//   PrivateKey = ***
