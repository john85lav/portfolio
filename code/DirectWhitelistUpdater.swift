//
//  DirectWhitelistUpdater.swift — фрагмент из JenxyVPN (iOS), см. cases/01
//
//  Приложение раз в сутки скачивает список сетей российских сервисов, которые
//  VPN-туннель пропускает мимо себя. Список берётся из чужого открытого проекта,
//  поэтому ему не доверяем: файл принимается, только если SHA-256 совпадает
//  с манифестом релиза и содержимое проходит проверку (DirectWhitelist.validatedServiceRanges:
//  100–2000 сетей, ни одной крупнее /12). Иначе используется снимок из сборки.
//  Источник — github.com/kyoresuas/ru-direct (MIT), уровень ru-standard.
//

import CryptoKit
import Foundation
import UIKit

final class DirectWhitelistUpdater {

    static let shared = DirectWhitelistUpdater()

    static let releaseURL = URL(string: "https://github.com/kyoresuas/ru-direct/releases/latest/download/")!
    static let manifestName = "manifest.json"
    static let listName = "ru-standard.ipv4.txt"

    /// Успешная проверка — раз в сутки; после ошибки пробуем через час.
    static let checkInterval: TimeInterval = 24 * 60 * 60
    static let retryInterval: TimeInterval = 60 * 60

    private let lastCheckKey = "direct_whitelist_last_check"
    private let lastAttemptKey = "direct_whitelist_last_attempt"
    private let defaults = UserDefaults.standard
    private let session: URLSession
    private var inFlight = false
    private var activeObserver: NSObjectProtocol?

    init(session: URLSession = URLSession(configuration: .ephemeral)) {
        self.session = session
    }

    // MARK: - Public

    /// Проверяет сразу и при каждом возврате приложения на экран. Смена scenePhase
    /// при запуске не приходит (приложение сразу активно), поэтому подписка на уведомление.
    func start() {
        // Юнит-тесты запускают приложение-хост: сеть и запись в App Group им не нужны.
        guard activeObserver == nil,
              ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil else { return }
        activeObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            self?.updateIfNeeded()
        }
        let lastCheck = defaults.object(forKey: lastCheckKey) as? Date
        let lastAttempt = defaults.object(forKey: lastAttemptKey) as? Date
        if !Self.isDue(now: Date(), lastCheck: lastCheck, lastAttempt: lastAttempt) {
            // Один раз при запуске, чтобы по логу было видно, почему загрузки не было.
            Logger.shared.vpn("Whitelist update not due: last success \(lastCheck.map { "\($0)" } ?? "never"), last failure \(lastAttempt.map { "\($0)" } ?? "never")")
        }
        updateIfNeeded()
    }

    func updateIfNeeded(now: Date = Date()) {
        DispatchQueue.main.async {
            guard !self.inFlight, Self.isDue(now: now,
                                             lastCheck: self.defaults.object(forKey: self.lastCheckKey) as? Date,
                                             lastAttempt: self.defaults.object(forKey: self.lastAttemptKey) as? Date) else { return }
            self.inFlight = true
            // Если приложение уйдёт в фон, iOS даст загрузке закончиться (два файла по десятку КБ).
            var backgroundTask = UIBackgroundTaskIdentifier.invalid
            backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "DirectWhitelistUpdate") {
                UIApplication.shared.endBackgroundTask(backgroundTask)
                backgroundTask = .invalid
            }
            self.download { result in
                DispatchQueue.main.async {
                    self.inFlight = false
                    // Время попытки пишем только по итогу: прерванная загрузка не откладывает следующую.
                    switch result {
                    case .success(let count):
                        self.defaults.set(Date(), forKey: self.lastCheckKey)
                        Logger.shared.vpn("Whitelist update: \(count) ranges saved from ru-direct")
                    case .failure(let error):
                        self.defaults.set(Date(), forKey: self.lastAttemptKey)
                        Logger.shared.warning("Whitelist update failed: \(error.description)", category: .vpn)
                    }
                    if backgroundTask != .invalid {
                        UIApplication.shared.endBackgroundTask(backgroundTask)
                        backgroundTask = .invalid
                    }
                }
            }
        }
    }

    static func isDue(now: Date, lastCheck: Date?, lastAttempt: Date?) -> Bool {
        if let lastCheck = lastCheck, now.timeIntervalSince(lastCheck) < checkInterval { return false }
        if let lastAttempt = lastAttempt, now.timeIntervalSince(lastAttempt) < retryInterval { return false }
        return true
    }

    // MARK: - Download

    enum UpdateError: Error {
        case network(String)
        case noHashInManifest
        case hashMismatch
        case invalidList
        case noContainer
        case write(String)

        var description: String {
            switch self {
            case .network(let text): return "network: \(text)"
            case .noHashInManifest: return "\(DirectWhitelistUpdater.listName) not found in manifest"
            case .hashMismatch: return "SHA-256 does not match manifest"
            case .invalidList: return "list rejected by validation"
            case .noContainer: return "App Group container unavailable"
            case .write(let text): return "write: \(text)"
            }
        }
    }

    private func download(completion: @escaping (Result<Int, UpdateError>) -> Void) {
        fetch(Self.manifestName) { manifestResult in
            switch manifestResult {
            case .failure(let error):
                completion(.failure(error))
            case .success(let manifest):
                guard let expected = Self.sha256(ofFile: Self.listName, inManifest: manifest) else {
                    completion(.failure(.noHashInManifest))
                    return
                }
                self.fetch(Self.listName) { listResult in
                    completion(listResult.flatMap { Self.store(list: $0, expectedSHA256: expected) })
                }
            }
        }
    }

    private func fetch(_ name: String, completion: @escaping (Result<Data, UpdateError>) -> Void) {
        var request = URLRequest(url: Self.releaseURL.appendingPathComponent(name), timeoutInterval: 30)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        session.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(.network(error.localizedDescription)))
                return
            }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            guard status == 200, let data = data else {
                completion(.failure(.network("\(name): HTTP \(status)")))
                return
            }
            completion(.success(data))
        }.resume()
    }

    /// Проверяет файл и сохраняет его в App Group; возвращает число диапазонов.
    static func store(list: Data, expectedSHA256: String,
                      containerURL: URL? = FileManager.default.containerURL(
                        forSecurityApplicationGroupIdentifier: TunnelSharedState.appGroupID)) -> Result<Int, UpdateError> {
        guard sha256Hex(list) == expectedSHA256.lowercased() else { return .failure(.hashMismatch) }
        guard let text = String(data: list, encoding: .utf8),
              let ranges = DirectWhitelist.validatedServiceRanges(text) else { return .failure(.invalidList) }
        guard let containerURL = containerURL else { return .failure(.noContainer) }
        do {
            try list.write(to: containerURL.appendingPathComponent(DirectWhitelist.downloadedRangesFileName), options: .atomic)
        } catch {
            return .failure(.write(error.localizedDescription))
        }
        return .success(ranges.count)
    }

    // MARK: - Manifest

    /// SHA-256 файла из manifest.json: `tiers.<уровень>.files[] {name, sha256}`.
    static func sha256(ofFile name: String, inManifest data: Data) -> String? {
        guard let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tiers = manifest["tiers"] as? [String: Any] else { return nil }
        for case let tier as [String: Any] in tiers.values {
            for case let file as [String: Any] in tier["files"] as? [Any] ?? [] where file["name"] as? String == name {
                if let hash = file["sha256"] as? String, hash.count == 64 { return hash.lowercased() }
            }
        }
        return nil
    }

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
