module SIEM
  class ThreatIntelligence
    def self.analyze_threat(file_path)
      # Análise de ameaças usando nosso próprio sistema + VirusTotal
      file_hash = calculate_file_hash(file_path)
      file_signatures = analyze_file_signatures(file_path)
      behavior_analysis = analyze_file_behavior(file_path)
      virustotal_analysis = scan_with_virustotal(file_hash)

      threat_data = {
        file_hash: file_hash,
        signatures: file_signatures,
        behavior: behavior_analysis,
        virustotal: virustotal_analysis,
        threat_level: calculate_threat_level(file_signatures, behavior_analysis, virustotal_analysis),
        scan_date: Time.now,
        status: 'success'
      }

      # Criar alerta se necessário
      if threat_data[:threat_level] != 'clean'
        create_threat_alert(threat_data)
      end

      threat_data
    end

    private

    def self.calculate_file_hash(file_path)
      require 'digest'
      Digest::SHA256.file(file_path).hexdigest
    end

    def self.analyze_file_signatures(file_path)
      signatures = {
        suspicious_patterns: [],
        known_malware_patterns: [],
        suspicious_headers: []
      }

      # Análise de padrões suspeitos
      File.open(file_path, 'rb') do |file|
        content = file.read(1024) # Ler primeiros 1024 bytes

        # Verificar assinaturas conhecidas de malware
        KNOWN_MALWARE_SIGNATURES.each do |signature|
          if content.include?(signature)
            signatures[:known_malware_patterns] << signature
          end
        end

        # Verificar cabeçalhos suspeitos
        SUSPICIOUS_HEADERS.each do |header|
          if content.include?(header)
            signatures[:suspicious_headers] << header
          end
        end

        # Verificar padrões suspeitos
        SUSPICIOUS_PATTERNS.each do |pattern|
          if content.match?(pattern)
            signatures[:suspicious_patterns] << pattern.to_s
          end
        end
      end

      signatures
    end

    def self.analyze_file_behavior(file_path)
      behavior = {
        suspicious_operations: [],
        network_operations: [],
        system_operations: []
      }

      # Simular execução em ambiente controlado
      begin
        # Verificar extensão do arquivo
        extension = File.extname(file_path).downcase
        if EXECUTABLE_EXTENSIONS.include?(extension)
          behavior[:suspicious_operations] << "Executable file detected"
        end

        # Verificar permissões
        if File.executable?(file_path)
          behavior[:suspicious_operations] << "File has executable permissions"
        end

        # Verificar tamanho
        if File.size(file_path) > MAX_SAFE_FILE_SIZE
          behavior[:suspicious_operations] << "File size exceeds safe limit"
        end

        # Verificar conteúdo do arquivo
        File.open(file_path, 'r') do |file|
          content = file.read

          # Verificar operações de rede suspeitas
          NETWORK_PATTERNS.each do |pattern|
            if content.match?(pattern)
              behavior[:network_operations] << "Suspicious network operation: #{pattern}"
            end
          end

          # Verificar operações de sistema suspeitas
          SYSTEM_PATTERNS.each do |pattern|
            if content.match?(pattern)
              behavior[:system_operations] << "Suspicious system operation: #{pattern}"
            end
          end
        end
      rescue => e
        behavior[:suspicious_operations] << "Error analyzing file: #{e.message}"
      end

      behavior
    end

    def self.scan_with_virustotal(file_hash)
      uri = URI(ENV['THREAT_FEED_VIRUSTOTAL_URL'])
      request = Net::HTTP::Get.new(uri)
      request['X-API-KEY'] = ENV['THREAT_FEED_VIRUSTOTAL_KEY']
      request.set_form_data('resource' => file_hash)

      response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
        http.request(request)
      end

      JSON.parse(response.body)
    rescue => e
      { error: e.message, status: 'error' }
    end

    def self.calculate_threat_level(signatures, behavior, virustotal)
      threat_score = 0

      # Calcular pontuação baseada em assinaturas
      threat_score += signatures[:known_malware_patterns].length * 10
      threat_score += signatures[:suspicious_headers].length * 5
      threat_score += signatures[:suspicious_patterns].length * 3

      # Calcular pontuação baseada em comportamento
      threat_score += behavior[:suspicious_operations].length * 8
      threat_score += behavior[:network_operations].length * 6
      threat_score += behavior[:system_operations].length * 4

      # Adicionar pontuação do VirusTotal se disponível
      if virustotal && virustotal['positives']
        threat_score += virustotal['positives'] * 5
      end

      # Determinar nível de ameaça
      case threat_score
      when 0
        'clean'
      when 1..10
        'low'
      when 11..20
        'medium'
      when 21..30
        'high'
      else
        'critical'
      end
    end

    def self.create_threat_alert(threat_data)
      Alert.create_from_security_log(
        nil,
        'threat_detection',
        threat_data[:threat_level],
        "Threat detected: #{threat_data[:threat_level]} level",
        threat_data
      )
    end

    # Constantes para análise
    KNOWN_MALWARE_SIGNATURES = [
      # Assinaturas conhecidas de malware
      "\x4D\x5A", # Assinatura de arquivo PE
      "\x7F\x45\x4C\x46", # Assinatura de arquivo ELF
      # Adicione mais assinaturas conforme necessário
    ]

    SUSPICIOUS_HEADERS = [
      # Cabeçalhos suspeitos
      "MZ",
      "ELF",
      # Adicione mais cabeçalhos conforme necessário
    ]

    SUSPICIOUS_PATTERNS = [
      # Padrões suspeitos
      /eval\s*\(/i,
      /base64_decode/i,
      /shell_exec/i,
      /system\s*\(/i,
      # Adicione mais padrões conforme necessário
    ]

    EXECUTABLE_EXTENSIONS = [
      '.exe', '.dll', '.so', '.dylib', '.bin',
      '.sh', '.bat', '.cmd', '.ps1', '.vbs'
    ]

    NETWORK_PATTERNS = [
      # Padrões de operações de rede suspeitas
      /socket\s*\(/i,
      /connect\s*\(/i,
      /http\s*:/i,
      /ftp\s*:/i,
      # Adicione mais padrões conforme necessário
    ]

    SYSTEM_PATTERNS = [
      # Padrões de operações de sistema suspeitas
      /chmod\s*\(/i,
      /mkdir\s*\(/i,
      /rmdir\s*\(/i,
      /unlink\s*\(/i,
      # Adicione mais padrões conforme necessário
    ]

    MAX_SAFE_FILE_SIZE = 10 * 1024 * 1024 # 10MB
  end
end