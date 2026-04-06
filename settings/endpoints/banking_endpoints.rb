module OPSMON
  module BankingEndpoints
    def self.receive_transaction(request)
      request.body.rewind
      transaction_data = JSON.parse(request.body.read)

      # Registrar a transação
      transaction = DB[:transactions].insert(
        id: transaction_data['id'],
        vat_number: transaction_data['vat_number'],
        amount: transaction_data['amount'],
        currency: transaction_data['currency'],
        type: transaction_data['type'],
        status: transaction_data['status'],
        ip_address: request.ip,
        device_fingerprint: request.env['HTTP_X_DEVICE_FINGERPRINT'],
        timestamp: Time.now
      )

      # Analisar a transação
      BankingMonitor.analyze_transaction(transaction)

      { status: 'received', transaction_id: transaction }
    end

    def self.receive_login(request)
      request.body.rewind
      login_data = JSON.parse(request.body.read)

      # Registrar o login
      login = DB[:logins].insert(
        vat_number: login_data['vat_number'],
        ip_address: request.ip,
        device_fingerprint: request.env['HTTP_X_DEVICE_FINGERPRINT'],
        user_agent: request.user_agent,
        success: login_data['success'],
        timestamp: Time.now
      )

      # Analisar o login
      SecurityAnalyzer.analyze_login(login)

      { status: 'received', login_id: login }
    end

    def self.get_transaction_alerts(vat_number)
      alerts = Alert
        .where(Sequel.lit("details->>'vat_number' = ?", vat_number))
        .order(Sequel.desc(:timestamp))
        .limit(100)
        .all

      { alerts: alerts.map(&:to_hash) }
    end

    def self.get_user_activity(vat_number)
      transactions = DB[:transactions]
        .where(vat_number: vat_number)
        .order(Sequel.desc(:timestamp))
        .limit(100)
        .all

      logins = DB[:logins]
        .where(vat_number: vat_number)
        .order(Sequel.desc(:timestamp))
        .limit(100)
        .all

      {
        transactions: transactions,
        logins: logins
      }
    end

    def self.get_compliance_report(vat_number, start_date, end_date)
      transactions = DB[:transactions]
        .where(vat_number: vat_number)
        .where(Sequel.lit("timestamp BETWEEN ? AND ?", start_date, end_date))
        .all

      aml_transactions = transactions.select { |t| t[:amount].to_f >= 10000 }
      suspicious_transactions = transactions.select { |t| t[:status] == 'suspicious' }

      {
        total_transactions: transactions.count,
        total_amount: transactions.sum { |t| t[:amount].to_f },
        aml_transactions: aml_transactions.count,
        suspicious_transactions: suspicious_transactions.count,
        transactions: transactions
      }
    end
  end
end