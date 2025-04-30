Sequel.migration do
  change do
    # Tabela de usuários
    create_table :users do
      primary_key :id
      String :vat_number, size: 20, null: false, unique: true
      String :password_hash, size: 100, null: false
      String :name, size: 100
      String :company_name, size: 100
      String :api_key, size: 64, unique: true
      String :kyc_status, size: 20, default: 'pending'
      DateTime :created_at
      DateTime :updated_at
    end

    # Tabela de funções
    create_table :roles do
      primary_key :id
      String :name, size: 50, null: false, unique: true
      String :description, text: true
      DateTime :created_at
      DateTime :updated_at
    end

    # Tabela de associação usuário-função
    create_table :users_roles do
      foreign_key :user_id, :users
      foreign_key :role_id, :roles
      primary_key [:user_id, :role_id]
    end

    # Tabela de transações
    create_table :transactions do
      primary_key :id
      String :vat_number, size: 20, null: false
      Decimal :amount, size: [15, 2], null: false
      String :currency, size: 3, null: false
      String :type, size: 50, null: false
      String :status, size: 20, null: false
      String :ip_address, size: 45
      String :device_fingerprint, size: 100
      String :user_agent, text: true
      DateTime :timestamp, null: false
      index :vat_number
      index :timestamp
    end

    # Tabela de logins
    create_table :logins do
      primary_key :id
      String :vat_number, size: 20, null: false
      String :ip_address, size: 45
      String :device_fingerprint, size: 100
      String :user_agent, text: true
      Boolean :success, null: false
      DateTime :timestamp, null: false
      index :vat_number
      index :timestamp
    end

    # Tabela de alertas
    create_table :alerts do
      primary_key :id
      String :alert_type, size: 50, null: false
      String :severity, size: 20, null: false
      String :message, text: true, null: false
      String :status, size: 20, default: 'new'
      json :details
      DateTime :timestamp, null: false
      index :alert_type
      index :severity
      index :status
      index :timestamp
    end

    # Tabela de métricas
    create_table :metrics do
      primary_key :id
      String :metric_type, size: 50, null: false
      Float :value, null: false
      String :source, size: 100
      DateTime :timestamp, null: false
      index :metric_type
      index :timestamp
    end

    # Tabela de regras de segurança
    create_table :security_rules do
      primary_key :id
      String :name, size: 100, null: false
      String :description, text: true
      String :rule_type, size: 50, null: false
      json :conditions, null: false
      String :action, size: 50, null: false
      Boolean :enabled, default: true
      DateTime :created_at
      DateTime :updated_at
    end

    # Tabela de relatórios
    create_table :reports do
      primary_key :id
      String :report_type, size: 50, null: false
      String :format, size: 20, default: 'pdf'
      json :parameters
      String :status, size: 20, default: 'pending'
      String :file_path, text: true
      DateTime :generated_at
      DateTime :created_at
      DateTime :updated_at
      index :report_type
      index :status
    end
  end
end