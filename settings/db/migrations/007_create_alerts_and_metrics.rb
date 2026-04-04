Sequel.migration do
  up do
    create_table(:alerts) do
      primary_key :id
      String :alert_type, size: 50, null: false
      String :severity, size: 20, null: false
      String :message, text: true, null: false
      String :status, size: 20, default: 'new'
      String :details, text: true
      DateTime :timestamp, null: false
      index :alert_type
      index :severity
      index :status
      index [:timestamp]
    end

    create_table(:metrics) do
      primary_key :id
      String :metric_type, size: 50, null: false
      Float :value, null: false
      String :source, size: 100
      DateTime :timestamp, null: false
      index :metric_type
      index [:timestamp]
    end
  end

  down do
    drop_table(:metrics)
    drop_table(:alerts)
  end
end
