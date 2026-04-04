Sequel.migration do
  up do
    create_table(:security_logs) do
      primary_key :id
      String :event_type, size: 50, null: false
      String :source, size: 100
      String :severity, size: 20, null: false
      String :message, text: true, null: false
      DateTime :timestamp, null: false
      String :user_id, size: 256
      String :ip_address, size: 64
      String :details, text: true
      index %i[user_id event_type timestamp]
      index [:timestamp]
    end
  end

  down do
    drop_table(:security_logs)
  end
end
