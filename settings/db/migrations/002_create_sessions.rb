Sequel.migration do
  up do
    create_table(:sessions) do
      String :id, primary_key: true
      foreign_key :admin_id, :admins
      DateTime :created_at, null: false
      DateTime :expires_at, null: false
    end
  end

  down do
    drop_table(:sessions)
  end
end