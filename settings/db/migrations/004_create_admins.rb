Sequel.migration do
  up do
    create_table(:admins) do
      primary_key :id
      String :username, null: false, unique: true
      String :password_hash, null: false
      DateTime :created_at, null: false
      DateTime :updated_at, null: false
    end
  end

  down do
    drop_table(:admins)
  end
end