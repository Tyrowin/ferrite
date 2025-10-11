// @generated automatically by Diesel CLI.

diesel::table! {
    notes (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 120]
        title -> Varchar,
        body -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        #[max_length = 32]
        username -> Varchar,
        #[max_length = 255]
        email -> Varchar,
        #[max_length = 128]
        password_hash -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(notes -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(notes, users,);
