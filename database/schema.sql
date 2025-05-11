

create table if not exists "user" (
	"id" 					serial primary key,
	"public_id" 			varchar not null,
	"name" 					varchar not null,
	"email" 				varchar not null,
	"password_hashed" 		varchar not null,
	"created_at" 			timestamp not null,
	"num_login_attempts" 	int not null default 0,
	unique("public_id"),
	unique("email")
);

create table if not exists "session" (
	"id" 			serial primary key,
	"public_id" 	varchar not null,
	"csrf_token" 	varchar not null,
	"user_id" 		int references "user"("id") on delete cascade,
	"created_at" 	timestamp not null,
	"expires_at" 	timestamp not null,
	unique("public_id"),
	unique("user_id", "created_at")
);
