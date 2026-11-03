CREATE TABLE "credentials" (
	"user_id" text PRIMARY KEY,
	"password_hash" text NOT NULL,
	"updated_at" bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE "identities" (
	"provider" text,
	"subject" text,
	"user_id" text NOT NULL,
	"name" text,
	"email" text,
	"linked_at" bigint NOT NULL,
	CONSTRAINT "identities_pkey" PRIMARY KEY("provider","subject")
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"token_hash" text PRIMARY KEY,
	"id" text NOT NULL UNIQUE,
	"user_id" text NOT NULL,
	"data" jsonb NOT NULL,
	"created_at" bigint NOT NULL,
	"updated_at" bigint NOT NULL,
	"expires_at" bigint
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" text PRIMARY KEY,
	"created_at" bigint NOT NULL
);
--> statement-breakpoint
CREATE INDEX "sessions_user_id" ON "sessions" ("user_id");--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "identities" ADD CONSTRAINT "identities_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id");