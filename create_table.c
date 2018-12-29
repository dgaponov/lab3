#include <stdio.h>
#include <sqlite3.h>
#include <string.h>


int main(){

    sqlite3 *db;
    char *err_msg = 0;

    int rc = sqlite3_open("users.db", &db);

    if (rc != SQLITE_OK) {

        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);

        return 1;
    }

    char *sql = "CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, secret TEXT nullable, activated INTEGER DEFAULT 0);\n"
                "CREATE TABLE `messages` (\n"
                "\t`id`\tINTEGER PRIMARY KEY AUTOINCREMENT,\n"
                "\t`user_from`\tINTEGER NOT NULL,\n"
                "\t`user_to`\tINTEGER NOT NULL,\n"
                "\t`content`\tTEXT NOT NULL\n"
                ");";

    printf("%s\n", sql);


    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);


    if (rc != SQLITE_OK ) {

        fprintf(stderr, "Failed to create table\n");
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);

    } else {

        fprintf(stdout, "Table created successfully\n");
    }


    int last_id = sqlite3_last_insert_rowid(db);
    printf("The last Id of the inserted row is %d\n", last_id);

    sqlite3_close(db);

    return 0;
}