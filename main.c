#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sqlite3.h>
#include <unistd.h>   //close
#include <arpa/inet.h>    //close
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "base64.h"
#include "ctype.h"

#define PADDING RSA_NO_PADDING
#define KEY_LENGTH  1024
#define PUB_EXP     65537
#define TRUE   1
#define FALSE  0
#define MAX_BUF 2048
#define PORT 8888
#define MAX_CLIENTS 30

#define try bool __HadError=false;
#define catch(x) ExitJmp:if(__HadError)
#define throw(x) __HadError=true;goto ExitJmp;

int client_socket[MAX_CLIENTS];
int clients_ids[MAX_CLIENTS];
int random_numbers[MAX_CLIENTS];
int client_auth[MAX_CLIENTS];

bool file_exist (char *filename)
{
    if (!realpath(filename, NULL))
        return 0;
    return 1;
}

// чтение файла в строку
char* read_file_to_string(char *filename) {
    char *buffer;
    long length = 4096;
    FILE * f = fopen (filename, "rb");

    if (f)
    {
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        buffer = malloc (length);
        if (buffer)
        {
            fread (buffer, 1, length, f);
        }
        fclose (f);
    }

    return buffer;
}

void write_client_public_key(int id, char *key) {
    char str[10], filename[30];
    sprintf(str, "%d", id);
    snprintf( filename, sizeof( filename ), "%s%s%s", "keys/clients/public", str, ".pem" );

    FILE *out = fopen(filename, "w");
    fseek(out,0,SEEK_SET);
    fwrite(key,sizeof(char),strlen(key), out);
    fclose(out);
}

void generate_keys_for_client(int id) {
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;

    // generate filenames
    char str[10], private_name[25], public_name[25];
    sprintf(str, "%d", id);
    snprintf( private_name, sizeof( private_name ), "%s%s%s", "keys/private", str, ".pem" );
    snprintf( public_name, sizeof( public_name ), "%s%s%s", "keys/public", str, ".pem" );

    //char 		buf[1024];
    //int		fd;
    //int		n;

    //settiamo il PNRG
    if(!RAND_load_file("dev/urandom", 1024)) {
        printf("Can't seed PNRG");
    }

    //BN_new() alloca una struttura BIGNUM nel modo corretto.
    bne = BN_new();

    //Bn_set_word(BIGNUM *a, unsigned long w) assegna alla struttura a con il valore w.
    ret = BN_set_word(bne, PUB_EXP);
    if(ret != 1){
        printf("BN_set_word fallita");
        return;
    }

    //RSA_new alloca e inizializza una struttura RSA.
    r = RSA_new();
    //RSA_generate_key_ex crea una chiave privata di lunghezza bits e di esponente bne.
    ret = RSA_generate_key_ex(r, KEY_LENGTH, bne, NULL);
    if(ret != 1){
        printf("errore");
        return;
    }

    //EVP_PKEY_new() inizializza una struttura EVP_PKEY che conterrà la chiave pubblica.
    EVP_PKEY *pkey = EVP_PKEY_new();
    //EVP_PKEY_set1_RSA permette di ricavare la chiave pubblica dalla chiave privata generata in precedenza.
    if (!EVP_PKEY_set1_RSA(pkey, r)) {
        printf("errore nel evp e pkey");
    }

    //Per impacchettare le chiavi in messaggi, prima bisogna inserirle dentro una sorta di Input Stream detti BIO i quali ci
    //permetteranno di convertire le chiavi in stringhe di caratteri.
    //Sia BIO_new che BIO_S_mem sono funzioni che allocano e inizializzano queste strutture.
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    //PEM_write_bio_RSAPrivateKey scrive la chiave privata in formato ? nello stream BIO pri.
    PEM_write_bio_RSAPrivateKey(pri, r, NULL, NULL, 0, NULL, NULL);
    //PEM_write_bio_PUBKEY scrive la chiave pubblica in formato ? nello stream BIO pub.
    PEM_write_bio_PUBKEY(pub, pkey);

    //BIO_pending ritorna il numero di caratteri utilizzati dagli stream per rappresentare la chiave. pri_len e pub_len
    //serviranno per allocare le stringhe contenenti le chiavi.
    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);

    //Alloco le due stringhe.
    char *pri_key = malloc(pri_len + 1);
    char *pub_key = malloc(pub_len + 1);

    //BIO_read permette di leggere gli Stream Bio e traferirli in strnghe di caratteri. Perciò leggo dagli stream e scrivo
    //nelle stringhe precedentemente allocate.
    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    //Aggiungo un caratteri terminatore alle stringhe.
    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    //Stampo a video le chiavi.

    FILE *out = fopen(private_name, "w");
    fseek(out,0,SEEK_SET);
    fwrite(pri_key,sizeof(char),pri_len, out);
    fclose(out);

    FILE *out2 = fopen(public_name, "w");
    fseek(out2,0,SEEK_SET);
    fwrite(pub_key,sizeof(char),pub_len, out2);
    fclose(out2);

    //Liberiamo la memoria dalle strutture allocate.
    RSA_free(r);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
}

// отправка id и публичного ключа
int send_id_public_key(int socket, int id) {
    char str[10], public_name[25];
    sprintf(str, "%d", id);

    snprintf( public_name, sizeof( public_name ), "%s%s%s", "keys/public", str, ".pem" );

    FILE *fp = fopen(public_name, "rb");

    if(fp==NULL){
        printf("File open error");
        return -1;
    }

    /* Read data from file and send it */
    for (;;){
        /* First read file in chunks of BUF_SIZE bytes */
        unsigned char buff[MAX_BUF]={0};
        int nread = fread(buff, 1, MAX_BUF, fp);

        /* If read was success, send data. */
        if(nread > 0) {
            write(socket, buff, nread);
        }
        /*
         * There is something tricky going on with read ..
         * Either there was error, or we reached end of file.
         */
        if (nread < MAX_BUF){
            if (feof(fp))
                printf("\nEnd of file\n");
            if (ferror(fp))
                printf("\nError reading\n");
            break;
        }
    }

    fclose(fp);

    return 1;
}

// чтение открытого ключа сервера
char* read_private_key_server(int id) {
    char str[10], private_name[25];
    sprintf(str, "%d", id);

    snprintf( private_name, sizeof( private_name ), "%s%s%s", "keys/private", str, ".pem" );

    char *buffer;
    long length = 2048;
    FILE * f = fopen (private_name, "rb");

    if (f)
    {
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        buffer = malloc (length);
        if (buffer)
        {
            fread (buffer, 1, length, f);
        }
        fclose (f);
    }

    return buffer;
}

RSA* loadPUBLICKeyFromString( const char* publicKeyStr )
{
    // A BIO is an I/O abstraction (Byte I/O?)

    // BIO_new_mem_buf: Create a read-only bio buf with data
    // in string passed. -1 means string is null terminated,
    // so BIO_new_mem_buf can find the dataLen itself.
    // Since BIO_new_mem_buf will be READ ONLY, it's fine that publicKeyStr is const.
    BIO* bio = BIO_new_mem_buf( (void*)publicKeyStr, -1 ) ; // -1: assume string is null terminated

    BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL

    // Load the RSA key from the BIO
    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY( bio, NULL, NULL, NULL ) ;
    if( !rsaPubKey )
        printf( "ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) ) ;

    BIO_free( bio ) ;
    return rsaPubKey ;
}

RSA* loadPRIVATEKeyFromString( const char* privateKeyStr )
{
    BIO *bio = BIO_new_mem_buf( (void*)privateKeyStr, -1 );
    //BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
    RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey( bio, NULL, NULL, NULL ) ;

    if ( !rsaPrivKey )
        printf("ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));

    BIO_free( bio ) ;
    return rsaPrivKey ;
}

unsigned char* rsaEncrypt( RSA *pubKey, const unsigned char* str, int dataSize, int *resultLen )
{
    int rsaLen = RSA_size( pubKey ) ;
    unsigned char* ed = (unsigned char*)malloc( rsaLen ) ;

    // RSA_public_encrypt() returns the size of the encrypted data
    // (i.e., RSA_size(rsa)). RSA_private_decrypt()
    // returns the size of the recovered plaintext.
    *resultLen = RSA_public_encrypt( dataSize, (const unsigned char*)str, ed, pubKey, PADDING ) ;
    if( *resultLen == -1 )
        printf("ERROR: RSA_public_encrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));

    return ed ;
}

unsigned char* rsaDecrypt( RSA *privKey, const unsigned char* encryptedData, int *resultLen )
{
    int rsaLen = RSA_size( privKey ) ; // That's how many bytes the decrypted data would be

    unsigned char *decryptedBin = (unsigned char*)malloc( rsaLen ) ;
    *resultLen = RSA_private_decrypt( RSA_size(privKey), encryptedData, decryptedBin, privKey, PADDING ) ;
    if( *resultLen == -1 )
        printf( "ERROR: RSA_private_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL) ) ;

    return decryptedBin ;
}

// You may need to encrypt several blocks of binary data (each has a maximum size
// limited by pubKey).  You shoudn't try to encrypt more than
// RSA_LEN( pubKey ) bytes into some packet.
// returns base64( rsa encrypt( <<binary data>> ) )
// base64OfRsaEncrypted()
// base64StringOfRSAEncrypted
// rsaEncryptThenBase64
char* rsaEncryptThenBase64( RSA *pubKey, unsigned char* binaryData, int binaryDataLen, int *outLen )
{
    int encryptedDataLen ;

    // RSA encryption with public key
    unsigned char* encrypted = rsaEncrypt( pubKey, binaryData, binaryDataLen, &encryptedDataLen ) ;

    // To base 64
    int asciiBase64EncLen ;
    char* asciiBase64Enc = base64( encrypted, encryptedDataLen, &asciiBase64EncLen ) ;

    // Destroy the encrypted data (we are using the base64 version of it)
    free( encrypted ) ;

    // Return the base64 version of the encrypted data
    return asciiBase64Enc ;
}

// rsaDecryptOfUnbase64()
// rsaDecryptBase64String()
// unbase64ThenRSADecrypt()
// rsaDecryptThisBase64()
unsigned char* rsaDecryptThisBase64( RSA *privKey, char* base64String, int *outLen )
{
    int encBinLen ;
    unsigned char* encBin = unbase64( base64String, (int)strlen( base64String ), &encBinLen ) ;

    // rsaDecrypt assumes length of encBin based on privKey
    unsigned char *decryptedBin = rsaDecrypt( privKey, encBin, outLen ) ;
    free( encBin ) ;

    return decryptedBin ;
}

char* decrypt_message(int id, char* message) {
    char *buffer;
    buffer = malloc (8192);
    memset(buffer, '\0', 8192);

    char *private_key;
    private_key = read_private_key_server(id);

    // Now decrypt this very string with the private key
    RSA *privKey = loadPRIVATEKeyFromString( private_key ) ;

    // если сообщение разделено по токенам
    if(strstr(message, "|") != NULL) {

        char *token;

        /* get the first token */
        token = strtok(message, "|");
        int i = 0;

        /* walk through other tokens */
        while (token != NULL) {
            if(i!=0) {
                int rBinLen;

                char *rBin = (char*)rsaDecryptThisBase64(privKey, token, &rBinLen);

                // извлекаем длину строки

                char *token2;
                int length_msg;
                int count_token = 0;
                while((token2 = strtok_r(rBin, "_", &rBin)))
                {
                    if(count_token == 0) {
                        sscanf(token2, "%d", &length_msg);
                    } else {
                        strncpy(buffer + strlen(buffer), token2, length_msg);
                    }
                    count_token++;
                }

                free(rBin);
            }
            token = strtok(NULL, "|");
            i++;
        }
    } else {

        int rBinLen ;
        char* rBin = (char*)rsaDecryptThisBase64( privKey, message, &rBinLen ) ;

        char *token2;
        int length_msg;
        int count_token = 0;
        while((token2 = strtok_r(rBin, "_", &rBin)))
        {
            if(count_token == 0) {
                sscanf(token2, "%d", &length_msg);
            } else {
                strncpy(buffer + strlen(buffer), token2, length_msg);
            }
            count_token++;
        }

        free(rBin);
    }

    buffer[strlen(buffer)] = '\0';

    RSA_free(privKey);

    return buffer;
}

char* encrypt_message(int id, char* message, size_t message_len) {
    char *buffer, *server_public_key;
    buffer = malloc(8192);
    memset(buffer, '\0', 8192);

    char str[10], filename[30];
    sprintf(str, "%d", id);
    snprintf( filename, sizeof( filename ), "%s%s%s", "keys/clients/public", str, ".pem" );

    // загружаем открытый ключ клиента
    server_public_key = read_file_to_string(filename);


    int dataSize = 124;
    // LOAD PUBLIC KEY
    RSA *pubKey = loadPUBLICKeyFromString(server_public_key) ;

    int asciiB64ELen;

    // Encrypt the message
    char buffer_to_encrypt[dataSize + 5];

    int msg_len = 0;

    // шифруем блоками по 128 символов
    for(int i = 0; i < message_len; i += dataSize) {
        if(message_len - i > dataSize) {
            msg_len = dataSize;
        } else {
            msg_len = message_len - i;
        }

        memset(buffer_to_encrypt, 0, dataSize + 5);

        // ставим в начало длину строки
        sprintf(buffer_to_encrypt, "%d_", msg_len);
        buffer_to_encrypt[strlen(buffer_to_encrypt)] = '\0';

        strncpy(buffer_to_encrypt + strlen(buffer_to_encrypt), &message[i], msg_len);

        buffer_to_encrypt[strlen(buffer_to_encrypt)] = '\0';

        char* asciiB64E = rsaEncryptThenBase64( pubKey, (unsigned char *)buffer_to_encrypt, dataSize + 4, &asciiB64ELen ) ;

        // разделяем блоки |
        if(i != 0)
            memcpy(buffer + strlen(buffer), "|", 1);

        memcpy(buffer + strlen(buffer), &asciiB64E[0], strlen(asciiB64E));

        memset(buffer_to_encrypt, 0, dataSize + 5);
    }

    buffer[strlen(buffer)] = '\0';

    RSA_free(pubKey);

    return buffer;
}

// регистрация клиента
int registration(int socket) {
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;

    int rc = sqlite3_open("users.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    char *sql = "INSERT INTO users(activated) VALUES (?);";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int(res, 1, 0);
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    int step = sqlite3_step(res);

    int id = sqlite3_last_insert_rowid(db);

    // генерируем ключи для клиента
    generate_keys_for_client(id);

    sqlite3_finalize(res);
    sqlite3_close(db);

    // отправляем id и открытый ключ
    char id_str[10];
    sprintf(id_str, "REGID|%d", id);

    // отправляем id пользователя
    send(socket, id_str, sizeof(id_str), 0);

    return id;
}

// ставим пользователя активным (прошел процедуру проверки ключей)
void set_user_activated_db(int id) {
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;

    int rc = sqlite3_open("users.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    char *sql = "UPDATE users SET activated=1 WHERE id=?;";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int(res, 1, id);
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_step(res);

    sqlite3_finalize(res);
    sqlite3_close(db);
}

void send_random_number_user(int socket, int id, int random_number) {
    char s[20];
    sprintf(s, "%d", random_number);
    s[strlen(s)] = '\0';
    char *encrypted_body = encrypt_message(id, s, strlen(s));

    char buffer[1024];
    sprintf(buffer, "RANDNUM|%s", encrypted_body);
    buffer[strlen(buffer)] = '\0';

    send(socket, buffer, sizeof(buffer), 0);
    free(encrypted_body);
}

bool check_activated_user(int user_id) {
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;

    int rc = sqlite3_open("users.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    char *sql = "SELECT count(*) FROM users WHERE activated=1 AND id=?";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int(res, 1, user_id);
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    int num_cols;

    while (sqlite3_step(res) != SQLITE_DONE) {
        num_cols = sqlite3_column_int(res, 0);
    }

    sqlite3_finalize(res);
    sqlite3_close(db);

    return num_cols > 0;
}

// проверка переданного и зашифрованного id
bool check_auth(char *buffer, int i) {
    char *pointer = buffer;

    char *token;

    int count_token = 0;
    char user_id_str[6] = "\0";
    int user_id_int;
    char *decrypted_message;
    while((token = strtok_r(pointer, "|", &pointer)))
    {
        if(count_token == 1) {
            strncpy(user_id_str, &token[0], strlen(token));
            user_id_str[strlen(user_id_str)] = '\0';
            sscanf(token, "%d", &user_id_int);
            // проверка, активирован ли пользователь
            if(!check_activated_user(user_id_int)) {
                return false;
            }
        }
        if(count_token == 2) {
            decrypted_message = decrypt_message(user_id_int, token);
        }
        count_token++;
    }

    // если строки совпадают, то все збс
    int result_check = strcmp(user_id_str, decrypted_message) == 0;

    if(result_check)
        clients_ids[i] = user_id_int;

    free(decrypted_message);
    free(pointer);

    return result_check;
}

// сохранение сообщения в базу
void save_message(int user_from, int user_to, char *content) {
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;

    int rc = sqlite3_open("users.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    char *sql = "INSERT INTO messages(user_from, user_to, content) VALUES (?, ?, ?);";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int(res, 1, user_from);
        sqlite3_bind_int(res, 2, user_to);
        sqlite3_bind_text(res, 3, content, -1, 0);
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    int step = sqlite3_step(res);

    sqlite3_finalize(res);
    sqlite3_close(db);
}

// отправка сообщения
bool message_send(char *buffer, int i) {
    char *pointer = buffer;

    char *token;

    int count_token = 0;
    char user_id_str[6] = "\0";
    char sender_id_str[6] = "\0";
    sprintf(sender_id_str, "%d", clients_ids[i]);

    int user_id_int;
    char *decrypted_message;

    while((token = strtok_r(pointer, "|", &pointer)))
    {
        if(count_token == 1) {
            strncpy(user_id_str, &token[0], strlen(token));
            user_id_str[strlen(user_id_str)] = '\0';

            if(sscanf(token, "%d", &user_id_int) != 1)
                return false;

            // проверка, существует ли пользователь с переданным id
            if(!check_activated_user(user_id_int)) {
                return false;
            }

        }
        if(count_token == 2) {
            // расшифровываем сообщение
            decrypted_message = decrypt_message(clients_ids[i], token);
        }
        count_token++;
    }


    bool user_is_online = false;
    int finded_user_index = -1;
    // проверяем, онлайн ли этот пользователь
    for(int j = 0; j < MAX_CLIENTS; j++) {
        if(clients_ids[j] == user_id_int) {
            user_is_online = true;
            finded_user_index = j;
            break;
        }
    }

    char *encrypted_user_id = encrypt_message(user_id_int, sender_id_str, strlen(sender_id_str));
    // зашифровываем сообщение
    char *encrypted_message = encrypt_message(user_id_int, decrypted_message, strlen(decrypted_message));

    // отправляем сообщение на сокет клиенту, если онлайн
    if(user_is_online) {

        char buffer[1024] = "NEWMESS|\0";

        memcpy(buffer+strlen(buffer), &encrypted_user_id[0], strlen(encrypted_user_id));
        memcpy(buffer+strlen(buffer), "|", 1);
        memcpy(buffer+strlen(buffer), &encrypted_message[0], strlen(encrypted_message));

        buffer[strlen(buffer)] = '\0';

        // отправляем сообщение клиенту
        send(client_socket[finded_user_index], buffer, strlen(buffer), 0);
    } else {
        // иначе сохраняем сообщение в БД
        save_message(clients_ids[i], user_id_int, encrypted_message);
    }

    free(decrypted_message);
    free(encrypted_user_id);
    free(encrypted_message);
    free(pointer);

    return true;
}

// проверка новых сообщений
void check_messages_count(int sockfd, int user_id) {
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;

    int rc = sqlite3_open("users.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    char *sql = "SELECT count(*) FROM messages WHERE user_to=?";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int(res, 1, user_id);
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    int num_cols;

    while (sqlite3_step(res) != SQLITE_DONE) {
        num_cols = sqlite3_column_int(res, 0);
    }

    sqlite3_finalize(res);
    sqlite3_close(db);

    char buffer[1024] = "MESSCOUNT|\0";
    char count_str[5];
    sprintf(count_str, "%d", num_cols);
    count_str[strlen(count_str)] = '\0';

    char *encrypted_message = encrypt_message(user_id, count_str, strlen(count_str));

    memcpy(buffer+strlen(buffer), &encrypted_message[0], strlen(encrypted_message));

    buffer[strlen(buffer)] = '\0';

    send(sockfd, buffer, strlen(buffer), 0);
}

void get_last_message(int sockfd, int user_id) {
    sqlite3 *db;
    char *err_msg = 0;
    sqlite3_stmt *res;

    int rc = sqlite3_open("users.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    char *sql = "SELECT * FROM messages WHERE user_to=? LIMIT 1";

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int(res, 1, user_id);
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    int message_id, user_from;
    char content[8192];

    // если найдено сообщение
    if (sqlite3_step(res) == SQLITE_ROW) {
        message_id  = sqlite3_column_int(res, 0);
        user_from  = sqlite3_column_int(res, 1);
        char *tmp_content = ( char *)sqlite3_column_text (res, 3);
        memcpy(content, &tmp_content[0], strlen(tmp_content));
        content[strlen(content)] = '\0';

        char buffer[1024] = "MESSLAST|\0";
        char user_from_str[5];
        sprintf(user_from_str, "%d", user_from);
        user_from_str[strlen(user_from_str)] = '\0';

        char *encrypted_message = encrypt_message(user_id, user_from_str, strlen(user_from_str));

        memcpy(buffer+strlen(buffer), &encrypted_message[0], strlen(encrypted_message));
        memcpy(buffer+strlen(buffer), "|", 1);
        memcpy(buffer+strlen(buffer), &content[0], strlen(content));

        buffer[strlen(buffer)] = '\0';

        // удаляем сообщение message_id
        char *sql2 = "DELETE FROM messages WHERE id=?";
        sqlite3_stmt *res2;

        rc = sqlite3_prepare_v2(db, sql2, -1, &res2, 0);

        if (rc == SQLITE_OK) {
            sqlite3_bind_int(res2, 1, message_id);
        } else {
            fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        }

        sqlite3_step(res2);

        // отправляем сообщение клиенту
        send(sockfd, buffer, strlen(buffer), 0);
        free(encrypted_message);
    } else {
        send(sockfd, "MESSLAST|NOMESSAGE", 18, 0);
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
}

int main() {
    srand(time(NULL));

    int opt = TRUE;
    int master_socket, addrlen, new_socket, activity, i, valread, sd;
    int max_sd;
    struct sockaddr_in address;

    char buffer[MAX_BUF+1];  //data buffer of 1K

    //set of socket descriptors
    fd_set readfds;

    //a message
    char *message = "Messenger v1.0 \r\n";

    //initialise all client_socket[] to 0 so not checked
    for (i = 0; i < MAX_CLIENTS; i++)
    {
        client_socket[i] = 0;
        clients_ids[i] = -1;
        random_numbers[i] = -1;
        client_auth[i] = -1;
    }

    //create a master socket
    if( (master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    //set master socket to allow multiple connections ,
    //this is just a good habit, it will work without this
    if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,
                   sizeof(opt)) < 0 )
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    //type of socket created
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );

    //bind the socket to localhost port 8888
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Listener on port %d \n", PORT);

    //try to specify maximum of 3 pending connections for the master socket
    if (listen(master_socket, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    //accept the incoming connection
    addrlen = sizeof(address);
    puts("Waiting for connections ...");

    while(TRUE)
    {
        //clear the socket set
        FD_ZERO(&readfds);

        //add master socket to set
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;

        //add child sockets to set
        for ( i = 0 ; i < MAX_CLIENTS ; i++)
        {
            //socket descriptor
            sd = client_socket[i];

            //if valid socket descriptor then add to read list
            if(sd > 0)
                FD_SET( sd , &readfds);

            //highest file descriptor number, need it for the select function
            if(sd > max_sd)
                max_sd = sd;
        }

        //wait for an activity on one of the sockets , timeout is NULL ,
        //so wait indefinitely
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);

        if ((activity < 0) && (errno!=EINTR))
        {
            printf("select error");
        }

        //If something happened on the master socket ,
        //then its an incoming connection
        if (FD_ISSET(master_socket, &readfds))
        {
            if ((new_socket = accept(master_socket,
                                     (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)
            {
                perror("accept");
                exit(EXIT_FAILURE);
            }

            //inform user of socket number - used in send and receive commands
            printf("New connection , socket fd is %d , ip is : %s , port : %d\n" , new_socket , inet_ntoa(address.sin_addr) , ntohs
                    (address.sin_port));

            //send new connection greeting message
            if( send(new_socket, message, strlen(message), 0) != strlen(message) )
            {
                perror("send");
            }

            puts("Welcome message sent successfully");

            //add new socket to array of sockets
            for (i = 0; i < MAX_CLIENTS; i++)
            {
                //if position is empty
                if( client_socket[i] == 0 )
                {
                    client_socket[i] = new_socket;
                    printf("Adding to list of sockets as %d\n" , i);

                    break;
                }
            }
        }

        //else its some IO operation on some other socket
        for (i = 0; i < MAX_CLIENTS; i++)
        {
            sd = client_socket[i];

            if (FD_ISSET( sd , &readfds))
            {
                //Check if it was for closing , and also read the
                //incoming message
                if ((valread = recv( sd , buffer, MAX_BUF, 0)) == 0)
                {
                    //Somebody disconnected , get his details and print
                    getpeername(sd , (struct sockaddr*)&address , \
                        (socklen_t*)&addrlen);
                    printf("Host disconnected , ip %s , port %d \n" ,
                           inet_ntoa(address.sin_addr) , ntohs(address.sin_port));

                    //Close the socket and mark as 0 in list for reuse
                    close( sd );
                    client_socket[i] = 0;
                    clients_ids[i] = -1;
                    random_numbers[i] = -1;
                    client_auth[i] = -1;
                }

                    //Echo back the message that came in
                else {
                    //set the string terminating NULL byte on the end
                    //of the data read
                    buffer[valread] = '\0';

                    // если не было попыток аутентификации и регистрации
                    if(client_auth[i] == -1) {
                        // РЕГИСТРАЦИЯ
                        if (strcmp(buffer, "REG") == 0) {
                            clients_ids[i] = registration(sd);
                            memset(buffer, 0, MAX_BUF + 1);
                            continue;
                        }

                        if (strcmp(buffer, "OKREG") == 0) {
                            // отправляем открытый ключ
                            send_id_public_key(sd, clients_ids[i]);
                            client_auth[i] = 0; // регистрация
                            memset(buffer, 0, MAX_BUF + 1);
                            continue;
                        }

                        // аутентификация
                        if (strstr(buffer, "AUTH") != NULL) {
                            if(check_auth(buffer, i)) {
                                client_auth[i] = 1; // аутентифицирован
                                send(sd, "AUTHGOOD", 8, 0);
                            } else {
                                send(sd, "AUTHBAD", 7, 0);
                            }
                            memset(buffer, 0, MAX_BUF + 1);
                            continue;
                        }

                        // метод не найден
                        send(sd, "404", 3, 0);
                    }

                    // Если рега
                    if (client_auth[i] == 0) {
                        // ПОЛУЧЕНИЕ ОТКРЫТОГО КЛЮЧА КЛИЕНТА
                        if (strstr(buffer, "PUBKEY") != NULL) {
                            char *decrypted = decrypt_message(clients_ids[i], buffer);
                            write_client_public_key(clients_ids[i], decrypted);

                            int r = rand() % 16000;
                            random_numbers[i] = r;

                            // отправляем рандомное число клиенту
                            send_random_number_user(sd, clients_ids[i], r);
                            free(decrypted);
                            memset(buffer, 0, MAX_BUF + 1);
                            continue;
                        }

                        // ПОЛУЧЕНИЕ РАНДОМНОГО ЧИСЛА + 1 ОТ КЛИЕНТА
                        if (strstr(buffer, "RANDNUMTWO") != NULL) {
                            char *decrypted_msg = decrypt_message(clients_ids[i], buffer);

                            int number;
                            sscanf(decrypted_msg, "%d", &number);

                            // сравниваем числа
                            if (random_numbers[i] == number - 1) {
                                client_auth[i] = 1; // аутентифицирован
                                set_user_activated_db(clients_ids[i]);
                                send(sd, "REGGOOD", 7, 0);
                            } else {
                                send(sd, "REGBAD", 5, 0);
                            }

                            free(decrypted_msg);
                            memset(buffer, 0, MAX_BUF + 1);
                            continue;
                        }

                        // метод не найден
                        send(sd, "404", 3, 0);
                    }

                    // Если аутентифицирован
                    if (client_auth[i] == 1) {

                        // проверка количества новых сообщений
                        if (strstr(buffer, "MESSCOUNT") != NULL) {
                            check_messages_count(sd, clients_ids[i]);
                            memset(buffer, 0, MAX_BUF + 1);
                            continue;
                        }

                        // получение последнего сообщения
                        if (strstr(buffer, "GETLASTMESS") != NULL) {
                            get_last_message(sd, clients_ids[i]);
                            memset(buffer, 0, MAX_BUF + 1);
                            continue;
                        }

                        // отправка сообщения определенному id
                        if (strstr(buffer, "SENDMESS") != NULL) {
                            if(message_send(buffer, i)) {
                                send(sd, "SENDMESSOK", 10, 0);
                            } else {
                                send(sd, "SENDMESSBAD", 11, 0);
                            }
                            memset(buffer, 0, MAX_BUF + 1);
                            continue;
                        }

                        // метод не найден
                        send(sd, "404", 3, 0);
                        memset(buffer, 0, MAX_BUF + 1);
                    }

                    // метод не найден
                    send(sd, "404", 3, 0);
                    memset(buffer, 0, MAX_BUF + 1);
                }
            }
        }
    }

    return 0;
}