/*
 * leaky_app.c — demo приложение с намеренными утечками данных
 * ТОЛЬКО ДЛЯ ОБРАЗОВАТЕЛЬНЫХ ЦЕЛЕЙ
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 *  УТЕЧКА #1 — Хардкод пароля администратора
 * ============================================================ */
#define ADMIN_PASSWORD   "Adm1n$uper2024!"
#define ADMIN_USERNAME   "root_admin"

/* ============================================================
 *  УТЕЧКА #2 — AWS Access Key прямо в коде
 * ============================================================ */
#define AWS_ACCESS_KEY_ID     "AKIAIOSFODNN7EXAMPLE3"
#define AWS_SECRET_ACCESS_KEY "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
#define AWS_REGION            "us-east-1"

/* ============================================================
 *  УТЕЧКА #3 — Stripe API ключ (продакшн)
 * ============================================================ */
#define STRIPE_SECRET_KEY  "sk_live_51NzQpLKG3j4Hf8dXbY9mWqR7vT2cP0eA"
#define STRIPE_PUBLIC_KEY  "pk_live_51NzQpLKG3j4Hf8dXbY9mWqR7vT2cP0eA"

/* ============================================================
 *  УТЕЧКА #4 — JWT Secret
 * ============================================================ */
#define JWT_SECRET  "mySuperSecret_JWT_Key_NeverShareThis_2024"

/* ============================================================
 *  УТЕЧКА #5 — Строка подключения к БД с паролем
 * ============================================================ */
#define DB_CONNECTION_STRING \
    "postgresql://db_user:P@ssw0rd123@prod-db.internal:5432/customers_prod"

/* ============================================================
 *  УТЕЧКА #6 — Telegram Bot Token
 * ============================================================ */
#define TELEGRAM_BOT_TOKEN "7412536890:AAFhkLmNpQrStUvWxYz-AbCdEfGhIjKlMnOp"

/* ============================================================
 *  УТЕЧКА #7 — Google OAuth Client Secret
 * ============================================================ */
#define GOOGLE_CLIENT_ID     "483920174856-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com"
#define GOOGLE_CLIENT_SECRET "GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz12"

/* ============================================================
 *  УТЕЧКА #8 — SSH приватный ключ (фрагмент) в строке
 * ============================================================ */
static const char *SSH_PRIVATE_KEY =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA3Tr24z8KBqkTRkKjBMkGe3yFg8WqHkCdF2p1oPsEkDt7Nv\n"
    "AAAA.....(truncated for demo).....AAAA\n"
    "-----END RSA PRIVATE KEY-----\n";

/* ============================================================
 *  УТЕЧКА #9 — Encryption key захардкожен как массив байт
 * ============================================================ */
static unsigned char AES_MASTER_KEY[32] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0x42, 0x00, 0xFF, 0xA0, 0xB0, 0xC0,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

/* ============================================================
 *  УТЕЧКА #10 — Данные кредитной карты в структуре
 * ============================================================ */
typedef struct {
    char number[20];
    char holder[64];
    char cvv[4];
    char expiry[6];
} CreditCard;

static CreditCard test_card = {
    .number = "4111111111111111",
    .holder = "Ivan Petrov",
    .cvv    = "737",
    .expiry = "12/26"
};

/* ============================================================
 *  УТЕЧКА #11 — SendGrid API Key
 * ============================================================ */
#define SENDGRID_API_KEY "SG.AbCdEfGhIjKlMnOpQrSt.UvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz1234"

/* ============================================================
 *  УТЕЧКА #12 — Логирование пароля в открытом виде
 * ============================================================ */
void authenticate(const char *username, const char *password) {
    /* BUG: пишем пароль в лог! */
    printf("[LOG] authenticate() called: user='%s' password='%s'\n",
           username, password);

    if (strcmp(username, ADMIN_USERNAME) == 0 &&
        strcmp(password, ADMIN_PASSWORD) == 0) {
        printf("[AUTH] Access granted to %s\n", username);
    } else {
        printf("[AUTH] Access denied\n");
    }
}

/* ============================================================
 *  УТЕЧКА #13 — Вывод ключа в отладочном сообщении
 * ============================================================ */
void init_stripe(void) {
    printf("[DEBUG] Stripe init: secret=%s public=%s\n",
           STRIPE_SECRET_KEY, STRIPE_PUBLIC_KEY);
}

/* ============================================================
 *  УТЕЧКА #14 — Токен попадает в URL (GET-параметр)
 * ============================================================ */
void make_api_request(void) {
    char url[256];
    /* BUG: токен в URL логируется прокси, браузером и т.д. */
    snprintf(url, sizeof(url),
             "https://api.example.com/data?token=%s&user=%s",
             JWT_SECRET, ADMIN_USERNAME);
    printf("[HTTP] GET %s\n", url);
}

/* ============================================================
 *  УТЕЧКА #15 — Данные карты в error message
 * ============================================================ */
void process_payment(void) {
    printf("[ERROR] Payment failed for card %s (CVV: %s, exp: %s)\n",
           test_card.number, test_card.cvv, test_card.expiry);
}

/* ============================================================
 *  УТЕЧКА #16 — Запись секрета в /tmp (world-readable)
 * ============================================================ */
void cache_token(const char *token) {
    FILE *f = fopen("/tmp/app_token.txt", "w"); /* 0644 по умолчанию */
    if (f) {
        fprintf(f, "token=%s\n", token);
        fclose(f);
    }
}

/* ---- main ---- */
int main(void) {
    printf("=== Leaky App Demo ===\n\n");

    authenticate(ADMIN_USERNAME, ADMIN_PASSWORD);
    init_stripe();
    make_api_request();
    process_payment();
    cache_token(JWT_SECRET);

    printf("\n[INFO] AWS Key: %s\n", AWS_ACCESS_KEY_ID);
    printf("[INFO] DB: %s\n", DB_CONNECTION_STRING);
    printf("[INFO] TG Bot: %s\n", TELEGRAM_BOT_TOKEN);
    printf("[INFO] Google Secret: %s\n", GOOGLE_CLIENT_SECRET);
    printf("[INFO] SendGrid: %s\n", SENDGRID_API_KEY);

    (void)AES_MASTER_KEY;
    (void)SSH_PRIVATE_KEY;
    return 0;
}