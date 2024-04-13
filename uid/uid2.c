#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdlib.h>

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>

#include <pwd.h>
static int pam_conversation(int num_msg, const struct pam_message **msg,
      			    struct pam_response **resp, void *appdata_ptr) {
    char *pass = malloc(strlen(appdata_ptr) + 1);
    strcpy(pass, appdata_ptr);

    int i;

    *resp = calloc(num_msg, sizeof(struct pam_response));

    for (i = 0; i < num_msg; ++i) {
        /* Игнорируем все сообщения PAM кроме сообщения со скрытым выводом - т.е. ввод пароля */
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF)
            continue;

        /* Подставляем пароль в PAM для проверки */
        resp[i]->resp = pass;
    }

    return PAM_SUCCESS;
}

/* Функция выводит на экран пользовательские идентификаторы вызывающего процесса */
int get_user_info()
{
	uid_t ruid, euid, suid;
	gid_t rgid, egid, sgid;

	getresuid(&ruid, &euid, &suid);
	printf("RUID: %d, EUID: %d, SUID: %d\n", ruid,euid,suid);
	getresgid(&rgid, &egid, &sgid);
	printf("RGID: %d, EGID: %d, SGID: %d\n", rgid,egid,sgid);
	return 0;
}


/* Возвращает  идентификатор пользователя, соответсвующего name, или -1 при ошибке */
uid_t userid_from_name(const char* name)
{
	struct passwd *pwd;
	uid_t u;
	char *endptr;
	if (name == NULL || *name == '\0')
		return -1;
	u = strtol(name, &endptr,10);
	if (*endptr == '\0')
		return 0;
	pwd = getpwnam(name);
	if (pwd == NULL)
		return -1;
	return pwd->pw_uid;
}

/* Возвращает  идентификатор первичной группы пользователя, соответсвующего name, или -1 при ошибке */
gid_t upgid_from_name(const char* name)
{
	struct passwd *pwd;
	char *endptr;
	if (name == NULL || *name == '\0')
		return -1;
	pwd = getpwnam(name);
	if (pwd == NULL)
		return -1;
	return pwd->pw_gid;
}

int main()
{
        pam_handle_t *handle = NULL;
        const char *service_name = "pam_example";
        int retval;
        char *username; /* Будет установлено PAM-ом в функции pam_get_item (см. ниже) */
	uid_t uid;
	gid_t gid;

	get_user_info(); /* Пользовательские идентификаторы процесса в начале выполнения */
       

	char *user = "user1"; // Чтобы не запрашивать пользователя интерактивно
	char *password = "netlab123";  // И пароль

	struct pam_conv conv = {
    		pam_conversation, /* Собственная conversation-функция */
    		(void *) password /* Подсовываем пароль в conversation-функцию */
	};
	retval = pam_start(service_name, user, &conv, &handle); /* Инициализация PAM */
        if (retval != PAM_SUCCESS){
                fprintf(stderr, "Ошибка инициализации PAM: %s\n", pam_strerror(handle, retval));
                return 1;
        }

        retval = pam_authenticate(handle, 0); /* Выполнить аутентфикацию (будет запрошен пароль)*/
        if (retval != PAM_SUCCESS) {
                fprintf(stderr, "Ошибка аутентификации PAM: %s\n", pam_strerror(handle, retval));
                return 1;
        }

        retval = pam_acct_mgmt(handle, 0); /* Проверка статуса УЗ (может ли пользователь получить доступ к системе) */
        if (retval != PAM_SUCCESS) {
                fprintf(stderr, "Ошибка проверки доступа PAM: %s\n", pam_strerror(handle, retval));
                return 1;
        }

        /* Получаем имя аутентифицированного пользователя */
        pam_get_item(handle, PAM_USER, (const void **)&username);

	/* Преобразуем имя аутентифицированного пользователя в пользовательские идентификаторы */
	uid = userid_from_name(username);
	gid = upgid_from_name(username);
        printf("Добро пожаловать, %s(%d,%d)\n", username, uid, gid);

	/* Меняем контекст безопасности процесса */
	setgid(gid);
	setuid(uid);

	get_user_info(); /* Пользовательские идентификаторы процесса после смены контекста */
        pam_end(handle, retval); /* Сеанс PAM обязательно завершать в конце */
}
