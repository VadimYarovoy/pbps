#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define MY_PAM_SERVICE "login"


int main()
{

	/* Используем стандартную conversation-функцию misc_conv   */
	struct pam_conv conv = {misc_conv, NULL};
	pam_handle_t *handle;
	int startResult, authResult;

	/* Создаем новый контекст PAM для сервиса MY_PAM_SERVICE           */
	startResult = pam_start(MY_PAM_SERVICE, NULL, &conv, &handle); 
	if (startResult != PAM_SUCCESS) {
		printf("Start -- %s (%d)\n",pam_strerror(handle,startResult),startResult);
		return 1;
	}

	/* Выполняем аутентификацию пользователя                */
    	authResult = pam_authenticate(handle, 0);
	if (authResult != PAM_SUCCESS) {
		printf("AUTH -- %s (%d)\n",pam_strerror(handle,authResult),authResult);
		return 1;
	}

	/* Закрываем контекст аутентификации                     */
    	pam_end(handle, authResult);
	printf("AUTH -- %s (%d)\n",pam_strerror(handle,authResult),authResult);
	return 0;
}
