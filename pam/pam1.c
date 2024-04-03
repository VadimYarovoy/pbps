#include <security/pam_appl.h> 
#include <security/pam_misc.h> 
#include <stdio.h> 
 
int main () 
{
  pam_handle_t* pamh; 
  struct pam_conv pamc; 
 
  /* Используем стандартную conversation-функцию misc_conv   */ 
  pamc.conv = &misc_conv; 
  pamc.appdata_ptr = NULL; 

  /* Создаем новый контекст PAM для сервиса su           */ 
  pam_start ("su", getenv ("USER"), &pamc, &pamh);
//  pam_start ("su", "root", &pamc, &pamh);
//  pam_start ("su", "testuser1", &pamc, &pamh);

  /* Выполняем аутентификацию пользователя                */ 
  if (pam_authenticate (pamh, 0) != PAM_SUCCESS) 
    fprintf (stderr, "Ошибка аутентификации!\n"); 
  else 
    fprintf (stderr, "Аутентификация прошла успешно.\n"); 

  /* Закрываем контекст аутентификации                     */ 
  pam_end (pamh, 0); 
  return 0; 
}
