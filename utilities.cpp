
#include "utilities.h"
// //======================================================================
// T_dlsym orig_dlsym;
// //======================================================================
// 
// //======================================================================
// void* new_dlsym(void* hModule, char* lpProcName)
// 	{
// 	void* pRet;
// 	
// 	pRet = orig_dlsym(hModule, lpProcName);
// 	if (!pRet) pRet = orig_dlsym(hOrigModule, lpProcName);
// 	
// 	return pRet;
// 	}
// //======================================================================

/* check if info-string is valid */
int isValid(char *info)
	{
	
	char *param, *value;
	int itemsize;
	
	/* valid info-strings may begin with a '\', which needs to be stripped */
	param = info;
	if (param[0] == '\\')
		param++;
	
	/* the string must not terminate before we got a param\value pair */
	if (param[0] == '\0')
		return 0;
	
	do
		{
		/* we check parameter size, to make sure it doesn't overflow buffer later*/
		itemsize = 0;
		do {
			/* there can't be a \0 or a parameter name > 127 */
			if ((*param == '\0') || (itemsize > 127))
				return 0;
			itemsize++;
			param++;
			/* carry on when serparating \ is found */
			} while (*param != '\\');
		
		param++;
		/* value can't begin with \0, and must not be zero-length (no delimiter after a delimiter) */
		if ((*param == '\0') || (*param == '\\'))
			return 0;
		
		/* carry on with param */
		value = param;
		itemsize = 0;
		do {
			/* there can't be a parameter value > 127 */
			if (itemsize > 127)
				return 0;
			itemsize++;
			value++;
			/* carry on when delimiter is found or input-string is terminated */
			} while ((*value != '\0') && (*value != '\\'));
		
		/* if there's a delimiter, jump over it */
		if (*value == '\\')
			value++;
		param = value;
		
		/* carry on as long there's no terminating zero as next character */
		} while ((*value != '\0') && (*(value++) != '\0'));
		
		return 1;
		
	}

