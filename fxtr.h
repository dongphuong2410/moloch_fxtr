#ifndef __FXTR_H__
#define __FXTR_H__

/**
  * Extract all files belong to a session
  * @input id Session Id
  * @return List of extracted file path, seperated by ';', return NULL if no file
  */
char *fxtr_by_sessionid(const char *id);

/**
  * Extract all files belong to a session
  * @input id Session Id
  * @return extracted le path, return NULL if no file
  */
char *fxtr_by_attachid(const char *id);

#endif
