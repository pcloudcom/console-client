#ifndef POVERLAY_H
#define POVERLAY_H

typedef struct _message {
  uint32_t type;
  uint64_t length;
  char value[];
} message;

void overlay_main_loop(VOID);
void instance_thread(LPVOID);
void get_answer_to_request(message *requesr, message *replay);


#endif // POVERLAY_H
